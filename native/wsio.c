#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define WS_IO_BUF 65536
#define WS_TLS_MAX_HANDLES 256
#define WS_DEFAULT_TIMEOUT_MS 10000

/* host, CA and client-cert paths are staged here for the duration of a
 * synchronous connect call, so they are thread-local. */
static _Thread_local char ws_host_buf[256];
static _Thread_local int ws_host_len = 0;
static _Thread_local char ws_ca_buf[512];
static _Thread_local int ws_ca_len = 0;
static _Thread_local char ws_cert_buf[512];
static _Thread_local int ws_cert_len = 0;
static _Thread_local char ws_key_buf[512];
static _Thread_local int ws_key_len = 0;

/* one buffer per direction and transport; each operation is synchronous */
static _Thread_local unsigned char ws_send_buf[WS_IO_BUF];
static _Thread_local int ws_send_len = 0;
static _Thread_local unsigned char ws_tls_send_buf[WS_IO_BUF];
static _Thread_local int ws_tls_send_len = 0;
static _Thread_local unsigned char ws_recv_buf[WS_IO_BUF];
static _Thread_local int ws_recv_len = 0;
static _Thread_local unsigned char ws_tls_recv_buf[WS_IO_BUF];
static _Thread_local int ws_tls_recv_len = 0;

static int ws_openssl_initialized = 0;

static void ws_ensure_openssl(void) {
    if (!ws_openssl_initialized) {
        OPENSSL_init_ssl(0, NULL);
        ws_openssl_initialized = 1;
    }
}

static void ws_set_socket_options(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

static void ws_set_timeouts_fd(int fd, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void ws_host_reset(void) {
    ws_host_len = 0;
    ws_host_buf[0] = '\0';
}

void ws_host_append(int ch) {
    if (ws_host_len < (int)sizeof(ws_host_buf) - 1) {
        ws_host_buf[ws_host_len++] = (char)(ch & 255);
        ws_host_buf[ws_host_len] = '\0';
    }
}

void ws_ca_reset(void) {
    ws_ca_len = 0;
    ws_ca_buf[0] = '\0';
}

void ws_ca_append(int ch) {
    if (ws_ca_len < (int)sizeof(ws_ca_buf) - 1) {
        ws_ca_buf[ws_ca_len++] = (char)(ch & 255);
        ws_ca_buf[ws_ca_len] = '\0';
    }
}

void ws_cert_reset(void) {
    ws_cert_len = 0;
    ws_cert_buf[0] = '\0';
}

void ws_cert_append(int ch) {
    if (ws_cert_len < (int)sizeof(ws_cert_buf) - 1) {
        ws_cert_buf[ws_cert_len++] = (char)(ch & 255);
        ws_cert_buf[ws_cert_len] = '\0';
    }
}

void ws_key_reset(void) {
    ws_key_len = 0;
    ws_key_buf[0] = '\0';
}

void ws_key_append(int ch) {
    if (ws_key_len < (int)sizeof(ws_key_buf) - 1) {
        ws_key_buf[ws_key_len++] = (char)(ch & 255);
        ws_key_buf[ws_key_len] = '\0';
    }
}

static int ws_connect_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    if (timeout_ms <= 0) {
        timeout_ms = WS_DEFAULT_TIMEOUT_MS;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    int rc = connect(fd, addr, addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        fcntl(fd, F_SETFL, flags);
        return -1;
    }

    if (rc < 0) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        do {
            rc = poll(&pfd, 1, timeout_ms);
        } while (rc < 0 && errno == EINTR);

        if (rc <= 0) {
            fcntl(fd, F_SETFL, flags);
            return -1;
        }

        int err = 0;
        socklen_t errlen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
            fcntl(fd, F_SETFL, flags);
            return -1;
        }
    }

    fcntl(fd, F_SETFL, flags);
    return 0;
}

int ws_host_connect(int port, int timeout_ms) {
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(ws_host_buf, portbuf, &hints, &res);
    if (rc != 0 || res == NULL) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        ws_set_socket_options(fd);
        if (ws_connect_timeout(fd, p->ai_addr, p->ai_addrlen, timeout_ms) == 0) {
            ws_set_timeouts_fd(fd, WS_DEFAULT_TIMEOUT_MS);
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int ws_tcp_connect_ip(int a, int b, int c, int d, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    ws_set_socket_options(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    unsigned char *ip = (unsigned char *)&addr.sin_addr.s_addr;
    ip[0] = (unsigned char)a;
    ip[1] = (unsigned char)b;
    ip[2] = (unsigned char)c;
    ip[3] = (unsigned char)d;

    if (ws_connect_timeout(fd, (struct sockaddr *)&addr, sizeof(addr), timeout_ms) < 0) {
        close(fd);
        return -1;
    }

    ws_set_timeouts_fd(fd, WS_DEFAULT_TIMEOUT_MS);
    return fd;
}

int ws_tcp_connect_localhost(int port, int timeout_ms) {
    return ws_tcp_connect_ip(127, 0, 0, 1, port, timeout_ms);
}

int ws_listen(int port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, backlog > 0 ? backlog : 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ws_accept(int fd) {
    if (fd < 0) {
        return -1;
    }
    int client = accept(fd, NULL, NULL);
    if (client < 0) {
        return -1;
    }
    ws_set_socket_options(client);
    ws_set_timeouts_fd(client, WS_DEFAULT_TIMEOUT_MS);
    return client;
}

int ws_local_port(int fd) {
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

void ws_send_reset(void) {
    ws_send_len = 0;
}

static int ws_flush_plain(int fd) {
    int offset = 0;
    while (offset < ws_send_len) {
        ssize_t n = send(fd, ws_send_buf + offset, (size_t)(ws_send_len - offset), MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        offset += (int)n;
    }
    ws_send_len = 0;
    return 0;
}

int ws_send_put(int fd, int value) {
    if (ws_send_len >= WS_IO_BUF && ws_flush_plain(fd) != 0) {
        return -1;
    }
    ws_send_buf[ws_send_len++] = (unsigned char)(value & 255);
    return 0;
}

int ws_send_flush(int fd) {
    return ws_flush_plain(fd);
}

int ws_recv_chunk(int fd, int max) {
    if (max <= 0 || max > WS_IO_BUF) {
        max = WS_IO_BUF;
    }
    for (;;) {
        ssize_t n = recv(fd, ws_recv_buf, (size_t)max, 0);
        if (n > 0) {
            ws_recv_len = (int)n;
            return (int)n;
        }
        if (n == 0) {
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -2;
        }
        return -3;
    }
}

int ws_recv_chunk_byte(int index) {
    if (index < 0 || index >= ws_recv_len) {
        return -1;
    }
    return (int)ws_recv_buf[index];
}

int ws_recv_byte(int fd) {
    unsigned char b = 0;
    for (;;) {
        ssize_t n = recv(fd, &b, 1, 0);
        if (n > 0) {
            return (int)b;
        }
        if (n == 0) {
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -2;
        }
        return -3;
    }
}

int ws_poll_read(int fd, int timeout_ms) {
    if (fd < 0) {
        return -1;
    }
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc > 0) {
        if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
            return 1;
        }
        return 0;
    }
    if (rc == 0) {
        return 0;
    }
    if (errno == EINTR) {
        return 0;
    }
    return -1;
}

int ws_set_recv_timeout(int fd, int timeout_ms) {
    if (fd < 0) {
        return -1;
    }
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    ws_set_timeouts_fd(fd, timeout_ms);
    return 0;
}

int ws_close_fd(int fd) {
    if (fd >= 0) {
        return close(fd);
    }
    return 0;
}

/* TLS support.
 * Handles are integer indices into a small fixed table so they can safely
 * cross the Neutron FFI boundary (Neutron `int` is marshalled as 32-bit
 * in FFI). On success ws_tls_connect takes ownership of the socket fd and
 * ws_tls_close closes it. On failure the caller retains ownership of fd.
 */

typedef struct ws_tls_state {
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
} ws_tls_state;

static ws_tls_state *ws_tls_handles[WS_TLS_MAX_HANDLES];
static atomic_flag ws_tls_lock = ATOMIC_FLAG_INIT;

static void ws_tls_table_lock(void) {
    while (atomic_flag_test_and_set_explicit(&ws_tls_lock, memory_order_acquire)) {
        /* the table is touched only at connect/close; keep the spin short */
    }
}

static void ws_tls_table_unlock(void) {
    atomic_flag_clear_explicit(&ws_tls_lock, memory_order_release);
}

static ws_tls_state *ws_tls_get(int handle) {
    if (handle < 0 || handle >= WS_TLS_MAX_HANDLES) {
        return NULL;
    }
    ws_tls_table_lock();
    ws_tls_state *st = ws_tls_handles[handle];
    ws_tls_table_unlock();
    return st;
}

static int ws_tls_slot(void) {
    ws_tls_table_lock();
    for (int i = 0; i < WS_TLS_MAX_HANDLES; i++) {
        if (ws_tls_handles[i] == NULL) {
            ws_tls_table_unlock();
            return i;
        }
    }
    ws_tls_table_unlock();
    return -1;
}

static void ws_tls_free_state(ws_tls_state *st) {
    if (!st) {
        return;
    }
    if (st->ssl) {
        SSL_shutdown(st->ssl);
        SSL_free(st->ssl);
        st->ssl = NULL;
    }
    if (st->ctx) {
        SSL_CTX_free(st->ctx);
        st->ctx = NULL;
    }
    if (st->fd >= 0) {
        close(st->fd);
        st->fd = -1;
    }
    free(st);
}

static int ws_host_is_ip(const char *host) {
    unsigned char buf[16];
    return inet_pton(AF_INET, host, buf) == 1 || inet_pton(AF_INET6, host, buf) == 1;
}

/* Perform TLS handshake over an already-connected socket.
 * verify: 0 = none, 1 = peer + hostname, 2 = peer + hostname with custom CA.
 * Returns a non-negative handle on success, or -1 on failure.
 * Does not close fd on failure.
 */
int ws_tls_connect(int fd, int verify) {
    if (fd < 0) {
        return -1;
    }
    ws_ensure_openssl();

    int slot = ws_tls_slot();
    if (slot < 0) {
        return -1;
    }

    ws_tls_state *st = (ws_tls_state *)calloc(1, sizeof(ws_tls_state));
    if (!st) {
        return -1;
    }

    st->fd = fd;
    st->ctx = SSL_CTX_new(TLS_client_method());
    if (!st->ctx) {
        st->fd = -1;
        free(st);
        return -1;
    }

    if (verify == 0) {
        SSL_CTX_set_verify(st->ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(st->ctx, SSL_VERIFY_PEER, NULL);
        if (verify == 2 && ws_ca_len > 0) {
            if (SSL_CTX_load_verify_locations(st->ctx, ws_ca_buf, NULL) != 1) {
                SSL_CTX_free(st->ctx);
                st->fd = -1;
                free(st);
                return -1;
            }
        } else {
            SSL_CTX_set_default_verify_paths(st->ctx);
        }
    }

    if (ws_cert_len > 0 && ws_key_len > 0) {
        if (SSL_CTX_use_certificate_chain_file(st->ctx, ws_cert_buf) != 1 ||
            SSL_CTX_use_PrivateKey_file(st->ctx, ws_key_buf, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(st->ctx) != 1) {
            SSL_CTX_free(st->ctx);
            st->fd = -1;
            free(st);
            return -1;
        }
    }

    st->ssl = SSL_new(st->ctx);
    if (!st->ssl) {
        SSL_CTX_free(st->ctx);
        st->ctx = NULL;
        st->fd = -1;
        free(st);
        return -1;
    }

    SSL_set_mode(st->ssl, SSL_MODE_AUTO_RETRY);

    if (ws_host_len > 0) {
        SSL_set_tlsext_host_name(st->ssl, ws_host_buf);
        X509_VERIFY_PARAM *param = SSL_get0_param(st->ssl);
        if (param) {
            if (ws_host_is_ip(ws_host_buf)) {
                X509_VERIFY_PARAM_set1_ip_asc(param, ws_host_buf);
            } else {
                X509_VERIFY_PARAM_set1_host(param, ws_host_buf, 0);
            }
        }
    }

    if (SSL_set_fd(st->ssl, fd) != 1) {
        SSL_free(st->ssl);
        st->ssl = NULL;
        SSL_CTX_free(st->ctx);
        st->ctx = NULL;
        st->fd = -1;
        free(st);
        return -1;
    }

    int ret = SSL_connect(st->ssl);
    if (ret != 1) {
        SSL_free(st->ssl);
        st->ssl = NULL;
        SSL_CTX_free(st->ctx);
        st->ctx = NULL;
        st->fd = -1; /* caller owns fd on failure */
        free(st);
        return -1;
    }

    ws_tls_table_lock();
    ws_tls_handles[slot] = st;
    ws_tls_table_unlock();
    return slot;
}

void ws_tls_send_reset(void) {
    ws_tls_send_len = 0;
}

static int ws_tls_flush(int tls_handle) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st || !st->ssl) {
        return -1;
    }
    int offset = 0;
    int spins = 0;
    while (offset < ws_tls_send_len) {
        int n = SSL_write(st->ssl, ws_tls_send_buf + offset, ws_tls_send_len - offset);
        if (n > 0) {
            offset += n;
            spins = 0;
            continue;
        }
        int err = SSL_get_error(st->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (++spins > 1000) {
                return -1;
            }
            continue;
        }
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
            continue;
        }
        return -1;
    }
    ws_tls_send_len = 0;
    return 0;
}

int ws_tls_send_put(int tls_handle, int value) {
    if (ws_tls_send_len >= WS_IO_BUF && ws_tls_flush(tls_handle) != 0) {
        return -1;
    }
    ws_tls_send_buf[ws_tls_send_len++] = (unsigned char)(value & 255);
    return 0;
}

int ws_tls_send_flush(int tls_handle) {
    return ws_tls_flush(tls_handle);
}

int ws_tls_recv_chunk(int tls_handle, int max) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st || !st->ssl) {
        return -3;
    }
    if (max <= 0 || max > WS_IO_BUF) {
        max = WS_IO_BUF;
    }

    for (;;) {
        int n = SSL_read(st->ssl, ws_tls_recv_buf, max);
        if (n > 0) {
            ws_tls_recv_len = n;
            return n;
        }
        if (n == 0) {
            return -1;
        }
        int err = SSL_get_error(st->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return -2;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            return -1;
        }
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
            continue;
        }
        return -3;
    }
}

int ws_tls_recv_chunk_byte(int index) {
    if (index < 0 || index >= ws_tls_recv_len) {
        return -1;
    }
    return (int)ws_tls_recv_buf[index];
}

int ws_tls_send_byte(int tls_handle, int value) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st || !st->ssl) {
        return -1;
    }
    unsigned char b = (unsigned char)(value & 255);
    int n = SSL_write(st->ssl, &b, 1);
    if (n > 0) {
        return n;
    }
    int err = SSL_get_error(st->ssl, n);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
        n = SSL_write(st->ssl, &b, 1);
        if (n > 0) {
            return n;
        }
    }
    return -1;
}

int ws_tls_recv_byte(int tls_handle) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st || !st->ssl) {
        return -3;
    }

    unsigned char b = 0;
    for (;;) {
        int n = SSL_read(st->ssl, &b, 1);
        if (n > 0) {
            return (int)b;
        }
        if (n == 0) {
            return -1;
        }
        int err = SSL_get_error(st->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return -2;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            return -1;
        }
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
            continue;
        }
        return -3;
    }
}

int ws_tls_pending(int tls_handle) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st || !st->ssl) {
        return 0;
    }
    return SSL_pending(st->ssl);
}

int ws_tls_poll_read(int tls_handle, int timeout_ms) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st || !st->ssl) {
        return -1;
    }
    if (SSL_pending(st->ssl) > 0) {
        return 1;
    }
    return ws_poll_read(st->fd, timeout_ms);
}

int ws_tls_set_recv_timeout(int tls_handle, int timeout_ms) {
    ws_tls_state *st = ws_tls_get(tls_handle);
    if (!st) {
        return -1;
    }
    return ws_set_recv_timeout(st->fd, timeout_ms);
}

int ws_tls_close(int tls_handle) {
    ws_tls_table_lock();
    ws_tls_state *st = ws_tls_handles[tls_handle];
    ws_tls_handles[tls_handle] = NULL;
    ws_tls_table_unlock();
    ws_tls_free_state(st);
    return 0;
}
