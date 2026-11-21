#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static char ws_host_buf[256];
static int ws_host_len = 0;

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

int ws_host_connect(int port) {
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
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int ws_tcp_connect_ip(int a, int b, int c, int d, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    unsigned char *ip = (unsigned char *)&addr.sin_addr.s_addr;
    ip[0] = (unsigned char)a;
    ip[1] = (unsigned char)b;
    ip[2] = (unsigned char)c;
    ip[3] = (unsigned char)d;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

int ws_tcp_connect_localhost(int port) {
    return ws_tcp_connect_ip(127, 0, 0, 1, port);
}

int ws_send_byte(int fd, int value) {
    unsigned char b = (unsigned char)(value & 255);
    ssize_t n = send(fd, &b, 1, 0);
    if (n < 0) {
        if (errno == EINTR) {
            return ws_send_byte(fd, value);
        }
        return -1;
    }
    return (int)n;
}

int ws_recv_byte(int fd) {
    unsigned char b = 0;
    ssize_t n = recv(fd, &b, 1, 0);
    if (n > 0) {
        return (int)b;
    }
    if (n == 0) {
        return -1; /* EOF */
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return -2; /* timeout/would-block */
    }
    return -3; /* error */
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
    struct timeval tv;
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int ws_close_fd(int fd) {
    if (fd >= 0) {
        return close(fd);
    }
    return 0;
}
