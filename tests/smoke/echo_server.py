#!/usr/bin/env python3
"""Minimal RFC 6455 echo server used by the smoke test.

Exercises the client's automatic pong (it sends a ping right after the
handshake), fragmented messages (it reassembles continuations before
echoing), and the closing handshake.
"""
import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def read_http_headers(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(1)
        if not chunk:
            return None
        data += chunk
        if len(data) > 65536:
            return None
    return data.decode("iso-8859-1")


def handshake(conn):
    req = read_http_headers(conn)
    if req is None:
        return False
    key = None
    for line in req.split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "sec-websocket-key":
                key = v.strip()
    if not key:
        return False
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    conn.sendall(resp.encode())
    return True


def read_frame(conn):
    header = recv_exact(conn, 2)
    if header is None:
        return None
    b0, b1 = header[0], header[1]
    fin = (b0 & 0x80) != 0
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) != 0
    length = b1 & 0x7F
    if length == 126:
        ext = recv_exact(conn, 2)
        if ext is None:
            return None
        length = struct.unpack("!H", ext)[0]
    elif length == 127:
        ext = recv_exact(conn, 8)
        if ext is None:
            return None
        length = struct.unpack("!Q", ext)[0]
    mask_key = b"\x00\x00\x00\x00"
    if masked:
        mask_key = recv_exact(conn, 4)
        if mask_key is None:
            return None
    payload = recv_exact(conn, length) if length > 0 else b""
    if payload is None:
        return None
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return (fin, opcode, payload)


def send_frame(conn, opcode, payload):
    b0 = 0x80 | (opcode & 0x0F)
    length = len(payload)
    header = bytearray([b0])
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))
    conn.sendall(bytes(header) + payload)


def handle_client(conn, addr):
    try:
        conn.settimeout(60.0)
        if not handshake(conn):
            return

        send_frame(conn, 0x9, b"server-ping")

        frag_opcode = None
        frag_payload = b""
        while True:
            frame = read_frame(conn)
            if frame is None:
                break
            fin, opcode, payload = frame
            if opcode == 0x8:
                try:
                    send_frame(conn, 0x8, payload[:2] if len(payload) >= 2 else b"\x03\xe8")
                except OSError:
                    pass
                break
            if opcode == 0x9:
                send_frame(conn, 0xA, payload)
            elif opcode == 0xA:
                pass
            elif opcode in (0x1, 0x2):
                if fin:
                    send_frame(conn, opcode, payload)
                else:
                    frag_opcode = opcode
                    frag_payload = payload
            elif opcode == 0x0:
                frag_payload += payload
                if fin and frag_opcode is not None:
                    send_frame(conn, frag_opcode, frag_payload)
                    frag_opcode = None
                    frag_payload = b""
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"READY {port}", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
