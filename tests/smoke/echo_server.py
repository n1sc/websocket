#!/usr/bin/env python3
import base64
import hashlib
import socket
import struct
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
        if ext is None: return None
        length = struct.unpack("!H", ext)[0]
    elif length == 127:
        ext = recv_exact(conn, 8)
        if ext is None: return None
        length = struct.unpack("!Q", ext)[0]
    mask_key = b"\x00\x00\x00\x00"
    if masked:
        mask_key = recv_exact(conn, 4)
        if mask_key is None: return None
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
        conn.settimeout(10.0)
        if not handshake(conn):
            return
        while True:
            frame = read_frame(conn)
            if frame is None:
                break
            fin, opcode, payload = frame
            if opcode == 0x8:  # close
                # echo close
                try:
                    send_frame(conn, 0x8, payload[:2] if len(payload) >= 2 else b"\x03\xe8")
                except Exception:
                    pass
                break
            elif opcode == 0x9:  # ping
                send_frame(conn, 0xA, payload)
            elif opcode == 0x1:  # text -> echo
                send_frame(conn, 0x1, payload)
            elif opcode == 0x2:  # binary -> echo
                send_frame(conn, 0x2, payload)
            # ignore continuation/pong for this simple server
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8765))
    srv.listen(16)
    print("READY 8765", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()

if __name__ == "__main__":
    main()
