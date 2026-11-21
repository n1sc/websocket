# websocket

WebSocket protocol support for Neutron.

Implements the RFC 6455 protocol core in pure Neutron: opening handshake,
SHA-1/Base64 accept calculation, frame encoding/decoding, masking, and a
`ws://` client connection API.

## Install

```console
ntsc pkg install websocket
```

```nt
use websocket
```

## Features

- **Handshake**: `Sec-WebSocket-Key` generation, `Sec-WebSocket-Accept`
  computation/validation, HTTP upgrade request building and response parsing
- **Crypto primitives**: pure-Neutron SHA-1 and Base64 (byte-array APIs)
- **Framing**: encode/decode RFC 6455 frames (FIN, opcode, masking, payload
  lengths 7/16/64-bit), helpers for text/binary/close/ping/pong messages
- **Client**: `ws://` URL parsing and TCP connect + opening handshake
- **Byte-safe transport (Neutron FFI)**: sends use direct FFI calls to libc
  `send` with raw byte pointers (`memory.raw_address` in `unsafe`); receive and
  socket control use FFI bindings to a small native helper (`native/libwsio.a`)
  for errno/struct-heavy operations (recv normalization, poll, timeouts,
  connect/DNS), supporting all byte values 0-255 including masked frames and
  binary payloads
- **DNS resolution**: hostname resolution supported via the native helper
  (in addition to `localhost` and numeric IPv4 addresses)
- **Polling/timeouts**: socket readability polling, configurable receive
  timeout, and non-blocking pump support for event-loop style usage
- **Byte-level APIs**: protocol operations work on `array[int]` byte buffers
  (values 0-255) using explicit integer/bitwise manipulation

## API overview

### Handshake

- `make_key() -> string`
- `accept_key(view string key) -> string`
- `validate_accept(view string key, view string accept) -> bool`
- `build_upgrade_request(view string host, view string path, view string key) -> string`
- `is_upgrade_response(view string response) -> bool`
- `header_value(view string response, view string name) -> string`

### Frames

- `text_message(view string text, view array[int] masking_key) -> array[int]`
- `binary_message_hex(view string hex, view array[int] masking_key) -> array[int]`
- `close_message(int code, view string reason, view array[int] masking_key) -> array[int]`
- `ping_message(view array[int] payload, view array[int] masking_key) -> array[int]`
- `pong_message(view array[int] payload, view array[int] masking_key) -> array[int]`
- `encode(view Frame value) -> array[int]`
- `decode(view array[int] data, int offset) -> DecodeResult`
- `apply_mask(view array[int] payload, view array[int] masking_key) -> array[int]`
- `random_mask() -> array[int]`

Types: `Frame`, `DecodeResult`, `Url`, `Connection`.

### Client

- `parse_url(view string url) -> Url`
- `connect(view string url) -> Connection`

`Connection` methods: `send_text`, `send_binary_hex`, `send_ping`, `send_pong`,
`send_close`, `pump`, `pump_nonblocking`, `poll`, `set_recv_timeout`,
`receive_frame`, `transmit_bytes`, `close_socket`.

### Utilities

- `sha1_hex(view string text) -> string`
- `sha1_bytes(view array[int] data) -> array[int]`
- `base64_encode_bytes(view array[int] data) -> string`
- `base64_decode_bytes(view string text) -> array[int]`
- `string_to_bytes(view string text) -> array[int]`
- `bytes_to_hex(view array[int] data) -> string`
- `hex_to_bytes(view string text) -> array[int]`

## Example

```nt
use arrays
use websocket

fun main() {
    // Handshake / protocol primitives
    var key = "dGhlIHNhbXBsZSBub25jZQ=="
    say(websocket.accept_key(key))
    // s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

    // Encode and decode a masked text frame
    var mask = [1, 2, 3, 4]
    var wire = websocket.text_message("Hello", mask)
    var decoded = websocket.decode(wire, 0)
    if (decoded.ok && decoded.frame.is_text()) {
        say(decoded.frame.payload_text())
    }

    // Connect to a ws:// endpoint (network required)
    // var conn = websocket.connect("ws://127.0.0.1:8080/chat")
    // conn.send_text("hello")
    // var out = websocket.empty_frame()
    // if (conn.pump(4096) && conn.receive_frame(out)) { say(out.payload_text()) }
    // conn.send_close(1000, "bye")
}
```

## Polling and non-blocking reads

- `poll(timeout_ms)` checks socket readability (`0` for immediate/non-blocking).
- `pump_nonblocking(max_bytes)` reads available bytes without blocking (useful
  for polling/event loops).
- `pump(max_bytes)` performs blocking reads according to the socket receive
  timeout (default set by the native helper); `set_recv_timeout(timeout_ms)`
  can adjust it.
- A live end-to-end smoke test (local echo server + client) is included under
  `tests/smoke/` (`run.sh`).

## Notes and limitations

- **`wss://` (TLS)** is not supported by `connect`.
- Transport is implemented via Neutron FFI (`extern "C"` + `[ffi]`): direct
  libc `send` for byte writes and a bundled native helper
  (`native/libwsio.a`) for connect/DNS, recv normalization, poll, and
  timeouts. The target platform must be able to link against the provided
  library and libc.
- Protocol correctness (handshake, framing, masking, SHA-1/Base64) is covered
  by in-memory tests, and end-to-end behavior is covered by `tests/smoke/`.

## License

Neutron Permissive License (NPL) 1.1
