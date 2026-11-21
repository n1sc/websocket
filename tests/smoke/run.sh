#!/bin/sh
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$DIR/../.." && pwd)

# An explicit NTSC always wins. Otherwise prefer a compiler built from a
# sibling neutron-rs checkout over a possibly stale installed one, so the
# smoke validates the compiler under development.
if [ -z "${NTSC:-}" ]; then
  for candidate in \
    "$ROOT/../../neutron-rs/target/debug/ntsc" \
    "$ROOT/../../neutron-rs/target/release/ntsc"
  do
    if [ -x "$candidate" ]; then
      NTSC=$(CDPATH= cd -- "$(dirname -- "$candidate")" && pwd)/$(basename -- "$candidate")
      break
    fi
  done
fi
NTSC="${NTSC:-ntsc}"
PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8765}"

echo "using compiler: $NTSC"

# Sync websocket library into smoke project and append smoke helper.
cp "$ROOT/src/lib.nt" "$DIR/src/websocket.nt"
cat >> "$DIR/src/websocket.nt" <<'NT'

// Smoke-test helper (kept in smoke copy only).
fun smoke_run() -> bool {
    say("starting smoke test")
    var conn = connect("ws://127.0.0.1:__PORT__/echo")
    conn.set_recv_timeout(10000)

    var out = empty_frame()

    if (!conn.send_text("hello websocket")) {
        say("send_text failed: " + conn.last_error)
        return false
    }
    if (!conn.receive_message(out)) {
        say("no echo frame received: " + conn.last_error)
        return false
    }
    if (!out.is_text() || out.payload_text() != "hello websocket") {
        say("bad echo: " + out.payload_text())
        return false
    }
    say("echo ok")

    if (!conn.send_text("héllo")) {
        say("utf8 send failed")
        return false
    }
    if (!conn.receive_message(out)) {
        say("no utf8 echo")
        return false
    }
    if (out.payload_text() != "héllo") {
        say("bad utf8 echo: " + out.payload_text())
        return false
    }
    say("utf8 ok")

    if (!conn.send_ping("early")) { say("ping send failed"); return false }
    if (!conn.receive_message(out)) { say("no pong: " + conn.last_error); return false }
    if (!out.is_pong() || out.payload_text() != "early") {
        say("bad pong")
        return false
    }
    say("ping/pong ok")

    var big = ""
    for (var i = 0; i < 20000; i = i + 1) {
        big = big + "abcdefghij"
    }
    if (!conn.send_text(big)) {
        say("fragmented send failed")
        return false
    }
    if (!conn.receive_message(out)) {
        say("no fragmented echo")
        return false
    }
    if (out.payload_text() != big) {
        say("bad fragmented echo, length=" + int_to_string(strings.length(out.payload_text())))
        return false
    }
    say("fragmented ok")

    if (!conn.send_text("after-frag")) {
        say("post-frag send failed")
        return false
    }
    if (!conn.receive_message(out)) {
        say("no post-frag echo: " + conn.last_error)
        return false
    }
    if (out.payload_text() != "after-frag") {
        say("bad post-frag echo")
        return false
    }
    say("post-frag ok")

    conn.send_close(1000, "bye")
    if (!conn.close_received || conn.close_code != 1000) {
        say("bad close handshake")
        return false
    }
    say("close ok")
    return true
}
NT
sed -i "s/__PORT__/$PORT/g" "$DIR/src/websocket.nt"

# Ensure native helper library is built for current platform.
make -C "$ROOT/native" >/dev/null
mkdir -p "$DIR/native"
cp "$ROOT/native/libwsio.a" "$DIR/native/libwsio.a"

cd "$DIR"
"$NTSC" build >/dev/null

"$PYTHON" -u echo_server.py "$PORT" >/tmp/ws_echo_server_smoke.log 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# wait for server readiness
i=0
while [ $i -lt 50 ]; do
  if grep -q "READY $PORT" /tmp/ws_echo_server_smoke.log 2>/dev/null; then
    break
  fi
  sleep 0.1
  i=$((i + 1))
done

if ! grep -q "READY $PORT" /tmp/ws_echo_server_smoke.log 2>/dev/null; then
  echo "echo server failed to start" >&2
  cat /tmp/ws_echo_server_smoke.log >&2 || true
  exit 1
fi

./build/debug/ws_smoke
