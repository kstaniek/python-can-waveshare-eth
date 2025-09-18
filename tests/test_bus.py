import socket
import threading
import time

import can

from can_waveshare.bus import _WSFrame


def make_server(bind_host="127.0.0.1", ready_evt=None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((bind_host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        if ready_evt is not None:
            ready_evt.set()
        try:
            conn, _ = srv.accept()
        except Exception:
            return
        with conn:
            while True:
                data = b""
                try:
                    while len(data) < 13:
                        chunk = conn.recv(13 - len(data))
                        if not chunk:
                            return
                        data += chunk
                except Exception:
                    return
                # Echo back the same 13-byte frame
                try:
                    conn.sendall(data)
                except Exception:
                    return

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, port, t


def test_wsframe_roundtrip():
    f = _WSFrame(can_id=0x1ABCDE, data=b"\x01\x02\x03", extended=True, rtr=False, dlc=3)
    raw = f.to_bytes()
    assert len(raw) == 13
    g = _WSFrame.from_bytes(raw)
    assert f == g


def test_send_recv_loopback():
    ready = threading.Event()
    srv, port, _ = make_server(ready_evt=ready)
    ready.wait(2.0)
    try:
        # Use channel style (host:port). Enable receive_own_messages to see echo.
        bus = can.Bus(
            interface="waveshare",
            channel=f"127.0.0.1:{port}",
            receive_own_messages=True,
        )
        with bus:
            msg = can.Message(arbitration_id=0x123, data=b"ABC", is_extended_id=False)
            bus.send(msg)
            rx = bus.recv(timeout=1.0)
            assert rx is not None
            assert rx.arbitration_id == 0x123
            assert rx.data == b"ABC"
            assert not rx.is_extended_id
    finally:
        srv.close()


def test_filters_drop_nonmatching():
    # Server sends two frames back-to-back on connect
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            # Send frame ID 0x100 (should match) and 0x555 (should be filtered)
            f1 = _WSFrame(
                can_id=0x100, data=b"\x01", extended=False, rtr=False, dlc=1
            ).to_bytes()
            f2 = _WSFrame(
                can_id=0x555, data=b"\x02", extended=False, rtr=False, dlc=1
            ).to_bytes()
            conn.sendall(f2 + f1)  # send non-matching first to exercise filtering
            time.sleep(0.1)

    th = threading.Thread(target=run, daemon=True)
    th.start()

    try:
        flt = [{"can_id": 0x100, "can_mask": 0x7FF, "extended": False}]
        bus = can.Bus(
            interface="waveshare", channel=f"127.0.0.1:{port}", can_filters=flt
        )
        with bus:
            rx = bus.recv(timeout=1.0)
            assert rx is not None
            assert rx.arbitration_id == 0x100
            assert rx.data == b"\x01"
    finally:
        srv.close()
