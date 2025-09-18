from __future__ import annotations

import errno
import select
import socket
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Iterable, List, Optional, Tuple

import can


@dataclass(slots=True)
class _WSFrame:
    """
    Waveshare's fixed 13-byte TCP wire frame.

    Byte 0:  [7]=extended, [6]=rtr, [3:0]=dlc (0..8)
    Bytes 1..4:  CAN ID (big-endian)
    Bytes 5..12: Data bytes (0..8 valid according to dlc)
    """

    can_id: int
    data: bytes
    extended: bool
    rtr: bool
    dlc: int

    @staticmethod
    def from_bytes(buf: bytes) -> "_WSFrame":
        if len(buf) != 13:
            raise ValueError("Waveshare frame must be exactly 13 bytes")
        b0 = buf[0]
        extended = bool(b0 & 0x80)
        rtr = bool(b0 & 0x40)
        dlc = b0 & 0x0F
        if dlc > 8:
            raise ValueError(f"Invalid DLC {dlc}")
        can_id = int.from_bytes(buf[1:5], "big", signed=False)
        data = bytes(buf[5 : 5 + dlc])
        return _WSFrame(can_id=can_id, data=data, extended=extended, rtr=rtr, dlc=dlc)

    def to_bytes(self) -> bytes:
        if not (0 <= self.dlc <= 8):
            raise ValueError("DLC must be 0..8")
        if self.dlc != len(self.data):
            raise ValueError("dlc must equal len(data)")
        b0 = (
            (0x80 if self.extended else 0)
            | (0x40 if self.rtr else 0)
            | (self.dlc & 0x0F)
        )
        out = bytearray(13)
        out[0] = b0
        out[1:5] = int(self.can_id).to_bytes(4, "big", signed=False)
        out[5 : 5 + self.dlc] = self.data
        return bytes(out)


def _matches_filter(msg: can.Message, flt: dict[str, Any]) -> bool:
    """
    python-can filter semantics:
      - 'can_id' and 'can_mask' (both required to match IDs)
      - optional 'extended' True/False filters on IDE
    """
    can_id = flt.get("can_id")
    can_mask = flt.get("can_mask")
    ext = flt.get("extended")
    if can_id is None or can_mask is None:
        return True  # accept if malformed; mirrors tolerant behavior
    if (msg.arbitration_id & can_mask) != (can_id & can_mask):
        return False
    if ext is not None and bool(msg.is_extended_id) is not bool(ext):
        return False
    return True


class WaveShareBus(can.BusABC):
    """
    python-can Bus for Waveshare 2-CH-CAN-TO-ETH (TCP server on device).

    Required connection args (choose one style):
      1) Explicit kwargs: host=..., port=...
      2) Through 'channel': "host:port" or "tcp://host:port"
         - IPv6: "[2001:db8::1]:20001"
         - Aliases: "can1" -> port 20001, "can2" -> port 20002 (host still needed via kwargs)

    Optional kwargs:
      - receive_own_messages: bool (default False) – suppress echoed frames (best effort)
      - tcp_nodelay: bool (default True)
      - keepalive: bool (default True)
      - timeout: float | None – default timeout used as base for send/recv select
      - can_filters: list[dict] – software filters applied in this backend

    Limitations:
      - CAN-FD is NOT supported (Waveshare wire format is limited to 8 data bytes).
      - No hardware/kernel filters; filtering is done in software here.
    """

    def __init__(
        self,
        channel: Optional[str] = None,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        receive_own_messages: bool = False,
        tcp_nodelay: bool = True,
        keepalive: bool = True,
        timeout: Optional[float] = None,
        can_filters: Optional[List[dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> None:
        # Allow passing host/port via channel
        ch_host, ch_port = _parse_channel(channel) if channel else (None, None)
        host = host or ch_host
        port = port or ch_port
        if host is None or port is None:
            raise can.CanError(
                "waveshare: missing host/port. "
                "Pass them as kwargs (host=..., port=...) or via channel='host:port'."
            )

        self.channel_info = f"Waveshare TCP {host}:{port}"
        # Initialize BusABC (sets up periodic send plumbing, etc.)
        super().__init__(channel=channel or f"{host}:{port}", **kwargs)

        self._host: str = host
        self._port: int = int(port)
        self._timeout_default: Optional[float] = timeout
        self._filters: List[dict[str, Any]] = list(can_filters or [])

        # Socket setup
        self._sock = socket.socket(
            socket.AF_INET6 if _is_ipv6_literal(host) else socket.AF_INET,
            socket.SOCK_STREAM,
        )
        try:
            if tcp_nodelay:
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            if keepalive:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

        # Connect
        try:
            self._sock.connect((self._host, self._port))
        except OSError as e:
            self._sock.close()
            raise can.CanError(
                f"WaveShareBus: connect to {self._host}:{self._port} failed: {e}"
            ) from e

        self._closed: bool = False

        # Best-effort own-message suppression (for echoing bridges)
        self._suppress_own: bool = not bool(receive_own_messages)
        self._recent_tx: Deque[tuple] = deque(maxlen=64)  # (t, id, dlc, data, rtr, ext)

    # ---------- python-can required overrides ----------

    def shutdown(self) -> None:
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        finally:
            super().shutdown()

    def fileno(self) -> Optional[int]:
        try:
            return self._sock.fileno()
        except OSError:
            return None

    def send(self, msg: can.Message, timeout: Optional[float] = None) -> None:
        if self._closed:
            raise can.CanError("WaveShareBus is closed")

        if getattr(msg, "is_fd", False):
            raise can.CanError(
                "Waveshare backend does not support CAN-FD (max 8 bytes)"
            )

        extended = bool(msg.is_extended_id)
        rtr = bool(msg.is_remote_frame)
        arb_id = int(msg.arbitration_id)

        if extended:
            if not (0 <= arb_id <= 0x1FFFFFFF):
                raise can.CanError(f"Invalid 29-bit CAN ID: {arb_id:#x}")
        else:
            if not (0 <= arb_id <= 0x7FF):
                raise can.CanError(f"Invalid 11-bit CAN ID: {arb_id:#x}")

        data = bytes(msg.data or b"")
        if len(data) > 8:
            raise can.CanError("Data length > 8 not supported by Waveshare format")

        # For RTR, dlc declares requested length. Prefer explicit msg.dlc if present.
        try:
            dlc_val = int(msg.dlc) if rtr else len(data)
        except AttributeError:
            dlc_val = len(data)

        ws = _WSFrame(
            can_id=arb_id,
            data=data if not rtr else b"",
            extended=extended,
            rtr=rtr,
            dlc=dlc_val,
        )

        payload = ws.to_bytes()

        to = _choose_timeout(timeout, self._timeout_default)
        if not _wait_for_io(self._sock, writable=True, timeout=to):
            raise can.CanError("WaveShareBus.send timeout (socket not writable)")

        try:
            _send_all(self._sock, payload)
        except OSError as e:
            raise can.CanError(f"WaveShareBus.send failed: {e}") from e

        # record for own-echo suppression (if active)
        if self._suppress_own:
            self._recent_tx.append(
                (time.monotonic(), arb_id, ws.dlc, bytes(data), rtr, extended)
            )

    def recv(self, timeout: Optional[float] = None) -> Optional[can.Message]:
        if self._closed:
            return None

        deadline: Optional[float] = None
        if timeout is not None:
            deadline = time.monotonic() + max(0.0, timeout)
        elif self._timeout_default is not None:
            deadline = time.monotonic() + max(0.0, self._timeout_default)

        while True:
            remain = None
            if deadline is not None:
                remain = max(0.0, deadline - time.monotonic())
                if remain == 0.0:
                    return None  # timeout

            if not _wait_for_io(self._sock, readable=True, timeout=remain):
                return None  # timeout

            try:
                raw = _recv_exact(self._sock, 13)
            except _SocketClosed:
                self.shutdown()
                return None
            except OSError as e:
                raise can.CanError(f"WaveShareBus.recv failed: {e}") from e

            try:
                ws = _WSFrame.from_bytes(raw)
            except ValueError:
                # skip malformed frames
                continue

            msg = can.Message(
                arbitration_id=ws.can_id,
                is_extended_id=ws.extended,
                is_remote_frame=ws.rtr,
                data=ws.data if not ws.rtr else b"",
                dlc=ws.dlc,  # especially important for RTR frames
                timestamp=time.time(),
                is_error_frame=False,
            )

            if self._filters and not any(
                _matches_filter(msg, f) for f in self._filters
            ):
                continue

            if self._suppress_own and _matches_recent(self._recent_tx, msg, window=0.1):
                continue

            return msg

    # ---------- optional API ----------

    def set_filters(self, filters: Optional[Iterable[dict[str, Any]]]) -> None:
        self._filters = list(filters or [])


# ---------- helpers ----------


class _SocketClosed(Exception):
    pass


def _choose_timeout(
    specific: Optional[float], default: Optional[float]
) -> Optional[float]:
    if specific is not None:
        return specific
    return default


def _wait_for_io(
    sock: socket.socket,
    *,
    readable: bool = False,
    writable: bool = False,
    timeout: Optional[float],
) -> bool:
    r, w, _ = select.select(
        [sock] if readable else [],
        [sock] if writable else [],
        [],
        0 if (timeout is not None and timeout <= 0) else timeout,
    )
    return bool(r or w)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise _SocketClosed."""
    view = memoryview(bytearray(n))
    got = 0
    while got < n:
        try:
            chunk = sock.recv(n - got)
        except InterruptedError:
            continue
        if chunk == b"":
            raise _SocketClosed()
        view[got : got + len(chunk)] = chunk
        got += len(chunk)
    return view.tobytes()


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    sent = 0
    while sent < len(view):
        try:
            n = sock.send(view[sent:])
        except InterruptedError:
            continue
        if n == 0:
            raise OSError(errno.EPIPE, "socket closed")
        sent += n


def _matches_recent(recent: Deque[tuple], msg: can.Message, *, window: float) -> bool:
    now = time.monotonic()
    # prune old
    while recent and (now - recent[0][0]) > window:
        recent.popleft()
    key = (
        msg.arbitration_id,
        msg.dlc,
        bytes(msg.data or b""),
        bool(msg.is_remote_frame),
        bool(msg.is_extended_id),
    )
    return any(
        (arb_id, dlc, data, rtr, ext) == key
        for _, arb_id, dlc, data, rtr, ext in recent
    )


def _parse_channel(channel: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """
    Accepts:
      - "172.31.11.67:20001"
      - "tcp://172.31.11.67:20002"
      - "[2001:db8::1]:20001" (IPv6 literal)
      - "can1" -> (None, 20001)  (host must come from kwargs/env/config)
      - "can2" -> (None, 20002)
    """
    if not channel:
        return (None, None)
    s = channel.strip()
    if s.startswith("tcp://"):
        s = s[6:]
    low = s.lower()
    if low in ("can1", "can0"):  # treat can0 like can1
        return (None, 20001)
    if low == "can2":
        return (None, 20002)
    # IPv6 in [addr]:port
    if s.startswith("["):
        try:
            host, rest = s[1:].split("]", 1)
            if rest.startswith(":"):
                return (host, int(rest[1:]))
        except Exception:
            return (None, None)
    # host:port (IPv4/DNS)
    if ":" in s:
        host, port_str = s.rsplit(":", 1)
        try:
            return (host, int(port_str))
        except ValueError:
            return (None, None)
    return (None, None)


def _is_ipv6_literal(host: str) -> bool:
    """Heuristic: treat as IPv6 if it contains ':' and not a bracketed literal removed by _parse_channel."""
    return ":" in host
