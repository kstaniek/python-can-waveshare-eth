[![CI](https://github.com/kstaniek/python-can-waveshare-eth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kstaniek/python-can-waveshare-eth/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/can-waveshare)](https://pypi.org/project/can-waveshare/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/can-waveshare)](https://pypi.org/project/can-waveshare/)


# can-waveshare

**python-can** backend for the **Waveshare 2-CH-CAN-TO-ETH** bridge that uses a fixed **13‑byte** TCP wire format.
Works with `python -m can.viewer/logger/player` and plain `can.Bus(...)`.

> Transport: TCP server on the device (e.g., `:20001` for CAN1, `:20002` for CAN2).  
> Frames: 13 bytes: `[flags/dlc][id:4][data:0..8 padded]`

**References**
- python-can documentation: [python-can.readthedocs.io](https://python-can.readthedocs.io/) — see [Bus API](https://python-can.readthedocs.io/en/stable/bus.html), [Command Line Tools](https://python-can.readthedocs.io/en/stable/scripts.html), and [Configuration](https://python-can.readthedocs.io/en/stable/configuration.html).
- Waveshare product page: [2-CH-CAN-TO-ETH](https://www.waveshare.com/2-ch-can-to-eth.htm) and vendor [Wiki](https://www.waveshare.com/wiki/2-CH-CAN-TO-ETH).


## Install

```bash
pip install can-waveshare
# or from source (editable):
pip install -e .[dev]
```

## Use with CLI

```bash
# Most portable: pass channel as host:port
python -m can.viewer -i waveshare -c 172.31.11.67:20001

# Or forward kwargs directly to the bus:
python -m can.viewer -i waveshare --bus-kwargs host=172.31.11.67 port=20001
```

### Config via `~/.canrc`

The stock CLIs read only the **[default]** section. Put this in `~/.canrc`:

```ini
[default]
interface = waveshare
channel   = 172.31.11.67:20001
```

Then:

```bash
python -m can.viewer
```

If you want multiple profiles, either (a) swap rc files or (b) write a tiny launcher in code and use `Bus(config_context="waveshare2")` to select other sections.

## Use in code

```python
import can

# explicit kwargs:
with can.Bus(interface="waveshare", host="172.31.11.67", port=20001) as bus:
    bus.send(can.Message(arbitration_id=0x123, data=b"\x11\x22\x33", is_extended_id=False))
    print(bus.recv(1.0))

# or via channel (parses host:port, tcp://host:port, [ipv6]:port, or aliases can1/can2):
with can.Bus(interface="waveshare", channel="172.31.11.67:20001") as bus:
    print(bus.recv(1.0))
```

## Features & Notes

- CAN 2.0 (0..8 data bytes). **CAN‑FD not supported** by Waveshare wire format.
- Software filters (`can_filters`) supported in the backend.
- Best‑effort own‑echo suppression when `receive_own_messages=False` (default). Set `True` to see echoes.
- Periodic TX via `bus.send_periodic(...)` works (python-can broadcast manager calls `send()` repeatedly).

## License

Apache 2.0