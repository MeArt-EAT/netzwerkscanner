"""Gemeinsame Test-Einrichtung.

HARTE REGEL: Kein Test sendet ein Paket ins echte Netz. Dieses Modul sperrt beim Laden
alle Ziele außerhalb von 127.0.0.0/8 bzw. ::1 – für TCP/UDP, Namensauflösung, Scapy und ping.
Ein Verstoß bricht den Test mit LanTrafficError ab.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # keine __pycache__-Ordner in Dropbox

import ipaddress
import os
import socket
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class LanTrafficError(AssertionError):
    """Ein Test wollte ins echte Netz senden."""


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode(errors="replace")
    if host is None:
        return True
    text = str(host).split("%", 1)[0].strip("[]")
    if text.lower() in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def _check(address: object, what: str) -> None:
    if isinstance(address, tuple) and address:
        host = address[0]
        if not _is_loopback(host):
            raise LanTrafficError(f"{what} an {address!r} ist im Test verboten (nur 127.0.0.0/8)")


_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_sendto = socket.socket.sendto
_real_getaddrinfo = socket.getaddrinfo
_real_gethostbyname = socket.gethostbyname
_real_getnameinfo = socket.getnameinfo


def _connect(self: socket.socket, address: object) -> None:
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address, "connect")
    return _real_connect(self, address)


def _connect_ex(self: socket.socket, address: object) -> int:
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address, "connect_ex")
    return _real_connect_ex(self, address)


def _sendto(self: socket.socket, data: bytes, *args: object) -> int:
    if self.family in (socket.AF_INET, socket.AF_INET6) and args:
        _check(args[-1], "sendto")
    return _real_sendto(self, data, *args)  # type: ignore[arg-type]


def _getaddrinfo(host: object, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
    if not _is_loopback(host):
        raise LanTrafficError(f"Namensauflösung für {host!r} ist im Test verboten")
    return _real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]


def _gethostbyname(host: str) -> str:
    if not _is_loopback(host):
        raise LanTrafficError(f"gethostbyname({host!r}) ist im Test verboten")
    return _real_gethostbyname(host)


def _gethostbyaddr(ip: str):  # type: ignore[no-untyped-def]
    raise LanTrafficError("gethostbyaddr ist im Test verboten – resolver injizieren")


def _getnameinfo(sockaddr: tuple, flags: int):  # type: ignore[no-untyped-def]
    if not _is_loopback(sockaddr[0]) or flags & socket.NI_NAMEREQD:
        raise LanTrafficError("getnameinfo ist im Test verboten – resolver injizieren")
    return _real_getnameinfo(sockaddr, flags)


_NET_TOOLS = {"ping", "ping.exe", "arping", "nmap", "nmap.exe", "tracert", "tracert.exe", "traceroute"}
_RealPopen = subprocess.Popen


class _GuardedPopen(_RealPopen):  # type: ignore[misc,valid-type]
    def __init__(self, args, *a, **kw):  # type: ignore[no-untyped-def]
        parts = [str(x) for x in (args if isinstance(args, (list, tuple)) else str(args).split())]
        if parts and os.path.basename(parts[0]).lower() in _NET_TOOLS:
            for p in parts[1:]:
                try:
                    if not ipaddress.ip_address(p).is_loopback:
                        raise LanTrafficError(f"{parts[0]} {p} ist im Test verboten")
                except ValueError:
                    continue
        super().__init__(args, *a, **kw)


def _scapy_forbidden(*_a: object, **_k: object) -> None:
    raise LanTrafficError("Scapy-Senden ist im Test verboten – sender injizieren")


def _install_lan_lock() -> None:
    socket.socket.connect = _connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = _sendto  # type: ignore[method-assign,assignment]
    socket.getaddrinfo = _getaddrinfo  # type: ignore[assignment]
    socket.gethostbyname = _gethostbyname  # type: ignore[assignment]
    socket.gethostbyaddr = _gethostbyaddr  # type: ignore[assignment]
    socket.getnameinfo = _getnameinfo  # type: ignore[assignment]
    subprocess.Popen = _GuardedPopen  # type: ignore[misc]
    try:  # Scapy nur sperren, wenn installiert; Import kann ein paar Sekunden dauern
        import scapy.all as scapy_all
        import scapy.sendrecv as scapy_sendrecv

        for mod in (scapy_all, scapy_sendrecv):
            for fn in ("srp", "srp1", "sr", "sr1", "send", "sendp", "sendpfast", "sniff", "srloop", "srploop", "arping"):
                if hasattr(mod, fn):
                    setattr(mod, fn, _scapy_forbidden)
        try:
            import scapy.layers.l2 as scapy_l2

            for fn in ("arping", "getmacbyip"):
                if hasattr(scapy_l2, fn):
                    setattr(scapy_l2, fn, _scapy_forbidden)
        except Exception:
            pass
    except Exception:
        pass


_install_lan_lock()


# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Eigener Datenordner je Test (nie der echte)."""
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("NETSCAN_DATA_DIR", str(d))
    return d


@pytest.fixture
def fake_platform():  # type: ignore[no-untyped-def]
    from tests.fakes import FakePlatform

    return FakePlatform()


@pytest.fixture
def services(data_dir: Path, fake_platform):  # type: ignore[no-untyped-def]
    """Vollständiger Services-Container mit FakePlatform und Test-Datenordner."""
    from netscan.core.services import build_services
    from tests.fakes import FakeOui

    svc = build_services(data_dir=data_dir, platform=fake_platform, oui=FakeOui())  # type: ignore[arg-type]
    yield svc
    svc.close()


@pytest.fixture
def make_ctx(fake_platform):  # type: ignore[no-untyped-def]
    """Fabrik für einen ScanContext ohne JobRunner: make_ctx(**settings_overrides)."""
    from dataclasses import replace

    from netscan.config import Settings
    from netscan.core.context import ScanContext
    from netscan.core.events import EventBus

    def _make(platform=None, **overrides):  # type: ignore[no-untyped-def]
        settings = replace(Settings(), **overrides)
        return ScanContext(job_id="test", bus=EventBus(), settings=settings, platform=platform or fake_platform)

    return _make
