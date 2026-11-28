"""Offline IP -> country lookup, from the free DB-IP "IP to Country Lite" database.

The CSV (CC BY 4.0, https://db-ip.com) is converted once into a compact binary file
next to the phishlens database. Lookups are local: no IP is ever sent to a third party.

    phishlens geoip update            download this month's file and convert it
    phishlens geoip update --file x   convert a CSV (.csv or .csv.gz) downloaded by hand
"""

from __future__ import annotations

import datetime
import gzip
import io
import ipaddress
import os
import struct
import sys
import tempfile
import threading
import urllib.request
from array import array
from pathlib import Path

MAGIC = b"PLGEO1"
URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
ATTRIBUTION = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"
_lock = threading.Lock()
_cache: dict = {"path": None, "mtime": None, "db": None}


def default_path() -> Path:
    if os.environ.get("PHISHLENS_GEOIP"):
        return Path(os.environ["PHISHLENS_GEOIP"])
    from . import store
    return store.default_path().parent / "geoip.bin"


# --- building --------------------------------------------------------------

def convert(lines, target: Path, version: str) -> int:
    """Convert DB-IP CSV lines (start,end,country) to the binary format. Returns range count."""
    v4: list[tuple[int, int, bytes]] = []
    v6: list[tuple[int, int, bytes]] = []
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) < 3 or len(parts[2]) != 2 or parts[2] == "ZZ":
            continue
        try:
            start, end = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        rows = v4 if start.version == 4 else v6
        code = parts[2].upper().encode("ascii")
        if rows and rows[-1][2] == code and rows[-1][1] + 1 == int(start):
            rows[-1] = (rows[-1][0], int(end), code)  # merge adjacent ranges
        else:
            rows.append((int(start), int(end), code))
    v4.sort()
    v6.sort()
    out = io.BytesIO()
    out.write(MAGIC + version.encode("ascii")[:10].ljust(10) + struct.pack("<II", len(v4), len(v6)))
    for column in (0, 1):
        values = array("I", (r[column] for r in v4))
        if sys.byteorder == "big":
            values.byteswap()
        out.write(values.tobytes())
    out.write(b"".join(r[2] for r in v4))
    for column in (0, 1):
        out.write(b"".join(r[column].to_bytes(16, "big") for r in v6))
    out.write(b"".join(r[2] for r in v6))
    target.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replace: a running web server never reads a half-written file
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
        tmp.write(out.getvalue())
    os.replace(tmp.name, target)
    return len(v4) + len(v6)


def update(target: Path | None = None, source: str | None = None, timeout: int = 120) -> tuple[int, str]:
    """Download (or read) the DB-IP CSV and convert it. Returns (ranges, version)."""
    target = target or default_path()
    if source:
        opener = gzip.open if source.endswith(".gz") else open
        with opener(source, "rt", encoding="utf-8") as fh:
            version = Path(source).name[:40]
            return convert(fh, target, datetime.date.today().isoformat()), version
    today = datetime.date.today().replace(day=1)
    last_month = (today - datetime.timedelta(days=1)).replace(day=1)
    error = None
    for month in (today, last_month):  # the new month's file can appear a few days late
        url = URL.format(month=month.strftime("%Y-%m"))
        request = urllib.request.Request(url, headers={"User-Agent": "phishlens"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = gzip.decompress(response.read()).decode("utf-8")
        except OSError as exc:
            error = exc
            continue
        version = month.strftime("%Y-%m")
        return convert(data.splitlines(), target, version), version
    raise RuntimeError(f"cannot download the DB-IP database ({error})")


# --- lookup ----------------------------------------------------------------

class GeoDB:
    def __init__(self, data: bytes):
        if data[:6] != MAGIC:
            raise ValueError("not a phishlens GeoIP file")
        self.version = data[6:16].decode("ascii").strip()
        n4, n6 = struct.unpack("<II", data[16:24])
        pos = 24
        self.v4_start = array("I")
        self.v4_start.frombytes(data[pos:pos + 4 * n4])
        pos += 4 * n4
        self.v4_end = array("I")
        self.v4_end.frombytes(data[pos:pos + 4 * n4])
        pos += 4 * n4
        if sys.byteorder == "big":
            self.v4_start.byteswap()
            self.v4_end.byteswap()
        self.v4_code = data[pos:pos + 2 * n4]
        pos += 2 * n4
        self.v6_start = data[pos:pos + 16 * n6]
        pos += 16 * n6
        self.v6_end = data[pos:pos + 16 * n6]
        pos += 16 * n6
        self.v6_code = data[pos:pos + 2 * n6]
        self.n6 = n6

    def country(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return None
        value = int(addr)
        if addr.version == 4:
            lo, hi = 0, len(self.v4_start)
            while lo < hi:  # last range whose start <= value
                mid = (lo + hi) // 2
                if self.v4_start[mid] <= value:
                    lo = mid + 1
                else:
                    hi = mid
            i = lo - 1
            if i >= 0 and value <= self.v4_end[i]:
                return self.v4_code[2 * i:2 * i + 2].decode()
            return None
        key = value.to_bytes(16, "big")
        lo, hi = 0, self.n6
        while lo < hi:
            mid = (lo + hi) // 2
            if self.v6_start[16 * mid:16 * mid + 16] <= key:
                lo = mid + 1
            else:
                hi = mid
        i = lo - 1
        if i >= 0 and key <= self.v6_end[16 * i:16 * i + 16]:
            return self.v6_code[2 * i:2 * i + 2].decode()
        return None


def load(path: Path | None = None) -> GeoDB | None:
    """The GeoIP database, cached and reloaded when the file changes. None if missing."""
    path = path or default_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    with _lock:
        if _cache["path"] != path or _cache["mtime"] != mtime:
            try:
                _cache.update(path=path, mtime=mtime, db=GeoDB(path.read_bytes()))
            except (OSError, ValueError):
                return None
        return _cache["db"]


def country(ip: str | None) -> str | None:
    if not ip:
        return None
    db = load()
    return db.country(ip) if db else None
