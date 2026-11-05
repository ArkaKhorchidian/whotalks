"""IP address -> network owner, using the public-domain iptoasn.com database (downloaded once, cached)."""
from __future__ import annotations

import bisect
import gzip
import io
import ipaddress
import os
import pickle
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
MAX_AGE = 30 * 86400
FORMAT = 1


def cache_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "whotalks"


@dataclass
class Owner:
    asn: int
    handle: str  # e.g. "AMAZON-02"
    name: str  # e.g. "Amazon.com, Inc."
    country: str


def split_desc(desc: str) -> tuple[str, str]:
    """'AMAZON-02 - Amazon.com, Inc.' -> ('AMAZON-02', 'Amazon.com, Inc.'); 'OVH OVH SAS' -> ('OVH', 'OVH SAS')."""
    if " - " in desc:
        h, _, n = desc.partition(" - ")
        return h.strip(), n.strip() or h.strip()
    h, _, n = desc.partition(" ")
    return h.strip(), (n or h).strip()


class Database:
    def __init__(self):
        self.v4_starts: list[int] = []
        self.v4_rows: list[tuple[int, int]] = []  # (end, owner index)
        self.v6_starts: list[int] = []
        self.v6_rows: list[tuple[int, int]] = []
        self.owners: list[Owner] = []

    @classmethod
    def parse(cls, tsv: str | bytes) -> "Database":
        if isinstance(tsv, bytes):
            tsv = tsv.decode("utf-8", "replace")
        db = cls()
        index: dict[tuple[int, str, str], int] = {}
        for line in io.StringIO(tsv):
            f = line.rstrip("\n").split("\t")
            if len(f) < 5 or f[2] == "0":
                continue
            asn = int(f[2])
            key = (asn, f[3], f[4])
            i = index.get(key)
            if i is None:
                h, n = split_desc(f[4])
                i = index[key] = len(db.owners)
                db.owners.append(Owner(asn, h, n, f[3]))
            a, b = ipaddress.ip_address(f[0]), ipaddress.ip_address(f[1])
            if a.version == 4:
                db.v4_starts.append(int(a))
                db.v4_rows.append((int(b), i))
            else:
                db.v6_starts.append(int(a))
                db.v6_rows.append((int(b), i))
        return db

    def lookup(self, ip: str) -> Owner | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        starts, rows = (self.v4_starts, self.v4_rows) if a.version == 4 else (self.v6_starts, self.v6_rows)
        k = bisect.bisect_right(starts, int(a)) - 1
        if k < 0 or int(a) > rows[k][0]:
            return None
        return self.owners[rows[k][1]]

    def __len__(self) -> int:
        return len(self.v4_starts) + len(self.v6_starts)


def load(refresh: bool = False, url: str = URL, directory: Path | None = None, timeout: float = 30) -> Database:
    """Cached parsed copy if fresh, else download (about 11 MB) and parse. Raises OSError when offline with no cache."""
    d = directory or cache_dir()
    pkl = d / "ip2asn.pickle"
    if not refresh and pkl.exists() and time.time() - pkl.stat().st_mtime < MAX_AGE:
        try:
            with pkl.open("rb") as fh:
                fmt, db = pickle.load(fh)
            if fmt == FORMAT:
                return db
        except Exception:
            pass
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "whotalks"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
        data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    except OSError:
        if pkl.exists():  # stale beats nothing
            with pkl.open("rb") as fh:
                return pickle.load(fh)[1]
        raise
    db = Database.parse(data)
    try:
        d.mkdir(parents=True, exist_ok=True)
        tmp = pkl.with_suffix(".tmp")
        with tmp.open("wb") as fh:
            pickle.dump((FORMAT, db), fh, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, pkl)
    except OSError:
        pass
    return db
