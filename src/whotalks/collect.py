"""Watch which remote servers each app on this machine is connected to. No admin rights needed."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field

import psutil


@dataclass(frozen=True)
class Conn:
    ip: str
    port: int
    proto: str  # "tcp" or "udp"
    app: str


@dataclass
class Server:
    ip: str
    ports: set[int] = field(default_factory=set)
    protos: set[str] = field(default_factory=set)
    apps: set[str] = field(default_factory=set)
    first: float = 0.0
    sightings: int = 0


PRETTY = {
    "chrome": "Google Chrome", "google chrome": "Google Chrome", "msedge": "Microsoft Edge", "firefox": "Firefox",
    "firefox-bin": "Firefox", "brave": "Brave", "safari": "Safari", "code": "VS Code", "code helper": "VS Code",
    "slack": "Slack", "spotify": "Spotify", "discord": "Discord", "zoom": "Zoom", "zoom.us": "Zoom",
    "teams": "Microsoft Teams", "ms-teams": "Microsoft Teams", "onedrive": "OneDrive", "dropbox": "Dropbox",
    "steam": "Steam", "steamwebhelper": "Steam", "svchost": "Windows services", "searchhost": "Windows Search",
    "explorer": "Windows Explorer", "wwahost": "Windows apps",
}
# macOS system daemons people actually see in the list, translated
MAC_DAEMONS = {
    "apsd": "Apple Push", "cloudd": "iCloud", "bird": "iCloud Drive", "nsurlsessiond": "macOS background downloads",
    "trustd": "macOS certificate checks", "akd": "Apple ID", "identityservicesd": "iMessage/FaceTime",
    "rapportd": "Apple Continuity", "mDNSResponder": "macOS DNS", "parsecd": "Siri Suggestions",
    "suggestd": "Siri Suggestions", "softwareupdated": "Software Update", "commerce": "App Store",
    "storedownloadd": "App Store", "assistantd": "Siri", "locationd": "Location Services",
    "timed": "macOS clock sync", "symptomsd": "macOS network diagnostics", "remindd": "Reminders",
    "CalendarAgent": "Calendar", "photoanalysisd": "Photos", "cloudphotod": "iCloud Photos",
    "itunescloudd": "Apple Music", "newsd": "Apple News", "weatherd": "Weather", "mobileassetd": "macOS assets",
    "AMPLibraryAgent": "Apple Music", "WeatherWidget": "Weather", "searchpartyd": "Find My",
}


def app_name(name: str | None, exe: str | None = None) -> str:
    """Turn a process into the app a person would recognise."""
    if exe:
        bundles = re.findall(r"/([^/]+)\.app(?=/)", exe.replace("\\", "/"))
        if bundles:
            return PRETTY.get(bundles[0].lower(), bundles[0])
    n = (name or "").strip()
    if not n:
        return "unknown"
    if n in MAC_DAEMONS:
        return MAC_DAEMONS[n]
    base = re.sub(r"\.exe$", "", n, flags=re.I)
    low = base.lower()
    if low in PRETTY:
        return PRETTY[low]
    # "Google Chrome Helper (Renderer)", "Slack Helper (GPU)", "chrome_crashpad_handler"
    m = re.match(r"(.+?) helper\b", low)
    if m and m.group(1) in PRETTY:
        return PRETTY[m.group(1)]
    if m:
        return base[: len(m.group(1))]
    return base


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


def _conn_list(p: psutil.Process):
    f = getattr(p, "net_connections", None) or p.connections  # psutil < 6 calls it connections()
    return f(kind="inet")


class Collector:
    """Call sample() repeatedly; `servers` accumulates everything seen."""

    SYSTEM_WIDE = sys.platform != "darwin"  # macOS needs root for the system-wide call

    def __init__(self):
        self.servers: dict[str, Server] = {}
        self.apps: dict[str, set[str]] = {}
        self.hidden = 0  # processes we weren't allowed to inspect in the last snapshot
        self._names: dict[int, tuple[float, str]] = {}  # pid -> (create_time, app)
        self._system_wide = self.SYSTEM_WIDE

    def _app(self, pid: int | None) -> str:
        if not pid:
            return "unknown"
        try:
            p = psutil.Process(pid)
            ct = p.create_time()
            hit = self._names.get(pid)
            if hit and hit[0] == ct:
                return hit[1]
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = None
            name = app_name(p.name(), exe)
            self._names[pid] = (ct, name)
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return "unknown"

    def snapshot(self) -> list[Conn]:
        raw: list[tuple] = []  # (pid, conn)
        if self._system_wide:
            try:
                raw = [(c.pid, c) for c in psutil.net_connections(kind="inet")]
            except psutil.AccessDenied:
                self._system_wide = False
        if not self._system_wide:
            hidden = 0
            for p in psutil.process_iter():
                try:
                    raw += [(p.pid, c) for c in _conn_list(p)]
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    hidden += 1
                except (psutil.NoSuchProcess, OSError):
                    pass
            self.hidden = hidden
        out = []
        for pid, c in raw:
            if not c.raddr:
                continue
            tcp = c.type == socket.SOCK_STREAM
            if tcp and c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT, psutil.CONN_CLOSE_WAIT,
                                        psutil.CONN_FIN_WAIT1, psutil.CONN_FIN_WAIT2):
                continue
            ip = c.raddr.ip.split("%")[0]
            if not is_public(ip):
                continue
            out.append(Conn(ip, c.raddr.port, "tcp" if tcp else "udp", self._app(pid)))
        return out

    def sample(self, now: float | None = None) -> list[Conn]:
        """Record one snapshot; returns connections to servers not seen before."""
        now = time.time() if now is None else now
        new = []
        for c in self.snapshot():
            s = self.servers.get(c.ip)
            if s is None:
                s = self.servers[c.ip] = Server(c.ip, first=now)
                new.append(c)
            s.ports.add(c.port)
            s.protos.add(c.proto)
            s.apps.add(c.app)
            s.sightings += 1
            self.apps.setdefault(c.app, set()).add(c.ip)
        return new


# ---------------------------------------------------------------------------
# Names for IPs
# ---------------------------------------------------------------------------
def parse_displaydns(out: str) -> dict[str, str]:
    """Windows `ipconfig /displaydns`: IP -> the name that was looked up to get it."""
    ips: dict[str, str] = {}
    name = None
    for line in out.splitlines():
        m = re.match(r"\s*Record Name[ .]*:\s*(\S+)", line)
        if m:
            name = m.group(1).rstrip(".")
            continue
        m = re.match(r"\s*(?:A|AAAA) \(Host\) Record[ .]*:\s*(\S+)", line)
        if m and name:
            ips.setdefault(m.group(1), name)
    return ips


def dns_cache() -> dict[str, str]:
    """Names this machine looked up recently, where the OS lets a normal user see them (Windows)."""
    if sys.platform != "win32":
        return {}
    try:
        out = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True, timeout=10,
                             errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_displaydns(out)


def reverse_dns(ips: list[str], workers: int = 32, timeout: float = 2.0) -> dict[str, str]:
    """PTR names for many IPs at once; missing ones are simply absent."""
    from concurrent.futures import ThreadPoolExecutor, wait

    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return ip, None

    out = {}
    ex = ThreadPoolExecutor(max_workers=workers)
    futs = [ex.submit(one, ip) for ip in ips]
    done, _ = wait(futs, timeout=timeout + 0.5 * len(ips) / workers)
    for f in done:
        ip, host = f.result()
        if host:
            out[ip] = host
    ex.shutdown(wait=False, cancel_futures=True)
    return out
