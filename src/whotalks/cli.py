"""whotalks: who does your computer talk to? Watches outbound connections and groups them by company."""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections import deque

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, asn, orgs
from .collect import Collector, Conn, dns_cache, reverse_dns
from .report import Report, build, plural

KIND_STYLE = {orgs.TECH: "bright_blue", orgs.CLOUD: "cyan", orgs.CDN: "magenta", orgs.ADS: "bold red",
              orgs.SERVICE: "green", orgs.ISP: "dim", orgs.OTHER: "white"}
KIND_LABEL = {orgs.TECH: "big tech", orgs.CLOUD: "cloud", orgs.CDN: "CDN", orgs.ADS: "ads/tracking",
              orgs.SERVICE: "service", orgs.ISP: "ISP", orgs.OTHER: ""}
GRADE_STYLE = {"A": "bold green", "B": "bold bright_green", "C": "bold yellow", "D": "bold dark_orange", "F": "bold red"}


class DB:
    """Loads the IP-owner database in the background so watching can start right away."""

    def __init__(self, offline: bool, refresh: bool):
        self.db: asn.Database | None = None
        self.error: str | None = None
        self.done = threading.Event()
        if offline:
            self.done.set()
        else:
            threading.Thread(target=self._load, args=(refresh,), daemon=True).start()

    def _load(self, refresh: bool) -> None:
        try:
            self.db = asn.load(refresh=refresh)
        except Exception as e:  # offline, blocked: still show apps and IPs
            self.error = f"couldn't download the IP owner database ({e.__class__.__name__}); showing raw IPs"
        self.done.set()

    def company(self, ip: str) -> tuple[str, str]:
        o = self.db.lookup(ip) if self.db else None
        if not o:
            return ("…" if not self.done.is_set() else "Unknown"), orgs.OTHER
        return orgs.classify(o.asn, o.handle, o.name)


class LiveView:
    def __init__(self, col: Collector, db: DB, seconds: float):
        self.col, self.db, self.seconds = col, db, seconds
        self.t0 = time.monotonic()
        self.feed: deque[Conn] = deque(maxlen=12)

    def add(self, conns: list[Conn]) -> None:
        self.feed.extend(conns)

    def __rich__(self):
        left = max(0.0, self.seconds - (time.monotonic() - self.t0))
        frac = 1 - left / self.seconds if self.seconds else 1
        bar = Text("━" * int(frac * 30), "cyan") + Text("─" * (30 - int(frac * 30)), "dim")
        companies = {self.db.company(ip)[0] for ip in self.col.servers} if self.db.db else set()
        head = Table.grid(padding=(0, 3))
        for _ in range(3):
            head.add_column(justify="center")
        big = lambda n, label: Text.assemble((f"{n}", "bold bright_white"), (f"\n{label}", "dim"))  # noqa: E731
        head.add_row(big(len(self.col.servers), "servers"),
                     big(len(companies) if self.db.db else "…", "companies"), big(len(self.col.apps), "apps"))
        feed = Table.grid(padding=(0, 2))
        feed.add_column(width=22, no_wrap=True)
        feed.add_column(width=2)
        feed.add_column(width=24, no_wrap=True)
        feed.add_column(no_wrap=True)
        for c in list(self.feed)[::-1]:
            name, kind = self.db.company(c.ip)
            feed.add_row(Text(c.app, "bold"), Text("→", "dim"), Text(name, KIND_STYLE.get(kind, "")),
                         Text(f"{c.ip}:{c.port}/{c.proto}", "dim"))
        status = Text.assemble(("Watching every connection this computer makes  ", ""), bar,
                               (f"  {int(left // 60)}:{int(left % 60):02d} left", "dim"))
        return Panel(Group(status, Text(""), head, Text(""), feed), title="[bold]whotalks[/]",
                     border_style="cyan", padding=(1, 2))


def render(rep: Report, console: Console, top: int = 12) -> None:
    span = f"{rep.seconds / 60:g} minute{'s' * (rep.seconds != 60)}" if rep.seconds >= 60 else f"{rep.seconds:.0f} seconds"
    head = Table.grid(expand=True)
    head.add_column(ratio=1)
    head.add_column(justify="right")
    head.add_row(Text.assemble(("In ", ""), (span, "bold"), (", this computer talked to ", ""),
                               (plural(rep.servers, "server"), "bold"), (" run by ", ""),
                               (plural(len(rep.companies), "company", "companies"), "bold"), (", from ", ""),
                               (plural(len(rep.apps), "app"), "bold"), (".", "")),
                 Text.assemble(("privacy  ", "dim"), (rep.grade, GRADE_STYLE.get(rep.grade, ""))))

    t = Table(box=None, header_style="dim", padding=(0, 2), expand=True)
    t.add_column("Company", no_wrap=True)
    t.add_column("What", no_wrap=True)
    t.add_column("Servers", no_wrap=True)
    t.add_column("Which apps", ratio=1)
    most = max((len(c.servers) for c in rep.companies), default=1)
    for c in rep.companies[:top]:
        n = len(c.servers)
        w = max(1, round(14 * n / most))
        t.add_row(Text(c.name, KIND_STYLE.get(c.kind, "")), Text(KIND_LABEL.get(c.kind, ""), "dim"),
                  Text("█" * w, KIND_STYLE.get(c.kind, "")) + Text(f" {n}", "bold"),
                  Text(", ".join(a for a, _ in c.apps.most_common(3)), "dim"))
    if len(rep.companies) > top:
        rest = rep.companies[top:]
        t.add_row(Text(f"+ {len(rest)} more", "dim"), "", Text(f"  {sum(len(c.servers) for c in rest)}", "dim"), "")

    a = Table(box=None, header_style="dim", padding=(0, 2), expand=True)
    a.add_column("App", no_wrap=True)
    a.add_column("Servers", justify="right")
    a.add_column("Talks to", ratio=1)
    for ap in rep.apps[:8]:
        a.add_row(Text(ap.name, "bold"), str(len(ap.servers)),
                  Text(", ".join(f"{c} ({k})" for c, k in ap.companies.most_common(4)), "dim"))

    g = Table.grid(padding=(0, 1))
    g.add_column(width=2)
    g.add_column(ratio=1)
    for x in rep.findings:
        g.add_row(Text("•", "dim"), x)

    console.print(Panel(Group(head, Text(""), t, Text(""), a, Text(""), g), title="[bold]Who does my computer talk to?[/]",
                        border_style=GRADE_STYLE.get(rep.grade, "cyan").split()[-1], padding=(1, 2)))
    console.print(Text("  Share: ", "dim") + Text(rep.share(), "italic"))
    console.print()


def watch(seconds: float, interval: float, col: Collector, on_new=None) -> None:
    end = time.monotonic() + seconds
    while True:
        t = time.monotonic()
        new = col.sample()
        if on_new and new:
            on_new(new)
        if t >= end:
            break
        time.sleep(max(0.05, min(interval - (time.monotonic() - t), end - time.monotonic())))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="whotalks", description="Watch which companies your computer talks to.")
    ap.add_argument("-s", "--seconds", type=float, default=60, help="how long to watch (default 60)")
    ap.add_argument("--interval", type=float, default=0.5, help="seconds between snapshots (default 0.5)")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument("--all", action="store_true", help="list every company, not just the top 12")
    ap.add_argument("--no-rdns", action="store_true", help="don't look up reverse-DNS names for servers")
    ap.add_argument("--offline", action="store_true", help="don't download the IP owner database")
    ap.add_argument("--refresh-db", action="store_true", help="re-download the IP owner database")
    ap.add_argument("-V", "--version", action="version", version=f"whotalks {__version__}")
    a = ap.parse_args(argv)

    console = Console(stderr=a.json)
    db = DB(a.offline, a.refresh_db)
    col = Collector()
    t0 = time.monotonic()
    try:
        if a.json or not console.is_terminal:
            watch(a.seconds, a.interval, col)
        else:
            view = LiveView(col, db, a.seconds)
            with Live(view, console=console, refresh_per_second=8, transient=True):
                watch(a.seconds, a.interval, col, view.add)
    except KeyboardInterrupt:
        pass  # report on whatever we saw so far
    seconds = min(a.seconds, round(time.monotonic() - t0))

    with console.status("Looking up who owns each server…") if not a.json else _null():
        names = dns_cache()
        if not a.no_rdns:
            todo = [ip for ip in col.servers if ip not in names]
            names.update(reverse_dns(todo))
        db.done.wait(timeout=120)
    if db.error:
        console.print(Text(f"  ! {db.error}", "yellow"))
    rep = build(col, seconds, db.db, names, hidden=col.hidden)
    if a.json:
        print(json.dumps(rep.as_dict(), indent=2))
    else:
        render(rep, console, top=10**6 if a.all else 12)
    return 0


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


if __name__ == "__main__":
    sys.exit(main())
