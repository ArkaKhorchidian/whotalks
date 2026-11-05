"""Group what we saw by company and by app, and grade it."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import orgs
from .asn import Database
from .collect import Collector

BIG_TECH = {"Google", "Google Cloud", "Amazon", "Amazon (AWS)", "Microsoft", "Meta", "Apple"}


@dataclass
class Company:
    name: str
    kind: str
    servers: set[str] = field(default_factory=set)
    apps: Counter = field(default_factory=Counter)  # app -> servers
    asns: set[int] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)


@dataclass
class App:
    name: str
    servers: set[str] = field(default_factory=set)
    companies: Counter = field(default_factory=Counter)


@dataclass
class Report:
    seconds: float
    companies: list[Company]
    apps: list[App]
    servers: int
    grade: str = "?"
    findings: list[str] = field(default_factory=list)
    hidden: int = 0  # processes we weren't allowed to look at

    @property
    def ads(self) -> list[Company]:
        return [c for c in self.companies if c.kind == orgs.ADS]

    def share(self) -> str:
        mins = self.seconds / 60
        span = "one minute" if abs(mins - 1) < 0.05 else f"{mins:g} minutes" if mins >= 1 else f"{self.seconds:.0f} seconds"
        s = (f"My laptop talked to {plural(self.servers, 'server')} run by "
             f"{plural(len(self.companies), 'company', 'companies')} in {span}"
             f" (privacy grade: {self.grade}).")
        return s + " Who does yours talk to? uvx whotalks"

    def as_dict(self) -> dict:
        return {
            "seconds": self.seconds, "servers": self.servers, "grade": self.grade, "findings": self.findings,
            "companies": [{"name": c.name, "kind": c.kind, "servers": sorted(c.servers), "asns": sorted(c.asns),
                           "apps": dict(c.apps), "hosts": sorted(c.hosts)} for c in self.companies],
            "apps": [{"name": a.name, "servers": len(a.servers), "companies": dict(a.companies)} for a in self.apps],
        }


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else many or word + 's'}"


def privacy_grade(n_ads: int, n_companies: int) -> str:
    if n_ads == 0:
        return "A" if n_companies <= 15 else "B"
    return "C" if n_ads <= 2 else "D" if n_ads <= 5 else "F"


def build(col: Collector, seconds: float, db: Database | None, names: dict[str, str] | None = None,
          hidden: int = 0) -> Report:
    names = names or {}
    companies: dict[str, Company] = {}
    apps: dict[str, App] = {}
    for ip, srv in col.servers.items():
        owner = db.lookup(ip) if db else None
        host = names.get(ip)
        cname, kind = orgs.classify(owner.asn if owner else None, owner.handle if owner else "",
                                    owner.name if owner else "", host)
        if cname == "Unknown" and host:
            cname = orgs.registrable(host)
        co = companies.setdefault(cname, Company(cname, kind))
        co.servers.add(ip)
        if owner:
            co.asns.add(owner.asn)
        if host:
            co.hosts.add(host)
        for a in srv.apps:
            co.apps[a] += 1
            ap = apps.setdefault(a, App(a))
            ap.servers.add(ip)
            ap.companies[cname] += 1

    rep = Report(seconds, sorted(companies.values(), key=lambda c: (-len(c.servers), c.name)),
                 sorted(apps.values(), key=lambda a: (-len(a.servers), a.name)), len(col.servers), hidden=hidden)
    rep.grade = privacy_grade(len(rep.ads), len(rep.companies))
    _findings(rep)
    return rep


def _list(names: list[str], n: int = 4) -> str:
    if len(names) <= n:
        return ", ".join(names[:-1]) + (" and " if len(names) > 1 else "") + names[-1] if names else ""
    return ", ".join(names[:n]) + f" and {len(names) - n} more"


def _findings(rep: Report) -> None:
    f = rep.findings
    if not rep.servers:
        f.append("Nothing talked to the internet. Either you're offline, or this is the quietest computer alive.")
        return
    ads = rep.ads
    if ads:
        via = Counter(a for c in ads for a in c.apps)
        f.append(f"{len(ads)} advertising or tracking compan{'y' if len(ads) == 1 else 'ies'}: "
                 f"{_list([c.name for c in ads])}, mostly via {via.most_common(1)[0][0]}.")
    else:
        f.append("No dedicated ad or tracking networks spotted. (Google's and Meta's ads come from the same servers as "
                 "everything else they run, so they can't be told apart here.)")
    big = sum(len(c.servers) for c in rep.companies if c.name in BIG_TECH)
    if big:
        f.append(f"{big / rep.servers:.0%} of the servers belong to Google, Amazon, Microsoft, Meta or Apple.")
    landlords = [c for c in rep.companies if c.kind in (orgs.CLOUD, orgs.CDN)]
    rented = sum(len(c.servers) for c in landlords)
    if rented:
        f.append(f"{plural(rented, 'server')} {'is' if rented == 1 else 'are'} rented from clouds and CDNs ({_list([c.name for c in landlords], 3)}): "
                 "those are the landlords, so check the app column for who's actually behind them.")
    if rep.apps:
        top = rep.apps[0]
        f.append(f"Chattiest app: {top.name}, which talked to {len(top.servers)} server{'s' * (len(top.servers) != 1)} "
                 f"at {len(top.companies)} compan{'y' if len(top.companies) == 1 else 'ies'}.")
    if rep.hidden:
        f.append(f"{rep.hidden} system processes wouldn't let us look. Run with sudo to include them.")
