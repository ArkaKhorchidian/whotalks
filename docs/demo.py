"""Record the README demo: a replay of a typical laptop's minute (Chrome with a news site open, Slack,
Spotify, VS Code, iCloud...). The connections are synthetic; the IP owner lookups are real."""
import random
import sys
import time

from whotalks import asn, cli, collect

random.seed(7)
db = asn.load()
by_asn: dict[int, list[tuple[int, int]]] = {}
for start, (end, i) in zip(db.v4_starts, db.v4_rows):
    by_asn.setdefault(db.owners[i].asn, []).append((start, end))


def ip_in(a: int) -> str:
    lo, hi = random.choice(by_asn[a])
    n = random.randint(lo, hi)
    return ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))


GOOGLE, AWS, MSFT, META, APPLE, CF, AKAMAI, FASTLY, GITHUB = 15169, 16509, 8075, 32934, 714, 13335, 20940, 54113, 36459
SCRIPT = [  # (app, asn, how many servers)
    ("Google Chrome", GOOGLE, 14), ("Google Chrome", CF, 11), ("Google Chrome", AWS, 12), ("Google Chrome", FASTLY, 6),
    ("Google Chrome", AKAMAI, 5), ("Google Chrome", META, 3), ("Google Chrome", 19750, 2), ("Google Chrome", 200478, 2),
    ("Google Chrome", 26459, 2), ("Google Chrome", 62713, 1), ("Google Chrome", 26667, 1), ("Google Chrome", 22075, 1),
    ("Google Chrome", 14061, 2), ("Google Chrome", 24940, 1), ("Google Chrome", 396982, 3),
    ("Slack", AWS, 7), ("Slack", CF, 2), ("Spotify", GOOGLE, 3), ("Spotify", 396982, 4), ("Spotify", FASTLY, 2),
    ("Spotify", AKAMAI, 1), ("VS Code", MSFT, 5), ("VS Code", GITHUB, 2), ("VS Code", FASTLY, 1),
    ("iCloud", APPLE, 4), ("iCloud", AKAMAI, 2), ("Apple Push", APPLE, 2), ("Zoom", 30103, 3), ("Zoom", AWS, 2),
    ("Dropbox", 19679, 3), ("Microsoft Teams", MSFT, 4), ("Microsoft Teams", AKAMAI, 2), ("Siri Suggestions", APPLE, 2),
    ("Discord", CF, 3), ("Discord", GOOGLE, 1), ("Docker Desktop", AWS, 2), ("Docker Desktop", CF, 1),
]
events = []
for app, a, n in SCRIPT:
    for _ in range(n):
        events.append((random.random() ** 1.6 * 55, collect.Conn(ip_in(a), random.choice([443, 443, 443, 5223, 80]),
                                                                  random.choice(["tcp", "tcp", "tcp", "udp"]), app)))
events.sort(key=lambda e: e[0])
t0 = time.monotonic()
collect.Collector.snapshot = lambda self: [c for t, c in events if t <= time.monotonic() - t0]
sys.exit(cli.main(["--no-rdns", "-s", "60"]))
