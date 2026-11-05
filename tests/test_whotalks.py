import gzip
import json
import socket
from collections import namedtuple
from pathlib import Path

import psutil
import pytest

from whotalks import asn, cli, collect, orgs, report

TSV = """1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed
8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC
52.0.0.0\t52.79.255.255\t16509\tUS\tAMAZON-02 - Amazon.com, Inc.
74.119.118.0\t74.119.119.255\t19750\tUS\tAS-CRITEO - Criteo Corp.
88.198.0.0\t88.198.255.255\t24940\tDE\tHETZNER-AS Hetzner Online GmbH
98.0.0.0\t98.0.255.255\t7922\tUS\tCOMCAST-7922 - Comcast Cable Communications, LLC
203.0.113.0\t203.0.113.255\t64500\tUS\tEXAMPLE-AS - Example Widgets Co., Ltd.
2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.
"""


@pytest.fixture(scope="module")
def db():
    return asn.Database.parse(TSV)


# ---------------------------------------------------------------------------
# IP -> owner
# ---------------------------------------------------------------------------
def test_lookup(db):
    assert db.lookup("1.0.0.1").asn == 13335 and db.lookup("1.0.0.1").name == "Cloudflare, Inc."
    assert db.lookup("2606:4700:4700::1111").asn == 13335
    assert db.lookup("::ffff:8.8.8.8").asn == 15169
    assert db.lookup("1.0.2.1") is None  # "not routed" rows are skipped
    assert db.lookup("9.9.9.9") is None and db.lookup("nonsense") is None
    assert db.lookup("88.198.1.1").handle == "HETZNER-AS"


def test_split_desc():
    assert asn.split_desc("AMAZON-02 - Amazon.com, Inc.") == ("AMAZON-02", "Amazon.com, Inc.")
    assert asn.split_desc("OVH OVH SAS") == ("OVH", "OVH SAS")


def test_load_downloads_once_and_caches(tmp_path, monkeypatch):
    calls = []

    class R:
        def __init__(self, data):
            self.data = data

        def read(self):
            return self.data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout):
        calls.append(req.full_url)
        return R(gzip.compress(TSV.encode()))

    monkeypatch.setattr(asn.urllib.request, "urlopen", fake)
    d = asn.load(directory=tmp_path)
    assert d.lookup("8.8.8.8").asn == 15169 and len(calls) == 1
    assert asn.load(directory=tmp_path).lookup("8.8.8.8").asn == 15169 and len(calls) == 1  # from cache

    def offline(req, timeout):
        raise OSError("offline")

    monkeypatch.setattr(asn.urllib.request, "urlopen", offline)
    assert asn.load(refresh=True, directory=tmp_path).lookup("8.8.8.8")  # stale cache beats nothing
    with pytest.raises(OSError):
        asn.load(directory=tmp_path / "empty")


# ---------------------------------------------------------------------------
# Who's who
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("asn_,handle,name,ptr,expect", [
    (15169, "GOOGLE", "Google LLC", None, ("Google", orgs.TECH)),
    (16509, "AMAZON-02", "Amazon.com, Inc.", None, ("Amazon (AWS)", orgs.CLOUD)),
    (16509, "AMAZON-02", "Amazon.com, Inc.", "lb-140-82-112-3-iad.github.com", ("GitHub", orgs.SERVICE)),
    (15169, "GOOGLE", "Google LLC", "ad.doubleclick.net", ("Google Ads", orgs.ADS)),
    (16509, "AMAZON-02", "Amazon.com, Inc.", "ib.adnxs.com", ("adnxs.com", orgs.ADS)),
    (19750, "AS-CRITEO", "Criteo Corp.", None, ("Criteo", orgs.ADS)),
    (7922, "COMCAST-7922", "Comcast Cable Communications, LLC", None, ("Comcast Cable Communications", orgs.ISP)),
    (64500, "EXAMPLE-AS", "Example Widgets Co., Ltd.", None, ("Example Widgets", orgs.OTHER)),
    (None, "", "", None, ("Unknown", orgs.OTHER)),
])
def test_classify(asn_, handle, name, ptr, expect):
    assert orgs.classify(asn_, handle, name, ptr) == expect


def test_tidy():
    assert orgs.tidy("Anthropic, PBC") == "Anthropic"
    assert orgs.tidy("HANGZHOU ALIBABA ADVERTISING CO.,LTD.") == "Hangzhou Alibaba Advertising"
    assert orgs.registrable("a.b.example.co.uk") == "example.co.uk" and orgs.registrable("ib.adnxs.com") == "adnxs.com"


# ---------------------------------------------------------------------------
# Apps and connections
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,exe,expect", [
    ("Google Chrome Helper (Renderer)",
     "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131/Helpers/"
     "Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)", "Google Chrome"),
    ("Slack Helper", "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper", "Slack"),
    ("apsd", "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd", "Apple Push"),
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google Chrome"),
    ("msedge.exe", None, "Microsoft Edge"),
    ("code", "/usr/share/code/code", "VS Code"),
    ("Foo Helper (GPU)", None, "Foo"),
    ("python3", "/usr/bin/python3", "python3"),
    (None, None, "unknown"),
])
def test_app_name(name, exe, expect):
    assert collect.app_name(name, exe) == expect


def test_is_public():
    assert collect.is_public("1.1.1.1") and collect.is_public("2606:4700::1111")
    for ip in ("127.0.0.1", "192.168.1.5", "10.0.0.1", "169.254.1.1", "::1", "fe80::1%en0", "224.0.0.251",
               "100.64.0.1", "::ffff:192.168.0.1", "junk"):
        assert not collect.is_public(ip), ip


Addr = namedtuple("Addr", "ip port")
SConn = namedtuple("SConn", "fd family type laddr raddr status pid")


def fake_conn(ip, port=443, pid=None, status=psutil.CONN_ESTABLISHED, kind=socket.SOCK_STREAM):
    return SConn(-1, socket.AF_INET, kind, Addr("192.168.1.2", 50000), Addr(ip, port) if ip else (), status, pid)


def test_collector_filters_and_accumulates(monkeypatch):
    conns = [
        fake_conn("1.0.0.1"), fake_conn("8.8.8.8", 443, kind=socket.SOCK_DGRAM, status=psutil.CONN_NONE),  # QUIC
        fake_conn("8.8.8.8", 443), fake_conn("192.168.1.1"), fake_conn(None, status=psutil.CONN_LISTEN),
        fake_conn("52.1.1.1", status=psutil.CONN_TIME_WAIT),
    ]
    monkeypatch.setattr(collect.psutil, "net_connections", lambda kind: conns)
    col = collect.Collector()
    col._system_wide = True
    new = col.sample()
    assert sorted(c.ip for c in new) == ["1.0.0.1", "8.8.8.8"]
    assert col.servers["8.8.8.8"].protos == {"tcp", "udp"} and col.servers["8.8.8.8"].sightings == 2
    assert col.sample() == []  # nothing new the second time
    assert col.servers["1.0.0.1"].sightings == 2 and col.apps["unknown"] == {"1.0.0.1", "8.8.8.8"}


def test_collector_falls_back_to_per_process(monkeypatch):
    def denied(kind):
        raise psutil.AccessDenied()

    class P:
        def __init__(self, pid, conns, deny=False):
            self.pid, self._c, self._deny = pid, conns, deny

        def net_connections(self, kind):
            if self._deny:
                raise psutil.AccessDenied()
            return self._c

    monkeypatch.setattr(collect.psutil, "net_connections", denied)
    monkeypatch.setattr(collect.psutil, "process_iter", lambda: [P(1, [fake_conn("1.0.0.9")]), P(2, [], deny=True)])
    col = collect.Collector()
    col._system_wide = True
    monkeypatch.setattr(col, "_app", lambda pid: f"app{pid}")
    assert [c.app for c in col.sample()] == ["app1"] and col.hidden == 1 and not col._system_wide


def test_real_connection_is_seen():
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=3)
    except OSError:
        pytest.skip("no internet")
    with s:
        col = collect.Collector()
        col.sample()
        assert "1.1.1.1" in col.servers
        me = psutil.Process()
        assert collect.app_name(me.name(), me.exe()) in col.servers["1.1.1.1"].apps


def test_parse_displaydns():
    out = """
Windows IP Configuration

    www.github.com
    ----------------------------------------
    Record Name . . . . . : www.github.com
    Record Type . . . . . : 5
    Time To Live  . . . . : 3593
    Data Length . . . . . : 8
    Section . . . . . . . : Answer
    CNAME Record  . . . . : github.com

    Record Name . . . . . : github.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 59
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 140.82.112.3
"""
    assert collect.parse_displaydns(out) == {"140.82.112.3": "github.com"}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def collector_with(servers: dict[str, set[str]]) -> collect.Collector:
    col = collect.Collector()
    for ip, apps in servers.items():
        col.servers[ip] = collect.Server(ip, apps=set(apps))
        for a in apps:
            col.apps.setdefault(a, set()).add(ip)
    return col


def test_report_groups_by_company_and_app(db):
    col = collector_with({"1.0.0.1": {"Google Chrome"}, "1.0.0.2": {"Slack"}, "8.8.8.8": {"Google Chrome"},
                          "52.1.1.1": {"Slack"}, "52.1.1.2": {"Slack"}, "74.119.118.5": {"Google Chrome"},
                          "203.0.113.9": {"Spotify"}, "9.9.9.9": {"Spotify"}})
    rep = report.build(col, 60, db, {"9.9.9.9": "dns9.quad9.net"})
    names = [c.name for c in rep.companies]
    assert names[:2] == ["Amazon (AWS)", "Cloudflare"] and "quad9.net" in names and "Example Widgets" in names
    assert [c.name for c in rep.ads] == ["Criteo"] and rep.grade == "C"
    slack = next(a for a in rep.apps if a.name == "Slack")
    assert slack.companies == {"Amazon (AWS)": 2, "Cloudflare": 1}
    text = "\n".join(rep.findings)
    assert "Criteo, mostly via Google Chrome" in text and "Chattiest app: Google Chrome, which talked to 3 servers at 3 companies" in text
    assert "38% of the servers belong to Google, Amazon" in text
    assert rep.share().startswith("My laptop talked to 8 servers run by 6 companies in one minute (privacy grade: C).")
    json.dumps(rep.as_dict())


def test_report_without_database():
    rep = report.build(collector_with({"1.0.0.1": {"x"}}), 30, None)
    assert rep.companies[0].name == "Unknown" and "30 seconds" in rep.share()


def test_privacy_grade():
    assert [report.privacy_grade(a, c) for a, c in [(0, 5), (0, 40), (1, 5), (4, 5), (9, 50)]] == ["A", "B", "C", "D", "F"]


def test_render(db):
    from rich.console import Console
    import io
    col = collector_with({"1.0.0.1": {"Google Chrome"}, "74.119.118.5": {"Google Chrome"}, "52.1.1.1": {"Slack"}})
    c = Console(width=160, record=True, file=io.StringIO())
    cli.render(report.build(col, 60, db), c)
    out = c.export_text()
    assert "Who does my computer talk to?" in out and "Criteo" in out and "ads/tracking" in out and "uvx whotalks" in out


def test_cli_json(monkeypatch, capsys, db):
    monkeypatch.setattr(collect.Collector, "SYSTEM_WIDE", True)
    monkeypatch.setattr(cli.asn, "load", lambda refresh=False: db)
    monkeypatch.setattr(collect.psutil, "net_connections", lambda kind: [fake_conn("8.8.8.8"), fake_conn("1.0.0.1")])
    monkeypatch.setattr(cli, "reverse_dns", lambda ips: {})
    assert cli.main(["--json", "-s", "0.3", "--interval", "0.1"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["servers"] == 2 and {c["name"] for c in out["companies"]} == {"Google", "Cloudflare"}
