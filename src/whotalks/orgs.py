"""Who's who: friendly company names and what kind of company each network belongs to.

Network owners (ASNs) were checked against the iptoasn.com database. Anything not listed falls back
to the owner's registered name, tidied up.
"""
from __future__ import annotations

import re

# kinds
TECH = "big tech"
CLOUD = "cloud"  # rents servers to other companies: the IP tells you the landlord, not the tenant
CDN = "cdn"  # delivers content for other companies
ADS = "ads & tracking"
SERVICE = "service"
ISP = "isp"
OTHER = "other"

KNOWN: dict[int, tuple[str, str]] = {}


def _add(company: str, kind: str, *asns: int) -> None:
    for a in asns:
        KNOWN[a] = (company, kind)


_add("Google", TECH, 15169, 36040, 36384, 43515)
_add("Google Fiber", ISP, 16591)
_add("Google Cloud", CLOUD, 396982, 16550, 32381, 394089, 396178)
_add("Amazon (AWS)", CLOUD, 16509, 14618, 8987, 36263)
_add("Amazon", TECH, 7224)
_add("Microsoft", TECH, 8075, 8068, 12076, 3598, 6584, 63314, 35106, 45139, 5761)
_add("Meta", TECH, 32934, 63293)
_add("Apple", TECH, 714, 6185)
_add("X (Twitter)", TECH, 13414, 35995)
_add("LinkedIn", TECH, 14413, 13443)
_add("ByteDance (TikTok)", TECH, 396986, 138699, 11983)
_add("Pinterest", TECH, 53620)
_add("Yandex", TECH, 13238, 202611)
_add("Tencent", TECH, 45090, 132203, 133478)
_add("Alibaba", CLOUD, 45102, 37963)
_add("Yahoo", TECH, 10310, 14776, 14777, 14778, 14779, 14780, 26101, 36088)
_add("Adobe", SERVICE, 14365, 15224, 58664)
_add("Salesforce", SERVICE, 22606, 393517, 396417)
_add("Oracle Cloud", CLOUD, 31898)
_add("Oracle", SERVICE, 1215, 20037)
_add("IBM Cloud", CLOUD, 36351)
_add("DigitalOcean", CLOUD, 14061, 393406, 46652)
_add("Hetzner", CLOUD, 24940, 212317, 213230, 215859)
_add("OVHcloud", CLOUD, 16276)
_add("Linode (Akamai)", CLOUD, 63949)
_add("Vultr", CLOUD, 20473)
_add("Scaleway", CLOUD, 12876)
_add("Equinix Metal", CLOUD, 54825)
_add("Cloudflare", CDN, 13335, 14789, 202623, 203898, 209242, 394536, 395747)
_add("Akamai", CDN, 20940, 16625, 24319, 32787, 393560, 213120)
_add("Fastly", CDN, 54113, 394192)
_add("Edgecast", CDN, 14210)
_add("CDN77", CDN, 60068)
_add("CacheFly", CDN, 30081)
_add("Imperva", CDN, 19551)
_add("GitHub", SERVICE, 36459)
_add("Netflix", SERVICE, 2906, 40027)
_add("Zoom", SERVICE, 30103)
_add("Dropbox", SERVICE, 19679)
_add("Valve (Steam)", SERVICE, 32590)
_add("Riot Games", SERVICE, 62830)
_add("Mozilla", SERVICE, 395642)
_add("Zscaler", SERVICE, 22616)
_add("Cisco Umbrella", SERVICE, 36692)
_add("NS1", SERVICE, 62597)
# companies whose business is advertising, measurement or tracking, and who run their own networks
_add("Criteo", ADS, 19750, 44788, 55569)
_add("Taboola", ADS, 200478, 206614)
_add("Outbrain", ADS, 22075)
_add("PubMatic", ADS, 62713)
_add("The Trade Desk", ADS, 26459)
_add("Xandr (Microsoft Ads)", ADS, 29990)
_add("Magnite", ADS, 26667)
_add("Quantcast", ADS, 27281)
_add("comScore", ADS, 42320)
_add("Adform", ADS, 198622)
_add("Adjust", ADS, 205184, 61273)
_add("InMobi", ADS, 133025)
_add("Unity Ads", ADS, 204032)

# reverse-DNS hints for the cases where the network owner hides the real party
PTR_HINTS = [
    (re.compile(r"(^|\.)1e100\.net$|(^|\.)google(usercontent|apis)?\.com$"), ("Google", TECH)),
    (re.compile(r"(^|\.)(facebook\.com|fbcdn\.net|fna\.fbcdn\.net)$"), ("Meta", TECH)),
    (re.compile(r"(^|\.)(doubleclick\.net|googlesyndication\.com|googleadservices\.com)$"), ("Google Ads", ADS)),
    (re.compile(r"(^|\.)(adnxs\.com|criteo\.(com|net)|taboola\.com|outbrain\.com|scorecardresearch\.com|"
                r"quantserve\.com|pubmatic\.com|rubiconproject\.com|adsrvr\.org|amazon-adsystem\.com|"
                r"moatads\.com|doubleverify\.com|adsafeprotected\.com|branch\.io|appsflyer\.com|"
                r"adjust\.(com|io)|mixpanel\.com|segment\.(io|com)|hotjar\.com)$"), (None, ADS)),
    (re.compile(r"(^|\.)github\.com$"), ("GitHub", SERVICE)),
    (re.compile(r"(^|\.)slack\.com$"), ("Slack", SERVICE)),
    (re.compile(r"(^|\.)spotify\.com$"), ("Spotify", SERVICE)),
    (re.compile(r"(^|\.)zoom\.us$"), ("Zoom", SERVICE)),
    (re.compile(r"(^|\.)apple\.com$|(^|\.)aaplimg\.com$"), ("Apple", TECH)),
]

ISP_WORDS = re.compile(r"COMCAST|CHARTER|VERIZON|AT&T|ATT-|COX |T-MOBILE|SPECTRUM|CENTURYLINK|LUMEN|FRONTIER|"
                       r"DEUTSCHE TELEKOM|VODAFONE|ORANGE|BRITISH TELECOM|VIRGIN MEDIA|TELEFONICA|ROGERS|BELL CANADA|"
                       r"TELSTRA|OPTUS|STARLINK|SPACEX|SKY BROADBAND|FREE SAS|PROXAD", re.I)
SUFFIX = re.compile(r"(?:[,.]\s*|\s+)(inc|llc|ltd|limited|corp|corporation|co|gmbh|sas|s\.a|b\.v|bv|ag|plc|pte|pty|sarl|"
                    r"srl|spa|oy|ab|as|a/s|l\.l\.c|pbc)\.?$", re.I)


def tidy(name: str) -> str:
    """'Amazon.com, Inc.' -> 'Amazon.com'; 'HETZNER ONLINE GMBH' -> 'Hetzner Online'."""
    n = name.strip().strip(",")
    for _ in range(3):
        n2 = SUFFIX.sub("", n).strip().strip(",")
        if n2 == n:
            break
        n = n2
    if n.isupper() and len(n) > 4:
        n = n.title()
    return n or name


def classify(asn: int | None, handle: str = "", name: str = "", ptr: str | None = None) -> tuple[str, str]:
    """(company, kind) for a network owner, refined by its reverse-DNS name when that helps."""
    company, kind = KNOWN.get(asn or -1, (None, None))
    if ptr:
        host = ptr.lower().rstrip(".")
        for rx, (c, k) in PTR_HINTS:
            if rx.search(host):
                if k == ADS:
                    return c or registrable(host), ADS
                if company is None or kind in (CLOUD, CDN):
                    return c, k
    if company:
        return company, kind
    if not name and not handle:
        return "Unknown", OTHER
    if ISP_WORDS.search(f"{handle} {name}"):
        return tidy(name or handle), ISP
    return tidy(name or handle), OTHER


def registrable(host: str) -> str:
    """Rough eTLD+1: 'ib.adnxs.com' -> 'adnxs.com', 'x.y.co.uk' -> 'y.co.uk'."""
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
