"""Cloud / CDN / hosting provider IP-address attribution.

Given an IP (and optionally its ASN), say which cloud/CDN/hosting provider it
belongs to, and - where the provider publishes it - the region and service.

Two mechanisms, in priority order:

1. Published prefix files - authoritative, and carry region + service. Fetched
   on first use and cached on disk (default 24h TTL). A provider whose file
   fails to fetch/parse falls back to its last good cached copy; failing that
   it is skipped and only the ASN map below can still attribute it.

2. A curated ASN -> provider map - coarse (provider name only, no region), for
   providers that publish no machine-readable prefix file (Alibaba, Tencent,
   Hetzner, OVH, IBM, Akamai edge, ...). Also used as a cross-check for the
   file-based providers.

Everything non-stdlib (`requests`) is imported defensively; with no network
the module's lookup() returns None and callers simply omit the cloud tags.
"""
import os
import csv
import io
import re
import json
import time
import logging
import ipaddress
import tempfile
from collections import namedtuple

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import USER_AGENT

CloudInfo = namedtuple('CloudInfo', ['provider', 'kind', 'region', 'service', 'source'])

DEFAULT_TTL = 86400          # 24h
FETCH_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Curated ASN -> (provider, kind). kind in {'cloud', 'cdn', 'hosting'}.
# Covers providers with no prefix file, plus the file-based ones as a
# cross-check / fallback when a fetch fails.
# ---------------------------------------------------------------------------
CLOUD_ASNS = {
    # --- AWS ---
    16509: ('AWS', 'cloud'), 14618: ('AWS', 'cloud'), 8987: ('AWS', 'cloud'),
    38895: ('AWS', 'cloud'), 19047: ('AWS', 'cloud'), 7224: ('AWS', 'cloud'),
    # --- Google / GCP ---
    15169: ('Google', 'cloud'), 396982: ('GCP', 'cloud'), 19527: ('Google', 'cloud'),
    43515: ('Google', 'cloud'), 36384: ('Google', 'cloud'), 36492: ('Google', 'cloud'),
    41264: ('Google', 'cloud'), 139070: ('GCP', 'cloud'), 396981: ('GCP', 'cloud'),
    # --- Microsoft / Azure ---
    8075: ('Azure', 'cloud'), 8068: ('Azure', 'cloud'), 8069: ('Azure', 'cloud'),
    8070: ('Azure', 'cloud'), 8071: ('Azure', 'cloud'), 12076: ('Azure', 'cloud'),
    # --- Oracle OCI ---
    31898: ('Oracle OCI', 'cloud'), 7160: ('Oracle OCI', 'cloud'),
    # --- Cloudflare ---
    13335: ('Cloudflare', 'cdn'), 209242: ('Cloudflare', 'cdn'),
    132892: ('Cloudflare', 'cdn'), 395747: ('Cloudflare', 'cdn'),
    # --- Fastly ---
    54113: ('Fastly', 'cdn'),
    # --- Akamai (edge + Linode compute post-acquisition) ---
    20940: ('Akamai', 'cdn'), 16625: ('Akamai', 'cdn'), 12222: ('Akamai', 'cdn'),
    32787: ('Akamai', 'cdn'), 21342: ('Akamai', 'cdn'), 21399: ('Akamai', 'cdn'),
    23454: ('Akamai', 'cdn'), 35994: ('Akamai', 'cdn'), 34164: ('Akamai', 'cdn'),
    63949: ('Linode', 'hosting'), 48163: ('Linode', 'hosting'),
    # --- DigitalOcean ---
    14061: ('DigitalOcean', 'hosting'),
    # --- Vultr / Choopa ---
    20473: ('Vultr', 'hosting'), 64515: ('Vultr', 'hosting'),
    # --- Alibaba Cloud ---
    45102: ('Alibaba Cloud', 'cloud'), 37963: ('Alibaba Cloud', 'cloud'),
    45104: ('Alibaba Cloud', 'cloud'), 134963: ('Alibaba Cloud', 'cloud'),
    134964: ('Alibaba Cloud', 'cloud'), 59055: ('Alibaba Cloud', 'cloud'),
    # --- Tencent Cloud ---
    132203: ('Tencent Cloud', 'cloud'), 45090: ('Tencent Cloud', 'cloud'),
    133478: ('Tencent Cloud', 'cloud'),
    # --- Hetzner ---
    24940: ('Hetzner', 'hosting'), 213230: ('Hetzner', 'hosting'), 212317: ('Hetzner', 'hosting'),
    # --- OVH ---
    16276: ('OVH', 'hosting'), 35540: ('OVH', 'hosting'),
    # --- IBM Cloud / SoftLayer ---
    36351: ('IBM Cloud', 'cloud'), 30315: ('IBM Cloud', 'cloud'),
    # --- Scaleway / Online SAS ---
    12876: ('Scaleway', 'hosting'),
    # --- Leaseweb ---
    60781: ('Leaseweb', 'hosting'), 28753: ('Leaseweb', 'hosting'),
    16265: ('Leaseweb', 'hosting'), 30633: ('Leaseweb', 'hosting'), 395954: ('Leaseweb', 'hosting'),
    # --- Contabo / Rackspace / GitHub ---
    51167: ('Contabo', 'hosting'),
    19994: ('Rackspace', 'hosting'), 33070: ('Rackspace', 'hosting'), 12200: ('Rackspace', 'hosting'),
    36459: ('GitHub', 'hosting'), 36460: ('GitHub', 'hosting'),
}


# ---------------------------------------------------------------------------
# Disk cache for the raw provider payloads
# ---------------------------------------------------------------------------
def _cache_dir():
    override = os.environ.get('TWIGS_EASM_CACHE_DIR')
    base = override or os.path.join(os.path.expanduser('~'), '.twigs', 'cache', 'easm')
    path = os.path.join(base, 'cloud_ranges')
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except OSError:
        path = os.path.join(tempfile.gettempdir(), 'twigs_easm_cloud_ranges')
        os.makedirs(path, exist_ok=True)
        return path


def _cache_read(name, ttl):
    """Returns (text, is_fresh) or (None, False)."""
    p = os.path.join(_cache_dir(), name)
    try:
        age = time.time() - os.path.getmtime(p)
        with open(p, 'r', encoding='utf-8') as fh:
            return fh.read(), age <= ttl
    except (OSError, ValueError):
        return None, False


def _cache_write(name, text):
    try:
        with open(os.path.join(_cache_dir(), name), 'w', encoding='utf-8') as fh:
            fh.write(text)
    except OSError:
        pass


def _get(url, cache_name, ttl):
    """Cached HTTP GET. Returns response text, or a stale cached copy, or None."""
    text, fresh = _cache_read(cache_name, ttl)
    if text is not None and fresh:
        return text
    if not HAVE_REQUESTS:
        return text  # possibly stale, best effort
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={'User-Agent': USER_AGENT})
        if resp.status_code == 200 and resp.text:
            _cache_write(cache_name, resp.text)
            return resp.text
        logging.warning("[EASM] cloud_ranges: %s -> HTTP %s (using %s)", url, resp.status_code,
                        "stale cache" if text else "nothing")
    except Exception as e:
        logging.warning("[EASM] cloud_ranges: %s failed: %s (using %s)", url, e,
                        "stale cache" if text else "nothing")
    return text


# ---------------------------------------------------------------------------
# Per-provider parsers. Each yields (cidr_str, region, service).
# ---------------------------------------------------------------------------
def _p_aws(ttl):
    raw = _get('https://ip-ranges.amazonaws.com/ip-ranges.json', 'aws.json', ttl)
    if not raw:
        return
    doc = json.loads(raw)
    for key in ('prefixes', 'ipv6_prefixes'):
        for e in doc.get(key, []):
            cidr = e.get('ip_prefix') or e.get('ipv6_prefix')
            if cidr:
                yield cidr, e.get('region', ''), e.get('service', '')


def _p_gcp(ttl):
    cloud = _get('https://www.gstatic.com/ipranges/cloud.json', 'gcp_cloud.json', ttl)
    seen = set()
    if cloud:
        for e in json.loads(cloud).get('prefixes', []):
            cidr = e.get('ipv4Prefix') or e.get('ipv6Prefix')
            if cidr:
                seen.add(cidr)
                yield cidr, e.get('scope', ''), e.get('service', 'Google Cloud')
    goog = _get('https://www.gstatic.com/ipranges/goog.json', 'gcp_goog.json', ttl)
    if goog:
        for e in json.loads(goog).get('prefixes', []):
            cidr = e.get('ipv4Prefix') or e.get('ipv6Prefix')
            if cidr and cidr not in seen:
                yield cidr, '', 'google-services'


_AZURE_JSON_RE = re.compile(
    r'https://download\.microsoft\.com/download/[^"\']*ServiceTags_Public_[0-9]+\.json')


def _p_azure(ttl):
    page = _get('https://www.microsoft.com/en-us/download/details.aspx?id=56519',
                'azure_page.html', ttl)
    url = None
    if page:
        m = _AZURE_JSON_RE.search(page)
        if m:
            url = m.group(0)
    if not url:
        # fall back to whatever JSON we cached previously
        raw, _ = _cache_read('azure.json', ttl)
    else:
        raw = _get(url, 'azure.json', ttl)
    if not raw:
        return
    for v in json.loads(raw).get('values', []):
        props = v.get('properties', {})
        region = props.get('region', '')
        service = props.get('systemService', '') or v.get('name', '')
        for cidr in props.get('addressPrefixes', []):
            yield cidr, region, service


def _p_oci(ttl):
    raw = _get('https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
               'oci.json', ttl)
    if not raw:
        return
    for reg in json.loads(raw).get('regions', []):
        region = reg.get('region', '')
        for c in reg.get('cidrs', []):
            cidr = c.get('cidr')
            if cidr:
                yield cidr, region, ','.join(c.get('tags', []) or [])


def _p_cloudflare(ttl):
    for suffix, name in (('ips-v4', 'cloudflare_v4.txt'), ('ips-v6', 'cloudflare_v6.txt')):
        raw = _get('https://www.cloudflare.com/' + suffix, name, ttl)
        if not raw:
            continue
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                yield line, '', 'CDN'


def _p_fastly(ttl):
    raw = _get('https://api.fastly.com/public-ip-list', 'fastly.json', ttl)
    if not raw:
        return
    doc = json.loads(raw)
    for cidr in list(doc.get('addresses', [])) + list(doc.get('ipv6_addresses', [])):
        yield cidr, '', 'CDN'


def _p_geofeed_csv(url, cache_name, service):
    def _parser(ttl):
        raw = _get(url, cache_name, ttl)
        if not raw:
            return
        for row in csv.reader(io.StringIO(raw)):
            if not row or row[0].lstrip().startswith('#'):
                continue
            cidr = row[0].strip()
            region = row[2].strip() if len(row) > 2 else ''
            city = row[3].strip() if len(row) > 3 else ''
            yield cidr, (region + '/' + city).strip('/'), service
    return _parser


_O365_CLIENT_ID = 'b10c5ed1-bad1-445f-b386-b919946339a7'  # any GUID; MS uses it for feed versioning


def _p_o365(ttl):
    """Microsoft 365 (Exchange Online, SharePoint Online, Teams) - published
    separately from Azure ServiceTags, and the range most EASM targets touch
    via their MX / autodiscover records."""
    raw = _get('https://endpoints.office.com/endpoints/worldwide?clientrequestid=' + _O365_CLIENT_ID,
               'o365.json', ttl)
    if not raw:
        return
    for e in json.loads(raw):
        service = e.get('serviceAreaDisplayName') or e.get('serviceArea') or ''
        for cidr in e.get('ips', []) or []:
            if '/' in cidr:
                yield cidr, '', service


def _p_github(ttl):
    raw = _get('https://api.github.com/meta', 'github.json', ttl)
    if not raw:
        return
    doc = json.loads(raw)
    for key in ('hooks', 'web', 'api', 'git', 'pages', 'importer', 'actions',
                'dependabot', 'packages'):
        for cidr in doc.get(key, []) or []:
            if '/' in cidr:
                yield cidr, '', key


# (provider, kind, parser). Order = tie-break priority when spans are equal.
PROVIDERS = [
    ('AWS', 'cloud', _p_aws),
    ('Google', 'cloud', _p_gcp),
    ('Azure', 'cloud', _p_azure),
    ('Microsoft 365', 'cloud', _p_o365),
    ('Oracle OCI', 'cloud', _p_oci),
    ('GitHub', 'hosting', _p_github),
    ('DigitalOcean', 'hosting',
     _p_geofeed_csv('https://www.digitalocean.com/geo/google.csv', 'digitalocean.csv', 'Compute')),
    ('Linode', 'hosting',
     _p_geofeed_csv('https://geoip.linode.com/', 'linode.csv', 'Compute')),
    ('Vultr', 'hosting',
     _p_geofeed_csv('https://geofeed.constant.com/', 'vultr.csv', 'Compute')),
    ('Fastly', 'cdn', _p_fastly),
    ('Cloudflare', 'cdn', _p_cloudflare),
]


# ---------------------------------------------------------------------------
# Longest-prefix lookup index
# ---------------------------------------------------------------------------
class _Index:
    __slots__ = ('v4', 'v6', 'max_span4', 'max_span6')

    def __init__(self):
        self.v4 = []   # list of (start_int, end_int, CloudInfo)
        self.v6 = []
        self.max_span4 = 0
        self.max_span6 = 0

    def add(self, cidr, info):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        # Some published geofeeds carry junk/placeholder rows (RFC 5737
        # TEST-NET, RFC 1918, CGNAT, ...). Only index globally-routable space.
        if not net.is_global:
            return
        start, end = int(net.network_address), int(net.broadcast_address)
        span = end - start
        if net.version == 4:
            self.v4.append((start, end, info))
            self.max_span4 = max(self.max_span4, span)
        else:
            self.v6.append((start, end, info))
            self.max_span6 = max(self.max_span6, span)

    def finalize(self):
        self.v4.sort(key=lambda e: e[0])
        self.v6.sort(key=lambda e: e[0])

    def lookup(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        entries, max_span = (self.v4, self.max_span4) if ip.version == 4 else (self.v6, self.max_span6)
        if not entries:
            return None
        target = int(ip)
        import bisect
        i = bisect.bisect_right(entries, (target, float('inf'))) - 1
        best = None
        best_span = None
        while i >= 0 and entries[i][0] >= target - max_span:
            start, end, info = entries[i]
            if start <= target <= end:
                span = end - start
                if best is None or span < best_span:
                    best, best_span = info, span
            i -= 1
        return best


_INDEX = None
_INDEX_ERROR = False


def _build_index(ttl):
    idx = _Index()
    for provider, kind, parser in PROVIDERS:
        count = 0
        try:
            for cidr, region, service in parser(ttl):
                idx.add(cidr, CloudInfo(provider, kind, region or '', service or '', 'range-file'))
                count += 1
        except Exception as e:
            logging.warning("[EASM] cloud_ranges: parsing %s failed: %s", provider, e)
        if count:
            logging.info("[EASM] cloud_ranges: %s -> %d prefixes", provider, count)
    idx.finalize()
    return idx


def _ensure_index(ttl):
    global _INDEX, _INDEX_ERROR
    if _INDEX is None and not _INDEX_ERROR:
        try:
            _INDEX = _build_index(ttl)
        except Exception as e:
            logging.warning("[EASM] cloud_ranges: index build failed: %s", e)
            _INDEX_ERROR = True
    return _INDEX


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def provider_for_asn(asn):
    """(provider, kind) for an AS number (int or 'ASxxxx'/str), or None."""
    if asn is None:
        return None
    try:
        n = int(str(asn).upper().lstrip('AS').strip())
    except (ValueError, AttributeError):
        return None
    return CLOUD_ASNS.get(n)


def lookup(ip, asn=None, ttl=DEFAULT_TTL):
    """Attribute an IP to a cloud/CDN/hosting provider.

    Returns a CloudInfo(provider, kind, region, service, source) or None if the
    IP looks like it is not on a known provider (candidate owned netblock).
    A prefix-file match wins; otherwise the ASN map is consulted.
    """
    idx = _ensure_index(ttl)
    if idx is not None:
        hit = idx.lookup(ip)
        if hit is not None:
            return hit
    by_asn = provider_for_asn(asn)
    if by_asn:
        return CloudInfo(by_asn[0], by_asn[1], '', '', 'asn-map')
    return None


def is_cloud_or_cdn(ip=None, asn=None, ttl=DEFAULT_TTL):
    """True if the IP/ASN belongs to a known cloud/CDN/hosting provider - i.e.
    NOT a netblock the target is likely to own directly. Used to gate ASN
    expansion in recursive discovery."""
    info = lookup(ip, asn=asn, ttl=ttl) if ip else None
    if info is None and asn is not None:
        info = None
        by_asn = provider_for_asn(asn)
        if by_asn:
            info = CloudInfo(by_asn[0], by_asn[1], '', '', 'asn-map')
    return info is not None


def as_tags(info):
    """CloudInfo -> list of asset tag strings. CLOUD:unattributed means the
    IP matched none of the known provider prefix files or ASNs - i.e. it was
    checked, not that it is definitely not cloud-hosted (coverage is
    incomplete); in practice it is a useful "likely target-owned / scan
    harder" signal."""
    if info is None:
        return ['CLOUD:unattributed']
    tags = ['CLOUD:' + info.provider]
    if info.region:
        tags.append('CLOUD_REGION:' + info.region)
    if info.service:
        tags.append('CLOUD_SERVICE:' + info.service)
    return tags
