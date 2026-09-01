"""Subdomain enumeration.

Passive discovery queries many free public sources in parallel and unions
whatever each returns:

  - crt.sh, SSLMate certspotter          (certificate transparency)
  - AnubisDB, Subdomain Center           (aggregated subdomain datasets)
  - HackerTarget                         (hostsearch)
  - AlienVault OTX                       (passive DNS - needs a free key)
  - urlscan.io                          (hostnames seen in real page loads)
  - RapidDNS                            (aggregated DNS dataset)
  - Internet Archive Wayback / CommonCrawl (historical crawl URL indexes)

Every one is individually flaky or quota-limited (crt.sh 502s, certspotter /
hackertarget / OTX return 429, AnubisDB is often empty, web.archive.org can be
unreachable), so no single source is trusted: a source that fails or returns
nothing is logged and skipped, and the others still stand. OTX, urlscan and
certspotter each take an optional API key (``--otx_api_key`` / ``OTX_API_KEY``,
``--urlscan_api_key`` / ``URLSCAN_API_KEY``, ``--certspotter_api_key`` /
``CERTSPOTTER_API_KEY``) for higher / any access.

Active discovery then adds a DNS brute force over a wordlist - the built-in
curated ~130-label list by default, or a bundled ~5k / ~20k SecLists-derived
list (``--wordlist_tier medium|large``), or a caller-supplied file
(``--wordlist_file``). On a wildcard-DNS domain the brute force still runs,
with its results filtered against a wildcard fingerprint (labels resolving
only to the wildcard address(es) are discarded) instead of being skipped.
"""
import os
import re
import time
import json
import random
import string
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from . import _cache
from .constants import USER_AGENT
from .util import HAVE_DNSPYTHON, _get_dns_resolver, _resolve_record


def _rr(res, name, rtype):
    """Resolve via either a ResolverPool (has .resolve_record) or a plain
    dnspython resolver."""
    if hasattr(res, 'resolve_record'):
        return res.resolve_record(name, rtype)
    return _resolve_record(res, name, rtype)

# A small, curated list of common subdomain labels used for DNS brute force
# enumeration when certificate-transparency lookups are unavailable/incomplete.
COMMON_SUBDOMAINS = [
    'www', 'mail', 'webmail', 'remote', 'vpn', 'api', 'dev', 'staging', 'test',
    'uat', 'qa', 'demo', 'app', 'apps', 'portal', 'admin', 'administrator',
    'secure', 'login', 'sso', 'auth', 'id', 'my', 'account', 'accounts',
    'blog', 'shop', 'store', 'support', 'help', 'helpdesk', 'status', 'docs',
    'wiki', 'ftp', 'sftp', 'ssh', 'git', 'gitlab', 'github', 'jenkins', 'ci',
    'cd', 'jira', 'confluence', 'monitor', 'monitoring', 'grafana', 'kibana',
    'elastic', 'metrics', 'stats', 'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop',
    'imap', 'autodiscover', 'cpanel', 'whm', 'webdisk', 'cdn', 'static',
    'assets', 'images', 'img', 'media', 'files', 'download', 'downloads',
    'upload', 'uploads', 'db', 'database', 'mysql', 'postgres', 'redis',
    'mongo', 'es', 'search', 'internal', 'intranet', 'extranet', 'partner',
    'partners', 'client', 'clients', 'customer', 'customers', 'billing',
    'pay', 'payment', 'payments', 'checkout', 'cart', 'crm', 'erp', 'hr',
    'jobs', 'careers', 'news', 'events', 'forum', 'forums', 'community',
    'm', 'mobile', 'beta', 'alpha', 'old', 'new', 'legacy', 'origin',
    'edge', 'proxy', 'gateway', 'gw', 'lb', 'k8s', 'kube', 'docker',
    'registry', 'nexus', 'artifactory', 'vault', 'consul', 'ldap', 'ad',
]

# Per-source HTTP timeout (seconds). These endpoints are occasionally slow;
# kept generous since all four run concurrently anyway.
SOURCE_HTTP_TIMEOUT = 25

# Upper bound on names kept from passive sources combined - a large domain's
# CT history can be many thousands of names, almost all long dead, and the
# caller resolves each one. Truncated (with a warning) past this.
MAX_PASSIVE_SUBDOMAINS = 5000

# certspotter returns issuances in pages of up to 100 (ascending id); this
# bounds how many pages we'll walk for one domain.
CERTSPOTTER_MAX_PAGES = 15

# Row caps for the historical crawl-index sources (their result sets can be
# huge; MAX_PASSIVE_SUBDOMAINS truncates the union afterwards anyway).
WAYBACK_LIMIT = 20000
COMMONCRAWL_LIMIT = 20000

# DNS brute-force wordlists. 'small' is the curated COMMON_SUBDOMAINS list
# above (fast, seconds); 'medium'/'large' are bundled SecLists-derived label
# lists under easm/data/ (~5k / ~20k, minutes). Selected via --wordlist_tier;
# --wordlist_file overrides with an arbitrary caller-supplied file.
_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
_WORDLIST_FILES = {'medium': 'subdomains-medium.txt', 'large': 'subdomains-large.txt'}
_WORDLIST_CACHE = {}

# Number of random non-existent labels resolved to fingerprint wildcard DNS.
WILDCARD_PROBES = 8


def _valid_hostname(name):
    return bool(re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,251})[a-z0-9]$', name))


def _clean_names(raw_names, domain):
    """Normalise a source's raw name list to in-scope, syntactically valid
    hostnames: lowercased, wildcard prefix stripped, must be the domain
    itself or a subdomain of it."""
    out = set()
    suffix = '.' + domain
    for name in raw_names:
        if not name:
            continue
        name = name.strip().lower().lstrip('*.').rstrip('.')
        if not name:
            continue
        if (name == domain or name.endswith(suffix)) and _valid_hostname(name):
            out.add(name)
    return out


def _hosts_from_urls(urls):
    """Extract hostnames from a list of (possibly scheme-less) URL strings."""
    out = []
    for u in urls:
        if not u:
            continue
        try:
            host = urlparse(u if '://' in u else 'http://' + u).hostname
        except ValueError:
            host = None
        if host:
            out.append(host)
    return out


def _source_crtsh(domain, retries=3, backoff=2):
    """crt.sh - free, unauthenticated, and frequently flaky (404/502/timeout
    are common transient failures, not "no results"), so retry with a short
    backoff before giving up."""
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
            if resp.status_code != 200:
                last_error = "HTTP %s" % resp.status_code
            else:
                names = []
                for entry in resp.json():
                    names.extend((entry.get('name_value') or '').split('\n'))
                    cn = entry.get('common_name')
                    if cn:
                        names.append(cn)
                return _clean_names(names, domain)
        except Exception as e:
            last_error = str(e)
        if attempt < retries:
            time.sleep(backoff * attempt)
    raise RuntimeError("crt.sh unavailable after %d attempt(s): %s" % (retries, last_error))


def _source_certspotter(domain, api_key=None):
    """SSLMate certspotter CT Search API. Unauthenticated access is capped at
    a low number of queries/day per source IP (HTTP 429 with a JSON body of
    {"code": "rate_limited"}); an API key raises that substantially. Results
    are paged (<=100 issuances/call, ascending id) via the `after` param."""
    base = "https://api.certspotter.com/v1/issuances"
    headers = {'User-Agent': USER_AGENT}
    if api_key:
        headers['Authorization'] = 'Bearer ' + api_key
    names = []
    after = None
    for _ in range(CERTSPOTTER_MAX_PAGES):
        params = {'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'}
        if after is not None:
            params['after'] = after
        resp = requests.get(base, params=params, headers=headers, timeout=SOURCE_HTTP_TIMEOUT)
        if resp.status_code == 429:
            raise RuntimeError("certspotter rate-limited (HTTP 429) - set CERTSPOTTER_API_KEY for a higher limit")
        if resp.status_code != 200:
            raise RuntimeError("certspotter HTTP %s" % resp.status_code)
        batch = resp.json()
        if isinstance(batch, dict):  # error object, e.g. {"code": "rate_limited"}
            raise RuntimeError("certspotter error: %s" % batch.get('message', batch.get('code', 'unknown')))
        if not batch:
            break
        for issuance in batch:
            names.extend(issuance.get('dns_names') or [])
            after = issuance.get('id', after)
        if len(batch) < 100:
            break
    return _clean_names(names, domain)


def _source_anubis(domain):
    """AnubisDB (anubisdb.com) - a static aggregated subdomain dataset.
    Returns a plain JSON array of hostnames; coverage is uneven (often an
    empty array), but it is fast and occasionally unique."""
    url = "https://anubisdb.com/anubis/subdomains/" + domain
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if resp.status_code != 200:
        raise RuntimeError("anubisdb HTTP %s" % resp.status_code)
    data = resp.json()
    if not isinstance(data, list):
        raise RuntimeError("anubisdb: unexpected response shape")
    return _clean_names(data, domain)


def _source_hackertarget(domain):
    """HackerTarget hostsearch - returns CSV `hostname,ip` lines. Free tier
    is a small number of queries/day per IP; once exhausted the body is a
    plain-text error ('API count exceeded ...') rather than an HTTP error."""
    url = "https://api.hackertarget.com/hostsearch/?q=" + domain
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    body = (resp.text or '').strip()
    if resp.status_code != 200:
        raise RuntimeError("hackertarget HTTP %s" % resp.status_code)
    low = body.lower()
    if 'api count exceeded' in low or low.startswith('error') or 'no records found' in low:
        if 'no records found' in low:
            return set()
        raise RuntimeError("hackertarget: %s" % body[:120])
    names = [line.split(',', 1)[0] for line in body.splitlines() if line]
    return _clean_names(names, domain)


def _source_otx(domain, api_key=None):
    """AlienVault OTX passive DNS. Anonymous access is blocked (HTTP 429 /
    "Please authenticate"); a free key (OTX_API_KEY / --otx_api_key) is
    generously rate-limited and returns names ever *resolved* by OTX's sensor
    network - incl. HTTP-only / no-cert hosts and long-dead names."""
    headers = {'User-Agent': USER_AGENT}
    if api_key:
        headers['X-OTX-API-KEY'] = api_key
    url = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % domain
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers=headers)
    if resp.status_code in (401, 403, 429):
        raise RuntimeError("OTX needs a free API key (set OTX_API_KEY)")
    if resp.status_code != 200:
        raise RuntimeError("OTX HTTP %s" % resp.status_code)
    names = [rec.get('hostname') for rec in (resp.json().get('passive_dns') or [])]
    return _clean_names(names, domain)


def _source_urlscan(domain, api_key=None):
    """urlscan.io search - hostnames observed in real page loads / user-
    submitted scans worldwide, including API/XHR subdomains referenced from
    page JavaScript. Works anonymously (lower quota); API-Key header raises
    it."""
    headers = {'User-Agent': USER_AGENT}
    if api_key:
        headers['API-Key'] = api_key
    url = "https://urlscan.io/api/v1/search/?q=domain:%s&size=10000" % domain
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers=headers)
    if resp.status_code == 429:
        raise RuntimeError("urlscan.io rate-limited (HTTP 429) - set URLSCAN_API_KEY")
    if resp.status_code != 200:
        raise RuntimeError("urlscan.io HTTP %s" % resp.status_code)
    names = []
    for r in (resp.json().get('results') or []):
        page = r.get('page') or {}
        task = r.get('task') or {}
        names.append(page.get('domain'))
        names.append(task.get('domain'))
        names.extend(_hosts_from_urls([page.get('url'), task.get('url')]))
    return _clean_names([n for n in names if n], domain)


def _source_rapiddns(domain):
    """RapidDNS.io - aggregated DNS dataset, HTML response, no key. Parsed by
    scraping every in-domain hostname out of the response body."""
    url = "https://rapiddns.io/subdomain/%s?full=1" % domain
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if resp.status_code != 200:
        raise RuntimeError("rapiddns HTTP %s" % resp.status_code)
    names = re.findall(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.%s' % re.escape(domain), resp.text)
    return _clean_names(names, domain)


def _source_subdomaincenter(domain):
    """api.subdomain.center - itself aggregates ~8 upstream sources. Returns a
    plain JSON array of hostnames. No key."""
    url = "https://api.subdomain.center/?domain=%s" % domain
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if resp.status_code != 200:
        raise RuntimeError("subdomain.center HTTP %s" % resp.status_code)
    data = resp.json()
    if not isinstance(data, list):
        raise RuntimeError("subdomain.center: unexpected response shape")
    return _clean_names(data, domain)


def _source_wayback(domain):
    """Internet Archive CDX - every archived URL under *.domain. Historical,
    so it surfaces retired / staging / beta hosts that still resolve. No key.
    (web.archive.org is occasionally unreachable - treated like any other
    source failure.)"""
    url = ("https://web.archive.org/cdx/search/cdx?url=*.%s&output=text&fl=original"
           "&collapse=urlkey&limit=%d" % (domain, WAYBACK_LIMIT))
    resp = requests.get(url, timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if resp.status_code != 200:
        raise RuntimeError("wayback CDX HTTP %s" % resp.status_code)
    return _clean_names(_hosts_from_urls(resp.text.splitlines()), domain)


def _source_commoncrawl(domain):
    """CommonCrawl URL index (latest crawl) - a web-scale crawl frontier
    distinct from Wayback's. No key. Two requests: the crawl list (disk-cached
    ~7d) then the CDX query against the newest crawl."""
    collinfo = _cache.cached_get("https://index.commoncrawl.org/collinfo.json",
                                 "cc_collinfo.json", 7 * 86400, sub="subdomains")
    if not collinfo:
        raise RuntimeError("commoncrawl: crawl list unavailable")
    crawls = json.loads(collinfo)
    cdx_api = crawls[0].get('cdx-api') if crawls else None
    if not cdx_api:
        raise RuntimeError("commoncrawl: no cdx-api in crawl list")
    resp = requests.get("%s?url=*.%s&output=json&limit=%d" % (cdx_api, domain, COMMONCRAWL_LIMIT),
                        timeout=SOURCE_HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if resp.status_code == 404:
        return set()   # nothing indexed for this domain in the latest crawl
    if resp.status_code != 200:
        raise RuntimeError("commoncrawl CDX HTTP %s" % resp.status_code)
    urls = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            urls.append(json.loads(line).get('url'))
        except json.JSONDecodeError:
            continue
    return _clean_names(_hosts_from_urls(urls), domain)


# (display name, callable). Sources in _KEYED_SOURCES are called with a second
# positional arg carrying their API key (or None).
_PASSIVE_SOURCES = [
    ('crt.sh', _source_crtsh),
    ('certspotter', _source_certspotter),
    ('anubisdb', _source_anubis),
    ('hackertarget', _source_hackertarget),
    ('otx', _source_otx),
    ('urlscan', _source_urlscan),
    ('rapiddns', _source_rapiddns),
    ('subdomaincenter', _source_subdomaincenter),
    ('wayback', _source_wayback),
    ('commoncrawl', _source_commoncrawl),
]

# source name -> (args attribute, env var) for the ones that take an API key
_KEYED_SOURCES = {
    'certspotter': ('certspotter_api_key', 'CERTSPOTTER_API_KEY'),
    'otx': ('otx_api_key', 'OTX_API_KEY'),
    'urlscan': ('urlscan_api_key', 'URLSCAN_API_KEY'),
}


def _source_api_key(name, args):
    attr, env = _KEYED_SOURCES[name]
    val = getattr(args, attr, None) if args is not None else None
    return val or os.environ.get(env)


def get_certspotter_api_key(args):
    return _source_api_key('certspotter', args)


def enumerate_subdomains_passive(domain, args=None):
    """Query every passive source concurrently and union the results. A
    source raising (unavailable / rate-limited / bad shape) is logged and
    dropped; the rest still contribute."""
    results = set()
    with ThreadPoolExecutor(max_workers=len(_PASSIVE_SOURCES)) as pool:
        future_to_name = {}
        for name, fn in _PASSIVE_SOURCES:
            if name in _KEYED_SOURCES:
                fut = pool.submit(fn, domain, _source_api_key(name, args))
            else:
                fut = pool.submit(fn, domain)
            future_to_name[fut] = name
        for fut in as_completed(future_to_name):
            name = future_to_name[fut]
            try:
                found = fut.result() or set()
            except Exception as e:
                logging.warning("[EASM] subdomain source [%s] unavailable: %s", name, e)
                continue
            if found:
                logging.info("[EASM] subdomain source [%s]: %d name(s)", name, len(found))
            else:
                logging.info("[EASM] subdomain source [%s]: no results", name)
            results |= found
    return results


# Backwards-compatible alias (older name / external callers).
def enumerate_subdomains_crtsh(domain, retries=3, backoff=2):
    try:
        return _source_crtsh(domain, retries=retries, backoff=backoff)
    except Exception as e:
        logging.debug("crt.sh subdomain enumeration failed: %s", e)
        return set()


def _dedupe_labels(lines):
    seen, out = set(), []
    for ln in lines:
        ln = ln.strip().lower()
        if not ln or ln.startswith('#') or ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
    return out


def load_wordlist(tier='small', custom_path=None):
    """Resolve a brute-force label list. custom_path wins; then tier
    ('small' -> curated COMMON_SUBDOMAINS, 'medium'/'large' -> bundled file,
    with the curated set always merged in). Falls back to 'small' on any
    read error."""
    if custom_path:
        try:
            with open(custom_path) as fh:
                labels = _dedupe_labels(fh)
            logging.info("[EASM] subdomain wordlist: %d label(s) from %s", len(labels), custom_path)
            return labels or list(COMMON_SUBDOMAINS)
        except OSError as e:
            logging.warning("[EASM] cannot read --wordlist_file [%s]: %s - using built-in 'small'", custom_path, e)

    tier = (tier or 'small').lower()
    if tier not in _WORDLIST_FILES:
        return list(COMMON_SUBDOMAINS)
    if tier in _WORDLIST_CACHE:
        return _WORDLIST_CACHE[tier]

    path = os.path.join(_DATA_DIR, _WORDLIST_FILES[tier])
    try:
        with open(path) as fh:
            labels = _dedupe_labels(fh)
    except OSError as e:
        logging.warning("[EASM] bundled wordlist [%s] unavailable: %s - using 'small'", path, e)
        return list(COMMON_SUBDOMAINS)

    have = set(labels)
    labels = labels + [l for l in COMMON_SUBDOMAINS if l not in have]
    _WORDLIST_CACHE[tier] = labels
    logging.info("[EASM] subdomain wordlist tier '%s': %d label(s)", tier, len(labels))
    return labels


def wildcard_fingerprint(domain, probes=WILDCARD_PROBES, resolver=None):
    """Fingerprint wildcard DNS. Returns (is_wildcard, wildcard_ips,
    wildcard_cname_targets): resolve `probes` random near-certainly-
    nonexistent labels and, if a majority answer, collect the union of
    addresses / CNAME targets they return so brute-force hits that resolve
    *only* to that set can be subtracted out later."""
    if not HAVE_DNSPYTHON:
        return False, set(), set()
    resolver = resolver or _get_dns_resolver()
    ips, cnames, hits = set(), set(), 0
    for _ in range(probes):
        fqdn = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20)) + '.' + domain
        a = _rr(resolver, fqdn, 'A')
        c = _rr(resolver, fqdn, 'CNAME')
        if not a and not c:
            continue
        hits += 1
        for rr in (a or []):
            ips.add(getattr(rr, 'address', None) or str(rr))
        for rr in (c or []):
            cnames.add(str(getattr(rr, 'target', rr)).rstrip('.').lower())
    return (hits >= max(2, probes // 2)), ips, cnames


def detect_wildcard_dns(domain):
    """Back-compat boolean wrapper around wildcard_fingerprint()."""
    return wildcard_fingerprint(domain)[0]


def enumerate_subdomains_bruteforce(domain, workers=20, labels=None,
                                    wildcard_ips=None, wildcard_cnames=None,
                                    resolver=None):
    """Resolve `labels` (default: COMMON_SUBDOMAINS) under `domain`. When
    wildcard_ips / wildcard_cnames are supplied, a candidate that resolves
    *only* to that wildcard set is treated as noise and dropped; one with a
    distinct address or CNAME target is kept. `resolver` may be a
    ResolverPool for spread-load high concurrency."""
    subdomains = set()
    if not HAVE_DNSPYTHON:
        return subdomains
    resolver = resolver or _get_dns_resolver()
    labels = COMMON_SUBDOMAINS if labels is None else labels
    wildcard_ips = wildcard_ips or set()
    wildcard_cnames = wildcard_cnames or set()
    filtering = bool(wildcard_ips or wildcard_cnames)

    def _try(label):
        candidate = label + '.' + domain
        a = _rr(resolver, candidate, 'A')
        c = _rr(resolver, candidate, 'CNAME')
        if not a and not c:
            return None
        if not filtering:
            return candidate
        cand_ips = {getattr(rr, 'address', None) or str(rr) for rr in (a or [])}
        cand_cn = {str(getattr(rr, 'target', rr)).rstrip('.').lower() for rr in (c or [])}
        if cand_cn and not cand_cn <= wildcard_cnames:
            return candidate
        if cand_ips and not cand_ips <= wildcard_ips:
            return candidate
        return None  # resolves only to the wildcard - noise

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_try, label): label for label in labels}
        for future in as_completed(futures):
            found = future.result()
            if found:
                subdomains.add(found)
    return subdomains


# Stage/environment tokens for permutation scanning: a known 'api-dev' will
# spawn 'api-staging', 'api-uat', ...; a lone 'dev' spawns 'staging', 'uat', ...
PERMUTATION_ENV_TOKENS = [
    'dev', 'development', 'staging', 'stage', 'stg', 'test', 'testing', 'qa',
    'uat', 'prod', 'production', 'preprod', 'pre', 'demo', 'sandbox', 'sbx',
    'internal', 'int', 'admin', 'api', 'app', 'new', 'old', 'beta', 'alpha',
    'live', 'legacy', 'backup', 'bak', 'mgmt', 'ops', 'corp',
]
_PERMUTATION_ENV_SET = set(PERMUTATION_ENV_TOKENS)
# Affixes appended/prepended to a known label ('portal' -> 'portal-dev',
# 'dev-portal', 'portal2', ...).
PERMUTATION_AFFIXES = [
    'dev', 'staging', 'stg', 'test', 'qa', 'uat', 'prod', 'preprod', 'internal',
    'int', 'new', 'old', 'beta', 'admin', 'api', 'app', 'v2', 'v3', '2', '02',
]
MAX_PERMUTATION_CANDIDATES = 3000


def _permute_label(label):
    """Mutation candidates for one known subdomain label (which may itself be
    multi-part, e.g. 'api.eu' relative to the apex)."""
    out = set()
    parts = label.split('.', 1)
    head, rest = parts[0], (parts[1] if len(parts) > 1 else '')
    join = lambda h: (h + '.' + rest) if rest else h

    for aff in PERMUTATION_AFFIXES:
        out.add(join('%s-%s' % (head, aff)))
        out.add(join('%s-%s' % (aff, head)))

    m = re.match(r'^(.+?)(\d+)$', head)
    if m:
        base, num = m.group(1), int(m.group(2))
        width = len(m.group(2))
        for nn in (num + 1, num + 2, num - 1):
            if nn >= 0:
                out.add(join('%s%0*d' % (base, width, nn)))
    else:
        for suf in ('2', '3', '01', '02'):
            out.add(join(head + suf))

    toks = head.split('-')
    for i, t in enumerate(toks):
        if t in _PERMUTATION_ENV_SET:
            for repl in PERMUTATION_ENV_TOKENS:
                if repl != t:
                    out.add(join('-'.join(toks[:i] + [repl] + toks[i + 1:])))

    out.discard(join(head))
    out.discard(label)
    return {c for c in out if c and _valid_hostname(c + '.example.com')}


def enumerate_subdomains_permutations(domain, known_subs, workers=20,
                                      wildcard_ips=None, wildcard_cnames=None,
                                      limit=MAX_PERMUTATION_CANDIDATES, resolver=None):
    """Mutate the already-known subdomain set (affixes, number bumps,
    env-token swaps) and resolve the candidates - finds sibling environments
    like 'api-staging' off a known 'api'. Reuses the wildcard filter."""
    if not HAVE_DNSPYTHON or not known_subs:
        return set()
    suffix = '.' + domain
    known_labels = {s[:-len(suffix)] for s in known_subs if s.endswith(suffix)}
    if not known_labels:
        return set()
    cands = set()
    for lbl in known_labels:
        cands |= _permute_label(lbl)
    cands -= known_labels
    cands = sorted(cands)[:limit]
    if not cands:
        return set()
    logging.info("[EASM] subdomain permutation scan: %d candidate(s) from %d known label(s)",
                 len(cands), len(known_labels))
    return enumerate_subdomains_bruteforce(domain, workers, cands, wildcard_ips, wildcard_cnames, resolver)


def enumerate_subdomains(domain, args):
    """Returns (subdomains, wildcard_detected, wordlist_size). Passive/CT
    results are always taken; DNS brute force runs over the selected wordlist
    (--wordlist_tier / --wordlist_file), followed by a permutation round off
    the discovered set (unless --no_subdomain_permutations). On a wildcard
    domain the brute force still runs but its results are filtered against a
    wildcard fingerprint (candidates resolving only to the wildcard
    address(es) are discarded) rather than skipping brute force altogether."""
    subdomains = enumerate_subdomains_passive(domain, args)

    labels = load_wordlist(getattr(args, 'wordlist_tier', 'small'),
                           getattr(args, 'wordlist_file', None))
    workers = getattr(args, 'dns_workers', 20) or 20

    resolver = None
    if not getattr(args, 'no_resolver_pool', False):
        try:
            from . import resolver_pool
            resolver = resolver_pool.get_pool(getattr(args, 'resolver_pool', None))
        except Exception as e:
            logging.debug("resolver pool unavailable: %s", e)
        if resolver and len(resolver) >= 3:
            workers = max(workers, 40)
        else:
            resolver = None

    wildcard, wc_ips, wc_cnames = wildcard_fingerprint(domain, resolver=resolver)
    wc_i = wc_ips if wildcard else None
    wc_c = wc_cnames if wildcard else None
    if wildcard:
        logging.info("[EASM] wildcard DNS for [%s] (wildcard target(s): %s) - brute-forcing %d label(s) with wildcard-response filtering",
                     domain, ', '.join(sorted(wc_ips | wc_cnames)) or 'n/a', len(labels))
    subdomains |= enumerate_subdomains_bruteforce(domain, workers, labels, wc_i, wc_c, resolver)

    if not getattr(args, 'no_subdomain_permutations', False):
        perm_hits = enumerate_subdomains_permutations(
            domain, subdomains, workers, wc_i, wc_c,
            limit=getattr(args, 'permutation_limit', MAX_PERMUTATION_CANDIDATES) or MAX_PERMUTATION_CANDIDATES,
            resolver=resolver)
        new_perm = perm_hits - subdomains
        if new_perm:
            logging.info("[EASM] subdomain permutation scan: %d new name(s)", len(new_perm))
        subdomains |= perm_hits

    subdomains.discard(domain)

    if len(subdomains) > MAX_PASSIVE_SUBDOMAINS:
        logging.warning("[EASM] subdomain enumeration for [%s] yielded %d names - truncating to %d",
                        domain, len(subdomains), MAX_PASSIVE_SUBDOMAINS)
        subdomains = set(sorted(subdomains)[:MAX_PASSIVE_SUBDOMAINS])

    logging.info("[EASM] subdomain enumeration for [%s]: %d unique name(s) across all sources",
                 domain, len(subdomains))
    return subdomains, wildcard, len(labels)
