"""Subdomain enumeration.

Passive discovery queries several free, unauthenticated public sources in
parallel - crt.sh, the SSLMate certspotter CT Search API, AnubisDB, and
HackerTarget - and unions whatever each returns. Every one of these is
individually flaky (crt.sh regularly 502s/404s, certspotter and hackertarget
have low per-day unauthenticated quotas and return 429, AnubisDB has sparse
coverage), so no single source is trusted: a source failing or returning
nothing is logged and skipped, and results from the others still stand.
certspotter accepts an API key (``--certspotter_api_key`` /
``CERTSPOTTER_API_KEY``) for a much higher rate limit.

Active discovery then adds a DNS brute force over a curated wordlist, unless
wildcard DNS is detected (which would make every guessed label appear to
resolve).
"""
import os
import re
import time
import json
import random
import string
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .constants import USER_AGENT
from .util import HAVE_DNSPYTHON, _get_dns_resolver, _resolve_record

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


# (display name, callable). certspotter is special-cased for the api_key arg.
_PASSIVE_SOURCES = [
    ('crt.sh', _source_crtsh),
    ('certspotter', _source_certspotter),
    ('anubisdb', _source_anubis),
    ('hackertarget', _source_hackertarget),
]


def get_certspotter_api_key(args):
    return (getattr(args, 'certspotter_api_key', None)
            or os.environ.get('CERTSPOTTER_API_KEY'))


def enumerate_subdomains_passive(domain, args=None):
    """Query every passive source concurrently and union the results. A
    source raising (unavailable / rate-limited / bad shape) is logged and
    dropped; the rest still contribute."""
    api_key = get_certspotter_api_key(args) if args is not None else os.environ.get('CERTSPOTTER_API_KEY')
    results = set()
    with ThreadPoolExecutor(max_workers=len(_PASSIVE_SOURCES)) as pool:
        future_to_name = {}
        for name, fn in _PASSIVE_SOURCES:
            if fn is _source_certspotter:
                fut = pool.submit(fn, domain, api_key)
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


def detect_wildcard_dns(domain):
    """A wildcard DNS record (e.g. '*.example.com A 1.2.3.4') makes every
    guessed brute-force label appear to "exist", which would otherwise flood
    the results with false positives. Detected by resolving two different
    random, near-certainly-nonexistent labels and checking whether both
    resolve to an overlapping IP set - a coincidental single match is
    possible, but two random 20-character labels both matching is not."""
    if not HAVE_DNSPYTHON:
        return False
    resolver = _get_dns_resolver()
    seen_ips = None
    for _ in range(2):
        label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        answers = _resolve_record(resolver, label + '.' + domain, 'A')
        if not answers:
            return False
        current = {getattr(rr, 'address', None) or str(rr) for rr in answers}
        if seen_ips is None:
            seen_ips = current
        elif not (seen_ips & current):
            return False
    return True


def enumerate_subdomains_bruteforce(domain, workers=20):
    subdomains = set()
    if not HAVE_DNSPYTHON:
        return subdomains
    resolver = _get_dns_resolver()

    def _try(label):
        candidate = label + '.' + domain
        for rtype in ('A', 'CNAME'):
            if _resolve_record(resolver, candidate, rtype) is not None:
                return candidate
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_try, label): label for label in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            found = future.result()
            if found:
                subdomains.add(found)
    return subdomains


def enumerate_subdomains(domain, args):
    """Returns (subdomains, wildcard_detected). DNS brute force is skipped
    entirely when wildcard DNS is detected - see detect_wildcard_dns - since
    its results would be unusable noise; passive/CT results are unaffected
    (they reflect subdomains a real certificate was actually issued for,
    independent of wildcard DNS)."""
    subdomains = enumerate_subdomains_passive(domain, args)

    wildcard = detect_wildcard_dns(domain)
    if wildcard:
        logging.info("[EASM] wildcard DNS detected for [%s] - skipping DNS brute-force enumeration", domain)
    else:
        subdomains |= enumerate_subdomains_bruteforce(domain, workers=getattr(args, 'dns_workers', 20))

    subdomains.discard(domain)

    if len(subdomains) > MAX_PASSIVE_SUBDOMAINS:
        logging.warning("[EASM] subdomain enumeration for [%s] yielded %d names - truncating to %d",
                        domain, len(subdomains), MAX_PASSIVE_SUBDOMAINS)
        subdomains = set(sorted(subdomains)[:MAX_PASSIVE_SUBDOMAINS])

    logging.info("[EASM] subdomain enumeration for [%s]: %d unique name(s) across all sources",
                 domain, len(subdomains))
    return subdomains, wildcard
