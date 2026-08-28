"""Subdomain enumeration: certificate transparency (crt.sh) + DNS brute
force."""
import re
import time
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


def enumerate_subdomains_crtsh(domain, retries=3, backoff=2):
    """crt.sh is a free, unauthenticated public service that is frequently
    flaky/rate-limited (404/502/timeout are common transient failures, not
    necessarily "no results"), so this retries with a short backoff before
    giving up."""
    subdomains = set()
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=20, headers={'User-Agent': USER_AGENT})
            if resp.status_code != 200:
                last_error = "HTTP %s" % resp.status_code
            else:
                entries = resp.json()
                for entry in entries:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower().lstrip('*.')
                        if name and name.endswith(domain) and _valid_hostname(name):
                            subdomains.add(name)
                return subdomains
        except Exception as e:
            last_error = str(e)
        logging.debug("crt.sh subdomain enumeration attempt [%s/%s] failed: %s", attempt, retries, last_error)
        if attempt < retries:
            time.sleep(backoff * attempt)
    logging.debug("crt.sh subdomain enumeration failed after [%s] attempt(s): %s", retries, last_error)
    return subdomains


def _valid_hostname(name):
    return bool(re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,251})[a-z0-9]$', name))


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
    its results would be unusable noise; certificate-transparency results are
    unaffected (they reflect subdomains a real certificate was actually
    issued for, independent of wildcard DNS)."""
    subdomains = set()
    subdomains |= enumerate_subdomains_crtsh(domain)
    wildcard = detect_wildcard_dns(domain)
    if wildcard:
        logging.debug("Wildcard DNS detected for [%s] - skipping DNS brute-force enumeration", domain)
    else:
        subdomains |= enumerate_subdomains_bruteforce(domain, workers=getattr(args, 'dns_workers', 20))
    subdomains.discard(domain)
    return subdomains, wildcard

