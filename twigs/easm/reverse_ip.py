"""Reverse-IP / virtual-host discovery.

For a discovered IP: (1) find other hostnames served from it (co-hosted
domains) via free reverse-IP sources, and (2) for hostnames that don't
currently resolve to the scanner, confirm by sending an HTTP request to the
IP with that Host header and checking whether a *distinct* site is served -
an application reachable "with no current DNS".

Sources (free, best-effort, per-source failure tolerated): HackerTarget
reverse-IP, RapidDNS sameip, AlienVault OTX passive DNS (OTX needs a key).

By default runs only against IPs NOT attributed to a shared cloud/CDN
provider (tag CLOUD:unattributed, or no CLOUD tag) - a reverse lookup on a
shared load-balancer IP returns thousands of unrelated tenants.
--reverse_ip_all overrides.
"""
import os
import re
import logging

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_MEDIUM, ISSUE_TYPE_SUBDOMAIN,
                        HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, get_registered_domain, _is_ipv6, resolve_ips

MAX_COHOSTED = 400
MAX_VHOST_PROBE = 25

# Providers whose individual IPs are typically shared frontends (CDN edges,
# hyperscaler load balancers) - a reverse-IP lookup returns unrelated tenants,
# so skip by default. VPS providers (Linode/DigitalOcean/Vultr/Hetzner/OVH/...)
# are single-tenant enough to be worth checking, as is CLOUD:unattributed.
_SHARED_PROVIDERS = {
    'aws', 'google', 'azure', 'microsoft 365', 'cloudflare', 'fastly',
    'akamai', 'github', 'oracle oci',
}


def _skip_shared(tags):
    for t in (tags or []):
        if t.startswith('CLOUD:'):
            return t.split(':', 1)[1].strip().lower() in _SHARED_PROVIDERS
    return False


def _hackertarget(ip):
    r = requests.get('https://api.hackertarget.com/reverseiplookup/?q=' + ip,
                     timeout=HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    b = (r.text or '').strip()
    low = b.lower()
    if r.status_code != 200 or 'api count exceeded' in low or low.startswith('error'):
        raise RuntimeError(b[:100] or 'HTTP %s' % r.status_code)
    if 'no dns' in low or 'no records' in low:
        return set()
    return {ln.strip().lower() for ln in b.splitlines() if ln.strip() and '.' in ln}


def _rapiddns(ip):
    r = requests.get('https://rapiddns.io/sameip/%s?full=1' % ip,
                     timeout=HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if r.status_code != 200:
        raise RuntimeError('HTTP %s' % r.status_code)
    return {m.lower() for m in re.findall(r'>\s*([A-Za-z0-9_.-]+\.[A-Za-z]{2,})\s*</td>', r.text)}


def _otx(ip, key):
    h = {'User-Agent': USER_AGENT}
    if key:
        h['X-OTX-API-KEY'] = key
    kind = 'IPv6' if _is_ipv6(ip) else 'IPv4'
    r = requests.get('https://otx.alienvault.com/api/v1/indicators/%s/%s/passive_dns' % (kind, ip),
                     timeout=HTTP_TIMEOUT, headers=h)
    if r.status_code in (401, 403, 429):
        raise RuntimeError('needs OTX_API_KEY')
    if r.status_code != 200:
        raise RuntimeError('HTTP %s' % r.status_code)
    return {(rec.get('hostname') or '').strip().lower()
            for rec in (r.json().get('passive_dns') or []) if rec.get('hostname')}


def _raw_get(scheme, ip, host_header):
    try:
        return requests.get('%s://%s/' % (scheme, ip),
                            headers={'Host': host_header, 'User-Agent': USER_AGENT},
                            timeout=HTTP_TIMEOUT, verify=False, allow_redirects=False)
    except requests.exceptions.RequestException:
        return None


def check_reverse_ip(host, ips, tags, asset_id, args):
    if getattr(args, 'no_reverse_ip', False) or not HAVE_REQUESTS or not ips:
        return []
    if _skip_shared(tags) and not getattr(args, 'reverse_ip_all', False):
        logging.info("[EASM] reverse_ip: [%s] is on shared cloud/CDN infrastructure - skipping (use --reverse_ip_all)", host)
        return []

    own_reg = get_registered_domain(host)
    otx_key = getattr(args, 'otx_api_key', None) or os.environ.get('OTX_API_KEY')
    ipv4 = [ip for ip in ips if not _is_ipv6(ip)] or list(ips)

    cohosted, used, failed = {}, [], []
    for ip in ipv4[:3]:
        for name, fn in (('hackertarget', _hackertarget),
                         ('rapiddns', _rapiddns),
                         ('otx', lambda i: _otx(i, otx_key))):
            try:
                for hn in fn(ip):
                    hn = hn.lstrip('*.').rstrip('.')
                    if hn and hn != host:
                        cohosted.setdefault(hn, ip)
                if name not in used:
                    used.append(name)
            except Exception as e:
                failed.append('%s (%s)' % (name, e))
                logging.debug("reverse_ip source %s failed for %s: %s", name, ip, e)

    if not cohosted:
        if failed and not used:
            logging.warning("[EASM] reverse_ip: all sources failed for [%s]: %s", host, '; '.join(failed))
        return []

    names = sorted(cohosted)[:MAX_COHOSTED]
    other_org = [n for n in names if get_registered_domain(n) != own_reg]

    issues = [_new_issue(
        'reverse-ip-cohosted', "Co-hosted hostnames on shared IP address(es)",
        "Reverse-IP lookup (%s) on %s found %d other hostname(s) served from the same address(es). Co-hosting implies shared exposure - a compromise or vulnerable virtual host on one name can affect the box others share:\n%s"
        % (', '.join(used) or 'n/a', ', '.join(ipv4[:3]), len(cohosted), '\n'.join(names)),
        RATING_INFO, asset_id, ISSUE_TYPE_SUBDOMAIN, object_id=ipv4[0],
        object_meta=','.join(names),
        remediation="Confirm which co-hosted names belong to your organisation. On a dedicated IP, unexpected third-party domains warrant investigation; on shared hosting, note the shared-tenant risk.")]

    probe = [n for n in other_org if not (set(resolve_ips(n)) & set(ipv4))][:MAX_VHOST_PROBE]
    shadow = []
    for scheme in ('https', 'http'):
        base = _raw_get(scheme, ipv4[0], ipv4[0])
        if base is None:
            continue
        base_sig = (base.status_code, len(base.content or b''))
        for n in probe:
            r = _raw_get(scheme, ipv4[0], n)
            if r is None:
                continue
            if r.status_code < 400 and (r.status_code, len(r.content or b'')) != base_sig:
                shadow.append('%s -> HTTP %s (%d bytes)' % (n, r.status_code, len(r.content or b'')))
        break

    if shadow:
        issues.append(_new_issue(
            'reverse-ip-vhost', "Virtual host(s) serving distinct content without current DNS",
            "The following hostname(s) do not currently resolve to %s, but the server returns a distinct site when addressed with that Host header - an application reachable only if the name is known:\n%s"
            % (ipv4[0], '\n'.join(shadow)),
            RATING_MEDIUM, asset_id, ISSUE_TYPE_SUBDOMAIN, object_id=ipv4[0],
            object_meta=','.join(s.split(' ')[0] for s in shadow),
            remediation="These are often forgotten staging/admin apps. Confirm each is intended to be internet-reachable; if not, bind it to an internal interface or enforce authentication at the edge."))
    return issues
