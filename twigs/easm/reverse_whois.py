"""Reverse-WHOIS style related-domain discovery, using crt.sh as a free
pivot. Certificate Transparency is queried by organisation name (cert subject
O=, when supplied via --reverse_whois_org) and by a keyword derived from the
domain's second-level label; every registrable domain that turns up in a
matching certificate's SANs - other than the one under assessment - is
reported as a candidate sibling / related domain.

crt.sh is the only source (no API key). A run where it is unreachable is a
logged no-op.
"""
import logging

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import RATING_INFO, ISSUE_TYPE_WHOIS, HTTP_TIMEOUT, USER_AGENT
from .util import _new_issue, get_registered_domain

MAX_RELATED = 300
# SLD labels too generic to pivot on (would match the whole internet).
_GENERIC_SLD = {
    'mail', 'www', 'cloud', 'app', 'apps', 'api', 'secure', 'portal', 'shop',
    'host', 'web', 'test', 'dev', 'admin', 'login', 'my', 'go', 'get', 'cdn',
    'static', 'assets', 'img', 'blog', 'store', 'online', 'site', 'home',
}


def _crtsh(query):
    url = 'https://crt.sh/?' + query + '&output=json'
    r = requests.get(url, timeout=HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if r.status_code != 200:
        raise RuntimeError('crt.sh HTTP %s' % r.status_code)
    return r.json()


def _related_from_entries(entries, exclude_reg):
    out = {}
    for e in entries:
        names = set((e.get('name_value') or '').split('\n'))
        if e.get('common_name'):
            names.add(e['common_name'])
        for n in names:
            n = (n or '').strip().lower().lstrip('*.').rstrip('.')
            if not n or ' ' in n or '@' in n:
                continue
            reg = get_registered_domain(n)
            if reg and reg != exclude_reg:
                out.setdefault(reg, (e.get('issuer_name') or '').strip())
    return out


def check_reverse_whois(domain, asset_id, args):
    if getattr(args, 'no_reverse_whois', False) or not HAVE_REQUESTS:
        return []

    reg = get_registered_domain(domain) or domain
    sld = reg.split('.')[0].lower()

    queries = []
    org = getattr(args, 'reverse_whois_org', None)
    if org:
        queries.append(('O=' + requests.utils.quote(org), 'organisation "%s"' % org))
    if len(sld) >= 4 and sld not in _GENERIC_SLD:
        queries.append(('q=' + requests.utils.quote('%' + sld + '%'),
                        'certificate CN/SAN keyword "%s"' % sld))
    if not queries:
        logging.info("[EASM] reverse_whois: no usable pivot for [%s] (generic label, no --reverse_whois_org)", domain)
        return []

    related, methods, failed = {}, [], []
    for query, label in queries:
        try:
            found = _related_from_entries(_crtsh(query), reg)
            related.update(found)
            methods.append('%s -> %d' % (label, len(found)))
        except Exception as e:
            failed.append('%s (%s)' % (label, e))
            logging.warning("[EASM] reverse_whois: %s pivot failed: %s", label, e)

    if not related:
        if failed:
            return []
        return [_new_issue(
            'reverse-whois-none', "No related domains found via reverse-WHOIS pivot",
            "Pivoted from [%s] via %s and found no other registrable domains sharing a certificate identity."
            % (domain, '; '.join(m.split(' -> ')[0] for m in methods)),
            RATING_INFO, asset_id, ISSUE_TYPE_WHOIS, object_id=domain,
            remediation="No action required.")]

    names = sorted(related)[:MAX_RELATED]
    detail = ("Pivoting from [%s] via %s surfaced %d other registrable domain(s) appearing in certificates that share an identity with it. These are candidate sibling / related domains (same organisation, brand, or infrastructure) - some may be unmanaged or forgotten:\n%s"
              % (domain, '; '.join(methods), len(related), '\n'.join(names)))
    if failed:
        detail += "\n(Note: %s failed this run.)" % '; '.join(failed)

    return [_new_issue(
        'reverse-whois-related', "Related domains discovered via reverse-WHOIS (crt.sh) pivot",
        detail, RATING_INFO, asset_id, ISSUE_TYPE_WHOIS, object_id=domain,
        object_meta=','.join(names),
        remediation="Review each domain: confirm ownership (WHOIS/registrant). For any your organisation owns, add it as an EASM seed so it is assessed and monitored - forgotten sibling domains are a common source of unmanaged exposure. Domains you do not own that closely match your brand warrant the same scrutiny as typosquats.")]
