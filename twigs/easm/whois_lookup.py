"""WHOIS registration lookups (registrar/creation/expiry/name servers)."""
import re
import logging

try:
    import dnstwist
    HAVE_DNSTWIST = True
except ImportError:
    HAVE_DNSTWIST = False

from .constants import RATING_INFO, ISSUE_TYPE_WHOIS
from .util import _call_with_timeout, FuturesTimeoutError, _new_issue

_WHOIS_EXPIRY_RE = re.compile(
    r'[\r\n](?:registry expiry date|registrar registration expiration date|expiration date|expiry date|paid-till|renewal date|expire date)[ .]*:\s+(?P<v>[^\r\n]+)',
    re.IGNORECASE)
_WHOIS_NAMESERVER_RE = re.compile(r'[\r\n]name server[ .]*:\s+(?P<v>[^\r\n]+)', re.IGNORECASE)
_WHOIS_STATUS_RE = re.compile(r'[\r\n]domain status[ .]*:\s+(?P<v>[^\r\n]+)', re.IGNORECASE)


def check_whois(domain, asset_id, object_id=None):
    """Performs a best-effort WHOIS lookup for a registered domain and reports
    a single, purely informational finding summarizing registrar/registration
    details. Returns an empty list if a WHOIS lookup could not be completed
    (e.g. server unreachable/timed out) rather than reporting a broken finding."""
    issues = []
    if not HAVE_DNSTWIST:
        return issues
    object_id = object_id or domain
    try:
        w = dnstwist.Whois()
        # dnstwist's Whois client applies only a 2s timeout per socket hop and
        # follows WHOIS "refer:" redirects recursively with no cycle detection
        # or overall bound, so a misbehaving/cyclic referral chain could stall
        # far longer than expected. Enforce a hard wall-clock ceiling here.
        result = _call_with_timeout(w.whois, 15, domain)
    except FuturesTimeoutError:
        logging.debug("WHOIS lookup for [%s] timed out", domain)
        return issues
    except Exception as e:
        logging.debug("WHOIS lookup failed for [%s]: %s", domain, str(e))
        return issues

    text = result.get('text') or ''
    if not text.strip():
        logging.debug("WHOIS lookup for [%s] returned no data", domain)
        return issues
    # normalize like dnstwist's own extractor does: strip each line so field
    # regexes anchored on line boundaries match regardless of indentation.
    normalized = '\r\n'.join(line.strip() for line in text.splitlines() if not line.startswith('%'))

    registrar = result.get('registrar')
    creation_date = result.get('creation_date')

    expiry_match = _WHOIS_EXPIRY_RE.search(normalized)
    expiry_raw = expiry_match.group('v').strip() if expiry_match else None

    name_servers = sorted(set(m.group('v').strip() for m in _WHOIS_NAMESERVER_RE.finditer(normalized)))
    statuses = sorted(set(m.group('v').strip().split()[0] for m in _WHOIS_STATUS_RE.finditer(normalized)))

    parts = ["WHOIS registration details for [%s]:" % domain]
    parts.append("Registrar [%s]." % (registrar or 'unknown/redacted'))
    parts.append("Created [%s]." % (creation_date or 'unknown'))
    parts.append("Expires [%s]." % (expiry_raw or 'unknown'))
    if name_servers:
        parts.append("Name server(s): %s." % ', '.join(name_servers))
    if statuses:
        parts.append("Domain status: %s." % ', '.join(statuses))
    parts.append("This is informational and reflects publicly available domain registration data at scan time; some registrars redact registrant details for privacy (GDPR/ICANN privacy proxy).")

    issues.append(_new_issue(
        'whois-info-%s' % domain, "WHOIS registration details: %s" % domain,
        ' '.join(parts), RATING_INFO, asset_id, ISSUE_TYPE_WHOIS, object_id=object_id,
        remediation="No action required. Useful for ownership/attribution triage - e.g. confirming who registered a domain and when, and whether name servers point to expected infrastructure."))
    return issues

