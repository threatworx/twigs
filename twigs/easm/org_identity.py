"""Best-effort organisation identity derivation for a registrable domain: a
ranked set of candidate "slugs" (the short label an organisation typically
registers on SaaS platforms - Okta, Atlassian, Slack, Zendesk, ...), a
best-effort display name, and a confidence tag reflecting how many
independent signals agreed.

Signals, best-first:
  1. EV/OV TLS certificate Subject organizationName (O=)  - CA-validated
  2. WHOIS registrant Organization                        - registry data
  3. Homepage og:site_name / application-name / copyright  - the "working" name
  4. Registrable-domain second-level label (SLD)          - always available

DV certificates carry no O= and a large share of WHOIS records are redacted,
so most runs fall back to the SLD (confidence 'low'). Callers that probe by
slug should try *every* candidate - confirmation is by the target service's
own response, so a wrong candidate only costs one HTTP 404.

Results are cached per registrable domain (7 days by default) under the
_cache 'saas' sub-directory, since organisation identity almost never
changes between runs.
"""
import re
import ssl
import json
import html
import socket
import logging

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

try:
    import dnstwist
    HAVE_DNSTWIST = True
except ImportError:
    HAVE_DNSTWIST = False

from . import _cache
from .constants import HTTP_TIMEOUT, RATING_INFO, ISSUE_TYPE_WHOIS
from .util import _new_issue, get_registered_domain, _http_get, _call_with_timeout, FuturesTimeoutError

DEFAULT_TTL = 604800  # 7 days
_SUB = 'saas'

# WHOIS / cert org values that are not the customer's name.
_JUNK_TOKENS = (
    'redacted', 'privacy', 'whois', 'proxy', 'gdpr', 'withheld', 'not disclosed',
    'all rights reserved', 'rights reserved', 'copyright ',
    'data protected', 'protection', 'obscured', 'anonymi', 'private customer',
    'domains by proxy', 'perfect privacy', 'contact privacy', 'identity shield',
    'registration private', 'private registration', 'statutory masking',
    # registrars / brand-protection vendors that show up in the org field
    'markmonitor', 'csc corporate', 'cscglobal', 'com laude', 'safenames',
    'nom-iq', 'gandi', 'godaddy', 'namecheap', 'cloudflare', 'key-systems',
    'tucows', 'enom', 'network solutions', 'registrar', 'ovh', 'ionos',
    'name.com', 'porkbun', 'squarespace domains', 'amazon registrar',
)

# Trailing legal-entity suffixes to strip to get a clean working label.
_SUFFIX_RE = re.compile(
    r'[\s,]+(?:'
    r'inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|'
    r'gmbh|mbh|ag|plc|pty|bv|b\.v|nv|n\.v|sarl|s\.a\.r\.l|sas|s\.a\.s|sa|s\.a|'
    r'spa|s\.p\.a|oy|oyj|ab|a\.b|a\.s|kg|kgaa|kk|k\.k|pvt|pte|llp|lp'
    r')\.?\s*$', re.IGNORECASE)

_PAREN_RE = re.compile(r'\([^)]*\)')
_NONWORD_RE = re.compile(r'[^a-z0-9]+')


def _clean(name):
    """Lowercase, drop parentheticals and a trailing legal suffix, collapse
    whitespace. Returns None for empty / junk / privacy-proxy values."""
    if not name:
        return None
    s = _PAREN_RE.sub(' ', str(name)).strip().strip('".\'')
    low = s.lower()
    if len(low) < 2 or any(tok in low for tok in _JUNK_TOKENS):
        return None
    # strip one or more trailing legal suffixes ("Foo Tech, Inc." -> "foo tech")
    prev = None
    while prev != low:
        prev = low
        low = _SUFFIX_RE.sub('', low).strip().strip(',').strip()
    low = re.sub(r'\s{2,}', ' ', low).strip()
    return low or None


def _slug_variants(cleaned):
    """Candidate SaaS-tenant slug spellings for a cleaned org name."""
    if not cleaned:
        return []
    out = []
    nospace = _NONWORD_RE.sub('', cleaned)
    dashed = _NONWORD_RE.sub('-', cleaned).strip('-')
    words = [w for w in re.split(r'[^a-z0-9]+', cleaned) if w]
    out.append(nospace)
    out.append(dashed)
    if words:
        out.append(words[0])
    if len(words) >= 2 and all(len(w) >= 1 for w in words):
        out.append(''.join(w[0] for w in words))
    seen, uniq = set(), []
    for s in out:
        if s and s not in seen and re.match(r'^[a-z0-9][a-z0-9-]{1,40}$', s):
            seen.add(s)
            uniq.append(s)
    return uniq


def _cert_org(host):
    if not HAVE_CRYPTOGRAPHY:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for target in (host, 'www.' + host):
        try:
            with socket.create_connection((target, 443), timeout=HTTP_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    der = ssock.getpeercert(True)
            cert = x509.load_der_x509_certificate(der, default_backend())
            oid = x509.oid.NameOID.ORGANIZATION_NAME
            vals = cert.subject.get_attributes_for_oid(oid)
            if vals and vals[0].value:
                return vals[0].value.strip()
        except Exception as e:
            logging.debug("[EASM] org_identity: cert O= lookup for [%s] failed: %s", target, e)
    return None


_WHOIS_ORG_RES = [
    re.compile(r'(?im)^\s*registrant\s+organi[sz]ation\s*:\s*(.+?)\s*$'),
    re.compile(r'(?im)^\s*(?:org(?:anization|anisation)?|organization\s+name)\s*:\s*(.+?)\s*$'),
    re.compile(r'(?im)^\s*OrgName\s*:\s*(.+?)\s*$'),
    re.compile(r'(?im)^\s*registrant\s*:\s*(.+?)\s*$'),
    re.compile(r'(?im)^\s*registrant\s+name\s*:\s*(.+?)\s*$'),
]


def _whois_org(domain):
    if not HAVE_DNSTWIST:
        return None
    try:
        w = dnstwist.Whois()
        result = _call_with_timeout(w.whois, 15, domain)
    except FuturesTimeoutError:
        return None
    except Exception as e:
        logging.debug("[EASM] org_identity: WHOIS for [%s] failed: %s", domain, e)
        return None
    text = (result or {}).get('text') or ''
    for rx in _WHOIS_ORG_RES:
        for m in rx.finditer(text):
            cleaned = _clean(m.group(1))
            if cleaned:
                return m.group(1).strip()
    return None


_OG_SITE_RE = re.compile(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']{2,60})["\']', re.I)
_APP_NAME_RE = re.compile(r'<meta[^>]+name=["\']application-name["\'][^>]+content=["\']([^"\']{2,60})["\']', re.I)
_TITLE_RE = re.compile(r'<title[^>]*>\s*([^<]{2,120})\s*</title>', re.I)
_COPYR_RE = re.compile(r'(?:&copy;|©|copyright)\s*(?:\d{4}(?:\s*[-–]\s*\d{4})?\s*)?(?:by\s+)?([A-Z][A-Za-z0-9&.,\'\- ]{2,45})', re.I)


_TITLE_JUNK_RE = re.compile(r'(?i)^(home|log ?in|sign ?in|welcome|dashboard|index|'
                            r'loading|just a moment|access denied|404|not found|untitled)\b')


def _first_name_segment(text):
    """From a <title> / site-name string, return the first segment that reads
    like an organisation name: not boilerplate, <= 4 words. Examples:
    'Acme - Login' -> 'Acme'; 'Home | Acme Corp' -> 'Acme Corp';
    'Acme - Unified Proactive Widget Platform' -> 'Acme'."""
    text = html.unescape(text or '').strip()
    for seg in re.split(r'\s*[|–—:·•]\s*|\s+[-‐]\s+', text):
        seg = seg.strip(' .,-–—')
        if not seg or _TITLE_JUNK_RE.match(seg) or not _clean(seg):
            continue
        words = seg.split()
        return seg if len(words) <= 4 else ' '.join(words[:4])
    return None


def _web_name(host):
    resp = _http_get('https://' + host + '/') or _http_get('http://' + host + '/')
    if resp is None or not getattr(resp, 'text', None):
        return None
    page = resp.text[:200000]
    for rx in (_OG_SITE_RE, _APP_NAME_RE):
        m = rx.search(page)
        if m:
            v = html.unescape(m.group(1)).strip()
            if _clean(v):
                return _first_name_segment(v) or v
    m = _COPYR_RE.search(page)
    if m:
        cand = re.split(r'[.|·•]|\ball rights reserved\b|\d{4}',
                        html.unescape(m.group(1)), 1, flags=re.I)[0].strip(' .,-')
        if _clean(cand) and len(cand.split()) <= 5:
            return cand
    m = _TITLE_RE.search(page)
    if m:
        return _first_name_segment(m.group(1))
    return None


def _derive_uncached(domain, extra_slugs):
    reg = get_registered_domain(domain) or domain
    sld = reg.split('.')[0].lower()

    signals = {}
    for key, fn in (('cert', lambda: _cert_org(reg)),
                    ('whois', lambda: _whois_org(reg)),
                    ('web', lambda: _web_name(reg))):
        try:
            v = fn()
        except Exception as e:
            logging.debug("[EASM] org_identity: %s signal failed for [%s]: %s", key, reg, e)
            v = None
        if v and _clean(v):
            signals[key] = v.strip()

    # ordered candidate slugs: explicit overrides, then cert, whois, web, sld
    ordered = []
    for s in (extra_slugs or []):
        s = (s or '').strip().lower()
        if re.match(r'^[a-z0-9][a-z0-9-]{1,40}$', s):
            ordered.append(s)
    for key in ('cert', 'whois', 'web'):
        ordered.extend(_slug_variants(_clean(signals.get(key))))
    ordered.append(sld)
    ordered.extend(_slug_variants(_clean(sld)))
    # A slug shorter than 4 chars (typically an acronym / initials form) is
    # very likely to collide with an unrelated organisation's real SaaS
    # tenant, so a hit on it would be misattributed. Keep such a slug only
    # when it is the registrable-domain label itself (e.g. ibm.com -> "ibm":
    # ibm.okta.com is almost certainly IBM's).
    seen, slugs = set(), []
    for s in ordered:
        if not s or s in seen:
            continue
        if len(s) < 4 and s != sld:
            continue
        seen.add(s)
        slugs.append(s)
    slugs = slugs[:14]

    # A homepage <title>/og:site_name is a weak signal (marketing taglines,
    # CDN interstitials), so 'web' alone never lifts confidence above 'low' -
    # only a validated cert O=, a WHOIS registrant org, or two signals that
    # agree with each other / the domain label do.
    def _sld_related(c):
        s = _clean(sld)
        return bool(c and s and (c == s or c.replace(' ', '') == s or
                                 s in c.split() or c.split()[0] == s))
    cleaned_vals = [_clean(signals.get(k)) for k in ('cert', 'whois', 'web')]
    cleaned_vals = [c for c in cleaned_vals if c]
    agree = (len(cleaned_vals) >= 2 and len(set(cleaned_vals)) < len(cleaned_vals)) or \
        any(_sld_related(_clean(signals.get(k))) for k in ('cert', 'whois'))
    if 'cert' in signals or agree:
        confidence = 'high'
    elif 'whois' in signals or _sld_related(_clean(signals.get('web'))):
        confidence = 'medium'
    else:
        confidence = 'low'

    display = signals.get('cert') or signals.get('whois') or signals.get('web') or sld.capitalize()
    display = html.unescape(str(display)).strip()
    return {
        'domain': reg,
        'display_name': display,
        'confidence': confidence,
        'slugs': slugs,
        'signals': signals,
    }


def derive(domain, extra_slugs=None, ttl=DEFAULT_TTL):
    """{domain, display_name, confidence, slugs[], signals{}} for a domain.

    Explicit `extra_slugs` (e.g. from --saas_slug) are always tried first and
    bypass the cache key so an override takes effect immediately."""
    reg = get_registered_domain(domain) or domain
    if not extra_slugs:
        cached, fresh = _cache.read('orgid_%s.json' % reg, ttl, sub=_SUB)
        if cached and fresh:
            try:
                return json.loads(cached)
            except ValueError:
                pass
    result = _derive_uncached(reg, extra_slugs)
    if not extra_slugs:
        try:
            _cache.write('orgid_%s.json' % reg, json.dumps(result), sub=_SUB)
        except Exception:
            pass
    return result


def identity_issue(info, asset_id):
    """An INFO finding recording how the org identity was derived - useful for
    triage of everything downstream that keyed off the slug."""
    sig = info.get('signals') or {}
    lines = ["Derived organisation identity for [%s]:" % info['domain'],
             "Display name: %s" % info['display_name'],
             "Confidence: %s" % info['confidence'],
             "Candidate tenant slug(s) tried: %s" % ', '.join(info['slugs'][:14])]
    if sig:
        lines.append("Signals: " + '; '.join('%s="%s"' % (k, v) for k, v in sig.items()))
    else:
        lines.append("Signals: none available (registrable-domain label only) - "
                     "TLS cert carries no O= and WHOIS registrant is redacted/unavailable.")
    return _new_issue(
        'org-identity', "Organisation identity (SaaS tenant slug derivation)",
        '\n'.join(lines), RATING_INFO, asset_id, ISSUE_TYPE_WHOIS,
        object_id=info['domain'], object_meta=','.join(info['slugs'][:14]),
        remediation="No action required. If the derived slug is wrong, re-run with --saas_slug <correct-slug> so SaaS tenant discovery probes the right namespace.")
