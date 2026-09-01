"""JavaScript bundle analysis for a host: fetch the page, pull same-origin /
first-party script bundles, and mine them for

  * secrets            - high-signal credential patterns (AWS/GCP/Slack/Stripe/
                         GitHub keys, private-key headers, bearer JWTs, ...)
  * internal hostnames - hostnames in string literals that are subdomains of
                         the site's registrable domain or look internal
                         (.internal / .local / .corp / RFC1918) - fed back
                         into discovery
  * API endpoints      - path literals ("/api/...", fetch("..."))
  * source maps        - //# sourceMappingURL= -> the .map's `sources[]`
                         reveal internal project structure / original source

Bundle count and per-bundle size are bounded.
"""
import re
import json
import logging
from urllib.parse import urljoin, urlsplit

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_HIGH, RATING_CRITICAL,
                        ISSUE_TYPE_CREDENTIAL_LEAK, ISSUE_TYPE_WEB_APPLICATION,
                        HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, _http_get, get_registered_domain

MAX_BUNDLES = 12
MAX_BUNDLE_BYTES = 3 * 1024 * 1024
MAX_LISTED = 100

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=([^\s*]+)')
_ENDPOINT = re.compile(r'["\'`](/(?:api|v\d|rest|graphql|internal|admin|auth|oauth|user|users|account)/[A-Za-z0-9_./{}-]{0,80})["\'`]')
_HOSTLITERAL = re.compile(r'https?://([a-z0-9.-]+\.[a-z]{2,})', re.I)

# High-signal secret patterns (curated; a compact stand-in for trufflehog rules)
_SECRET_RULES = [
    ('AWS access key id',        re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('AWS secret access key',    re.compile(r'(?i)aws_secret_access_key["\'\s:=]{1,4}([A-Za-z0-9/+=]{40})')),
    ('Google API key',           re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ('Google OAuth client secret', re.compile(r'\bGOCSPX-[0-9A-Za-z_\-]{20,}\b')),
    ('Slack token',              re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,48}\b')),
    ('Slack webhook',            re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+')),
    ('Stripe live secret key',   re.compile(r'\bsk_live_[0-9A-Za-z]{16,}\b')),
    ('GitHub token',             re.compile(r'\bgh[pousr]_[0-9A-Za-z]{36,}\b')),
    ('GitLab PAT',               re.compile(r'\bglpat-[0-9A-Za-z_\-]{20,}\b')),
    ('Twilio API key',           re.compile(r'\bSK[0-9a-fA-F]{32}\b')),
    ('SendGrid API key',         re.compile(r'\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b')),
    ('Private key block',        re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----')),
    ('JWT',                      re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b')),
    ('Generic secret assignment', re.compile(r'(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b["\'\s:=]{1,4}["\']([A-Za-z0-9_\-./+=]{12,64})["\']')),
]

_INTERNAL_TLDS = ('.internal', '.local', '.lan', '.corp', '.intranet', '.test', '.example')
_RFC1918 = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)')


def _looks_internal(host, reg):
    h = host.lower()
    if reg and (h == reg or h.endswith('.' + reg)):
        return True
    if h.endswith(_INTERNAL_TLDS):
        return True
    return bool(_RFC1918.match(h))


def _fetch(url, cap=MAX_BUNDLE_BYTES):
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, verify=False, stream=True,
                         headers={'User-Agent': USER_AGENT})
    except requests.exceptions.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.raw.read(cap, decode_content=True).decode('utf-8', 'replace')
    except Exception:
        return (r.text or '')[:cap]


def check_js_analysis(host, asset_id, args):
    """Returns (issues, internal_hostnames_set)."""
    if getattr(args, 'no_js_analysis', False) or not HAVE_REQUESTS:
        return [], set()

    page = None
    base = None
    for scheme in ('https', 'http'):
        page = _http_get('%s://%s/' % (scheme, host))
        if page is not None:
            base = '%s://%s/' % (scheme, host)
            break
    if page is None:
        return [], set()

    reg = get_registered_domain(host)
    srcs = []
    for m in _SCRIPT_SRC.finditer(page.text or ''):
        u = urljoin(base, m.group(1))
        if not u.startswith(('http://', 'https://')):
            continue
        hn = (urlsplit(u).hostname or '').lower()
        # same-origin or first-party CDN only
        if hn == host.lower() or (reg and hn.endswith('.' + reg)) or (reg and hn == reg):
            srcs.append(u)
    srcs = list(dict.fromkeys(srcs))[:MAX_BUNDLES]
    if not srcs:
        return [], set()

    secrets, endpoints, int_hosts, sourcemaps = {}, set(), set(), []
    for u in srcs:
        body = _fetch(u)
        if not body:
            continue
        for label, rx in _SECRET_RULES:
            for m in rx.finditer(body):
                val = m.group(0)
                secrets.setdefault(label, set()).add((u, val[:16] + '...' if len(val) > 20 else val))
        for m in _ENDPOINT.finditer(body):
            endpoints.add(m.group(1))
        for m in _HOSTLITERAL.finditer(body):
            hn = m.group(1).lower()
            if hn != host.lower() and _looks_internal(hn, reg):
                int_hosts.add(hn)
        sm = _SOURCEMAP.search(body)
        if sm:
            map_url = urljoin(u, sm.group(1).strip())
            if map_url.startswith(('http://', 'https://')):
                mb = _fetch(map_url, cap=2 * 1024 * 1024)
                srcpaths = []
                if mb:
                    try:
                        srcpaths = [s for s in (json.loads(mb).get('sources') or []) if s][:40]
                    except ValueError:
                        pass
                sourcemaps.append((map_url, srcpaths))

    issues = []
    if secrets:
        lines = []
        for label, items in sorted(secrets.items()):
            for src, sample in sorted(items)[:5]:
                lines.append('%s: %s  (in %s)' % (label, sample, src))
        issues.append(_new_issue(
            'js-secret-exposed', "Credential/secret pattern(s) in client-side JavaScript",
            "Pattern(s) matching credentials or API secrets were found in JavaScript served to every visitor of [%s]. Client-side code is fully public - treat any match as compromised until proven a false positive:\n%s"
            % (host, '\n'.join(lines[:MAX_LISTED])),
            RATING_CRITICAL if any(k in secrets for k in ('AWS secret access key', 'Private key block', 'Stripe live secret key', 'AWS access key id')) else RATING_HIGH,
            asset_id, ISSUE_TYPE_CREDENTIAL_LEAK, object_id=host,
            object_meta=','.join(sorted(secrets)),
            remediation="Revoke and rotate every matched credential now. Remove secrets from front-end bundles - move the call server-side or use short-lived, scoped tokens minted per session. Add secret scanning to CI to prevent recurrence."))
    if int_hosts:
        issues.append(_new_issue(
            'js-internal-hostname', "Internal hostname(s) referenced in client-side JavaScript",
            "JavaScript on [%s] references hostname(s) that look internal or are additional subdomains of the same organisation - useful reconnaissance and additional attack surface:\n%s"
            % (host, '\n'.join(sorted(int_hosts)[:MAX_LISTED])),
            RATING_LOW, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            object_meta=','.join(sorted(int_hosts)),
            remediation="Confirm none of these should be secret. Internal API/base URLs in front-end code disclose infrastructure and often bypass an intended gateway."))
    if sourcemaps:
        sm_lines = []
        for mu, sp in sourcemaps:
            sm_lines.append('%s  (%d source path(s))' % (mu, len(sp)))
            sm_lines.extend('    ' + p for p in sp[:15])
        issues.append(_new_issue(
            'js-sourcemap-exposed', "JavaScript source map(s) exposed",
            "Source map(s) are reachable for [%s], exposing original (pre-minification) file paths and often full original source:\n%s"
            % (host, '\n'.join(sm_lines[:MAX_LISTED])),
            RATING_LOW, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            object_meta=','.join(mu for mu, _ in sourcemaps),
            remediation="Do not deploy .map files to production (or restrict them to internal IPs). They reveal code structure, comments, and unminified logic that aids attackers."))
    if endpoints:
        issues.append(_new_issue(
            'js-endpoints', "API endpoints referenced in client-side JavaScript",
            "%d API/route path(s) were extracted from JavaScript on [%s] - a real, observed endpoint list for manual testing:\n%s"
            % (len(endpoints), host, '\n'.join(sorted(endpoints)[:MAX_LISTED])),
            RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            object_meta=','.join(sorted(endpoints)[:50]),
            remediation="Review these endpoints for missing authentication/authorization, verbose errors, and IDOR. Front-end code enumerates the API surface for an attacker."))

    return issues, int_hosts
