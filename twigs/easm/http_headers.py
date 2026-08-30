"""HTTP security headers audit: Strict-Transport-Security (HSTS),
Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and
Referrer-Policy.

This deliberately overlaps with what nuclei's community templates can also
cover, because nuclei is optional/binary-dependent (not guaranteed
installed) and community-template coverage/freshness isn't guaranteed."""
import re

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, ISSUE_TYPE_HTTP_HEADERS
from .util import _new_issue, _http_get


def check_security_headers(host, asset_id):
    issues = []
    resp = None
    used_scheme = None
    for scheme in ('https', 'http'):
        r = _http_get("%s://%s/" % (scheme, host))
        if r is not None:
            resp = r
            used_scheme = scheme
            break
    if resp is None:
        return issues

    headers = {k.lower(): v for k, v in resp.headers.items()}
    problems = []

    if used_scheme == 'https':
        hsts = headers.get('strict-transport-security')
        if not hsts:
            problems.append(_new_issue(
                'header-missing-hsts', "Missing Strict-Transport-Security (HSTS) header",
                "[%s] does not send a Strict-Transport-Security header over HTTPS. Without HSTS, browsers will still attempt a plaintext HTTP connection on the next visit (or after any cached HSTS policy expires), giving a network attacker a window to intercept/downgrade the connection (SSL-stripping) before HTTPS is established." % host,
                RATING_MEDIUM, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
                remediation="Add a Strict-Transport-Security header, e.g. 'Strict-Transport-Security: max-age=31536000; includeSubDomains'. Consider HSTS preload once you're confident all subdomains support HTTPS."))
        else:
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age < 15768000:  # ~6 months, a commonly cited minimum
                problems.append(_new_issue(
                    'header-weak-hsts', "Weak Strict-Transport-Security max-age",
                    "[%s] sends a Strict-Transport-Security header with max-age=%s, below the commonly recommended minimum of 6 months (15768000 seconds). A short max-age narrows the downgrade-protection window between visits." % (host, max_age),
                    RATING_LOW, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
                    remediation="Increase max-age to at least 15768000 (6 months), ideally 31536000 (1 year) or more."))

    csp = headers.get('content-security-policy')
    if not csp:
        problems.append(_new_issue(
            'header-missing-csp', "Missing Content-Security-Policy header",
            "[%s] does not send a Content-Security-Policy header. CSP is a browser-enforced allow-list restricting which sources scripts/styles/frames/etc. may load from, and is one of the strongest available defenses against XSS." % host,
            RATING_MEDIUM, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Add a Content-Security-Policy header scoped to your actual resource origins. Start in Content-Security-Policy-Report-Only mode to validate it doesn't break functionality before enforcing it."))
    elif re.search(r'unsafe-inline|unsafe-eval', csp):
        problems.append(_new_issue(
            'header-weak-csp', "Content-Security-Policy allows unsafe-inline/unsafe-eval",
            "[%s]'s Content-Security-Policy includes 'unsafe-inline' and/or 'unsafe-eval', which significantly weakens its XSS protection by allowing inline scripts/styles or dynamic code evaluation - exactly what CSP is meant to restrict." % host,
            RATING_LOW, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Remove 'unsafe-inline'/'unsafe-eval' where possible; use per-response nonces or content hashes for any legitimate inline scripts/styles instead."))

    has_frame_ancestors = bool(csp) and 'frame-ancestors' in csp
    if not headers.get('x-frame-options') and not has_frame_ancestors:
        problems.append(_new_issue(
            'header-missing-xfo', "Missing X-Frame-Options header (and no CSP frame-ancestors)",
            "[%s] sends neither an X-Frame-Options header nor a Content-Security-Policy frame-ancestors directive, so the page can be embedded in an iframe on any other site - enabling clickjacking attacks (tricking users into clicking something different from what they perceive)." % host,
            RATING_MEDIUM, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or the equivalent CSP 'frame-ancestors' directive, which supersedes X-Frame-Options in modern browsers), unless this page is intentionally meant to be embeddable."))

    if headers.get('x-content-type-options', '').lower() != 'nosniff':
        problems.append(_new_issue(
            'header-missing-xcto', "Missing or incorrect X-Content-Type-Options header",
            "[%s] does not send 'X-Content-Type-Options: nosniff'. Without it, some browsers will try to guess (\"sniff\") a response's content type rather than trusting the declared Content-Type, which can be abused to have a file treated as executable script/HTML rather than its intended type." % host,
            RATING_LOW, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Add 'X-Content-Type-Options: nosniff' to all responses."))

    if not headers.get('referrer-policy'):
        problems.append(_new_issue(
            'header-missing-referrer-policy', "Missing Referrer-Policy header",
            "[%s] does not send a Referrer-Policy header, so browsers fall back to their default referrer behavior, which can leak the full URL (including sensitive path/query data) to third-party sites and resources linked from this page." % host,
            RATING_LOW, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Add a Referrer-Policy header, e.g. 'Referrer-Policy: strict-origin-when-cross-origin' (a good, widely-compatible default)."))

    issues.extend(problems)
    if not problems:
        issues.append(_new_issue(
            'header-all-good', "HTTP security headers are properly configured",
            "[%s] sends HSTS with an adequate max-age (if served over HTTPS), a Content-Security-Policy without unsafe-inline/unsafe-eval, X-Frame-Options or a CSP frame-ancestors directive, X-Content-Type-Options: nosniff, and Referrer-Policy." % host,
            RATING_INFO, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="No action required."))
    return issues


_COOKIE_SECURE_RE = re.compile(r';\s*secure\b', re.I)
_COOKIE_HTTPONLY_RE = re.compile(r';\s*httponly\b', re.I)
_COOKIE_SAMESITE_RE = re.compile(r';\s*samesite\s*=\s*(\w+)', re.I)


def check_cookie_security(host, asset_id):
    issues = []
    resp = None
    used_scheme = None
    for scheme in ('https', 'http'):
        r = _http_get("%s://%s/" % (scheme, host))
        if r is not None:
            resp = r
            used_scheme = scheme
            break
    if resp is None:
        return issues

    cookie_headers = []
    try:
        cookie_headers = resp.raw.headers.get_all('Set-Cookie') or []
    except AttributeError:
        try:
            cookie_headers = resp.raw.headers.getlist('Set-Cookie') or []
        except AttributeError:
            single = resp.headers.get('Set-Cookie')
            if single:
                cookie_headers = [single]
    if not cookie_headers:
        return issues

    missing_secure = []
    missing_httponly = []
    weak_samesite = []
    for raw in cookie_headers:
        name = raw.split('=', 1)[0].strip()
        is_secure = bool(_COOKIE_SECURE_RE.search(raw))
        if used_scheme == 'https' and not is_secure:
            missing_secure.append(name)
        if not _COOKIE_HTTPONLY_RE.search(raw):
            missing_httponly.append(name)
        m = _COOKIE_SAMESITE_RE.search(raw)
        samesite_val = m.group(1).lower() if m else None
        if samesite_val is None or (samesite_val == 'none' and not is_secure):
            weak_samesite.append(name)

    if missing_secure:
        issues.append(_new_issue(
            'cookie-missing-secure', "Cookie(s) missing the Secure flag",
            "[%s] sets cookie(s) without the Secure flag over HTTPS: %s. Without Secure, these cookies could be sent over a future plaintext HTTP connection to the same host (e.g. via a mixed-content redirect or an HTTP-served subdomain), exposing them to network interception." % (host, ', '.join(missing_secure)),
            RATING_MEDIUM, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Add the 'Secure' flag to all cookies set over HTTPS."))
    if missing_httponly:
        issues.append(_new_issue(
            'cookie-missing-httponly', "Cookie(s) missing the HttpOnly flag",
            "[%s] sets cookie(s) without the HttpOnly flag: %s. Without HttpOnly, these cookies are readable by JavaScript, meaning a successful XSS attack could exfiltrate them directly (e.g. session hijacking)." % (host, ', '.join(missing_httponly)),
            RATING_LOW, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Add the 'HttpOnly' flag to cookies that don't need to be read by client-side JavaScript (most session/auth cookies)."))
    if weak_samesite:
        issues.append(_new_issue(
            'cookie-weak-samesite', "Cookie(s) missing or with a weak SameSite attribute",
            "[%s] sets cookie(s) with no SameSite attribute, or SameSite=None without also being marked Secure: %s. This weakens protection against cross-site request forgery (CSRF), since the browser will still attach these cookies to cross-site requests." % (host, ', '.join(weak_samesite)),
            RATING_LOW, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="Set 'SameSite=Lax' (or 'Strict' for sensitive cookies that don't need cross-site delivery) on all cookies. A cookie that genuinely needs SameSite=None for cross-site use must also be marked Secure."))

    if not (missing_secure or missing_httponly or weak_samesite):
        issues.append(_new_issue(
            'cookie-security-ok', "Cookies set with appropriate security flags",
            "[%s] sets [%s] cookie(s), all with appropriate Secure/HttpOnly/SameSite flags for their context." % (host, len(cookie_headers)),
            RATING_INFO, asset_id, ISSUE_TYPE_HTTP_HEADERS, object_id=host,
            remediation="No action required."))
    return issues
