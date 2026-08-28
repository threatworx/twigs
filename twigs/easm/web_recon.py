"""Miscellaneous web reconnaissance checks: security.txt (RFC 9116),
robots.txt/sitemap.xml mining, open-redirect probing of common query
parameters, HTTP method enumeration, and directory listing detection."""
import re
from urllib.parse import quote, urlparse

import requests

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_WEB_APPLICATION, HTTP_TIMEOUT, USER_AGENT
from .util import _new_issue, _http_get


def check_security_txt(host, asset_id):
    """RFC 9116 security.txt: a rare positive-framed check - does this org
    publish a responsible-disclosure contact? Checks the canonical location
    first, falling back to the legacy pre-RFC path some older sites still
    use."""
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    resp = None
    used_path = None
    for path in ('/.well-known/security.txt', '/security.txt'):
        r = _http_get(base + path)
        if r is not None and r.status_code == 200 and 'Contact:' in r.text:
            resp = r
            used_path = path
            break

    if resp is None:
        issues.append(_new_issue(
            'security-txt-not-found', "No security.txt found",
            "[%s] does not publish a security.txt file (checked /.well-known/security.txt and the legacy /security.txt location). security.txt (RFC 9116) tells security researchers how to responsibly report a vulnerability to your organization." % host,
            RATING_LOW, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="Publish a security.txt file at /.well-known/security.txt with at least a Contact field (email or URL) and an Expires field, per RFC 9116. This is a low-effort way to make it easy for researchers to report issues to you responsibly instead of publicly."))
        return issues

    contacts = re.findall(r'(?im)^Contact:\s*(.+)$', resp.text)
    expires_match = re.search(r'(?im)^Expires:\s*(.+)$', resp.text)
    detail = "[%s] publishes a security.txt at [%s]. Contact(s): %s." % (host, used_path, '; '.join(c.strip() for c in contacts))
    if not expires_match:
        detail += " No Expires field was found - RFC 9116 requires one, and its absence can cause some consumers to treat the file as invalid/stale."
        rating = RATING_LOW
    else:
        detail += " Expires: %s." % expires_match.group(1).strip()
        rating = RATING_INFO
    issues.append(_new_issue(
        'security-txt-found', "security.txt found",
        detail, rating, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
        remediation="No action required beyond keeping the Expires date current and the contact(s) monitored." if rating == RATING_INFO else
                     "Add an Expires field (RFC 9116 requires one), e.g. 'Expires: 2027-01-01T00:00:00Z', and keep it refreshed."))
    return issues


def check_robots_sitemap(host, asset_id):
    """Mines robots.txt Disallow entries and sitemap.xml URLs for
    reconnaissance value. Purely informational recon, not a hardening
    control, so - unlike most other checks in this package - nothing is
    reported when neither file reveals anything of note."""
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    robots_resp = _http_get(base + '/robots.txt')
    if robots_resp is not None and robots_resp.status_code == 200:
        disallowed = sorted(set(re.findall(r'(?im)^Disallow:\s*(\S+)', robots_resp.text)))
        disallowed = [p for p in disallowed if p and p != '/']
        if disallowed:
            sample = ', '.join(disallowed[:20])
            more = ' (and %s more)' % (len(disallowed) - 20) if len(disallowed) > 20 else ''
            issues.append(_new_issue(
                'robots-txt-paths', "robots.txt reveals candidate paths",
                "[%s]'s robots.txt disallows [%s] path(s) from search-engine crawling: %s%s. These are not necessarily sensitive, but Disallow entries sometimes hint at internal/admin/staging areas the site owner didn't want indexed - which paradoxically reveals their existence." % (host, len(disallowed), sample, more),
                RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=base + '/robots.txt',
                remediation="No action required by itself - robots.txt is advisory only (well-behaved crawlers honor it, nothing enforces it). If any listed path is meant to be actually inaccessible rather than merely unindexed, protect it with authentication instead of relying on robots.txt."))

    sitemap_resp = _http_get(base + '/sitemap.xml')
    if sitemap_resp is not None and sitemap_resp.status_code == 200:
        locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', sitemap_resp.text, re.IGNORECASE)
        if locs:
            sample = ', '.join(locs[:10])
            more = ' (and %s more)' % (len(locs) - 10) if len(locs) > 10 else ''
            issues.append(_new_issue(
                'sitemap-xml-found', "sitemap.xml found",
                "[%s] publishes a sitemap.xml listing [%s] URL(s), e.g.: %s%s." % (host, len(locs), sample, more),
                RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=base + '/sitemap.xml',
                remediation="No action required. Useful for understanding the site's full structure during triage."))
    return issues


OPEN_REDIRECT_PARAMS = [
    'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'return',
    'returnUrl', 'return_to', 'dest', 'destination', 'continue', 'go', 'target',
]
OPEN_REDIRECT_PROBE = 'https://easm-redirect-probe.invalid/'


def check_open_redirect(host, asset_id):
    """Probes common redirect-parameter names on the site root for an
    unvalidated open redirect - a frequent phishing-enablement bug (a link
    that appears to point to a trusted domain but silently forwards
    elsewhere). Single non-destructive GET per parameter, redirects not
    followed."""
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    found = []
    for param in OPEN_REDIRECT_PARAMS:
        url = "%s/?%s=%s" % (base, param, quote(OPEN_REDIRECT_PROBE, safe=''))
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=False,
                                 headers={'User-Agent': USER_AGENT})
        except requests.exceptions.RequestException:
            continue
        if resp.status_code not in (301, 302, 303, 307, 308):
            continue
        # Parse where the redirect actually points, rather than a substring
        # match on the raw Location header - a same-host redirect (e.g. a
        # canonical www-to-apex redirect) can echo the untouched query
        # string, including our probe value, while still pointing at the
        # correct host. A substring match would misreport that as an open
        # redirect; only the parsed hostname of the target matters.
        target_host = urlparse(resp.headers.get('Location', '')).hostname or ''
        if target_host.lower() == 'easm-redirect-probe.invalid':
            found.append(param)

    if found:
        issues.append(_new_issue(
            'open-redirect-found', "Possible open redirect via query parameter",
            "[%s] redirects to an arbitrary attacker-supplied URL when the following query parameter(s) are set on the site root: %s. Open redirects are commonly abused in phishing (a link that appears to point to this trusted domain but silently forwards the victim elsewhere) and can sometimes assist OAuth/SSO token theft." % (host, ', '.join(found)),
            RATING_MEDIUM, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="Validate redirect targets against an explicit allow-list of trusted destinations, or require same-origin relative paths only, rather than redirecting to a user-supplied absolute URL."))
    else:
        issues.append(_new_issue(
            'open-redirect-none-found', "No open redirect found via common parameters",
            "Checked [%s] common redirect-parameter names against the site root of [%s] and found none that redirect to an arbitrary external URL." % (len(OPEN_REDIRECT_PARAMS), host),
            RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="No action required. This checks a curated set of common parameter names on the site root only, not an exhaustive crawl of every page/parameter."))
    return issues


# Methods that are meaningful to flag at the site root - PUT/DELETE imply a
# resource can be created/modified/removed there, and TRACE enables
# Cross-Site Tracing (reading otherwise-HttpOnly cookies by reflecting the
# request back). CONNECT is proxy-only and not meaningful for an origin
# server. GET/HEAD/POST/OPTIONS are always expected and not flagged.
DANGEROUS_HTTP_METHODS = {'PUT', 'DELETE', 'TRACE', 'CONNECT'}


def check_http_methods(host, asset_id):
    """Sends a single non-destructive OPTIONS request to the site root and
    inspects the Allow header - does not actually invoke PUT/DELETE/TRACE,
    only checks whether the server advertises support for them."""
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    try:
        resp = requests.options(base + '/', timeout=HTTP_TIMEOUT, verify=False,
                                 headers={'User-Agent': USER_AGENT})
    except requests.exceptions.RequestException:
        return issues

    allow = resp.headers.get('Allow') or resp.headers.get('Access-Control-Allow-Methods') or ''
    advertised = {m.strip().upper() for m in allow.split(',') if m.strip()}
    if not advertised:
        return issues

    dangerous = sorted(advertised & DANGEROUS_HTTP_METHODS)
    if dangerous:
        rating = RATING_MEDIUM if 'TRACE' in dangerous or 'CONNECT' in dangerous else RATING_LOW
        detail = "[%s] advertises support for the following HTTP method(s) at its site root, per its Allow header: %s (full list: %s)." % (host, ', '.join(dangerous), ', '.join(sorted(advertised)))
        if 'TRACE' in dangerous:
            detail += " TRACE in particular enables Cross-Site Tracing (XST), which can be used to read cookies/headers otherwise inaccessible to JavaScript (e.g. HttpOnly cookies) if combined with an XSS elsewhere on the site."
        if 'PUT' in dangerous or 'DELETE' in dangerous:
            detail += " PUT/DELETE at the site root is unusual outside a REST API context - if unintentional, it may allow uploading or removing content without authentication."
        issues.append(_new_issue(
            'http-methods-dangerous', "Potentially dangerous HTTP methods advertised",
            detail, rating, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="Disable TRACE at the web server level (most servers support this directly, e.g. Apache's TraceEnable off). For PUT/DELETE, confirm they are intentional and require authentication/authorization before allowing them; if unintentional, disable them for this path."))
    else:
        issues.append(_new_issue(
            'http-methods-ok', "No dangerous HTTP methods advertised",
            "[%s] advertises the following HTTP method(s) at its site root: %s. None of PUT/DELETE/TRACE/CONNECT are advertised." % (host, ', '.join(sorted(advertised))),
            RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="No action required."))
    return issues


# Common directories worth probing for autoindex (directory listing) output.
# Kept small and high-signal - these are locations that commonly exist and
# commonly get autoindex left on by accident, not an exhaustive path list.
DIRECTORY_LISTING_PATHS = [
    '/images/', '/img/', '/uploads/', '/upload/', '/backup/', '/backups/',
    '/files/', '/assets/', '/media/', '/static/', '/tmp/', '/log/', '/logs/',
    '/data/', '/documents/', '/download/', '/downloads/', '/old/', '/archive/',
]

_DIRECTORY_LISTING_SIGNATURES = [
    re.compile(r'<title>Index of ', re.I),
    re.compile(r'<h1>Index of ', re.I),
    re.compile(r'Directory Listing -- ', re.I),  # IIS/older Apache style
    re.compile(r'\[To Parent Directory\]', re.I),  # IIS
]


def check_directory_listing(host, asset_id):
    """Probes a curated set of common directory paths for autoindex
    (directory listing) output - a misconfiguration that reveals the full
    file listing of a directory instead of a default/expected index page."""
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    found = []
    for path in DIRECTORY_LISTING_PATHS:
        resp = _http_get(base + path)
        if resp is None or resp.status_code != 200:
            continue
        if any(sig.search(resp.text[:2000]) for sig in _DIRECTORY_LISTING_SIGNATURES):
            found.append(base + path)

    if found:
        sample = ', '.join(found[:10])
        more = ' (and %s more)' % (len(found) - 10) if len(found) > 10 else ''
        issues.append(_new_issue(
            'directory-listing-found', "Directory listing (autoindex) enabled",
            "[%s] serves an autoindex directory listing at [%s] path(s): %s%s, revealing the full file listing of those directories instead of a default index page. This can expose filenames not otherwise linked from the site (backups, old versions, unpublished files)." % (host, len(found), sample, more),
            RATING_LOW, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="Disable autoindex/directory browsing for these paths (e.g. Apache 'Options -Indexes', Nginx 'autoindex off;'), and confirm nothing sensitive is reachable within them regardless."))
    else:
        issues.append(_new_issue(
            'directory-listing-none-found', "No directory listing found",
            "Checked [%s] common directory paths on [%s] for autoindex output and found none." % (len(DIRECTORY_LISTING_PATHS), host),
            RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="No action required. This checks a curated set of common paths, not an exhaustive crawl."))
    return issues
