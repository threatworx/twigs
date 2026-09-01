"""Per-host historical content discovery via the Internet Archive Wayback
CDX index: every URL (path + query string) ever archived for this host. A
real observed-URL list beats a blind path wordlist. Security-relevant paths
(admin / api / upload / backup / config / source / archive extensions and
keywords) are listed, and a bounded sample is probed to see which are still
live.
"""
import re
import logging
from urllib.parse import urlsplit

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import RATING_INFO, RATING_LOW, ISSUE_TYPE_WEB_APPLICATION, HTTP_TIMEOUT, USER_AGENT
from .util import _new_issue, _http_get, get_registered_domain

CDX_LIMIT = 15000
MAX_LISTED = 200
MAX_LIVE_PROBE = 30
CDX_TIMEOUT = max(HTTP_TIMEOUT, 30)   # web.archive.org CDX is routinely slow

# Deliberately excludes mainstream dynamic-page extensions (.php/.asp/.jsp/...)
# - too common to be signal; those are still caught by _INTERESTING_KW when the
# path itself looks sensitive.
_INTERESTING_EXT = re.compile(
    r'\.(sql|db|sqlite|bak|old|orig|save|swp|tmp|tar|gz|tgz|zip|rar|7z|log|'
    r'env|ini|conf|config|cfg|properties|pem|key|crt|p12|pfx|jks|'
    r'git|svn|htpasswd|htaccess|dockerfile|tf|tfstate|yaml|yml|dist|inc|bkp)(\?|$|/)', re.I)
_INTERESTING_KW = re.compile(
    r'(admin|adminer|/api/|graphql|swagger|openapi|actuator|/console|dashboard|/debug|/test|'
    r'staging|internal|backup|dump|export|import|/upload|/download|setup|install|/config|phpinfo|'
    r'server-status|server-info|\.git|\.svn|\.env|wp-admin|wp-json|xmlrpc|jenkins|gitlab|/jira|'
    r'password|passwd|secret|token|credential|apikey|api_key|private)', re.I)


def _cdx(host, limit):
    url = ("http://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original"
           "&collapse=urlkey&limit=%d" % (host, limit))
    r = requests.get(url, timeout=CDX_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if r.status_code != 200:
        raise RuntimeError('CDX HTTP %s' % r.status_code)
    return [ln.strip() for ln in r.text.splitlines() if ln.strip()]


def check_content_discovery(host, asset_id, args):
    if getattr(args, 'no_content_discovery', False) or not HAVE_REQUESTS:
        return []
    limit = getattr(args, 'content_discovery_limit', CDX_LIMIT) or CDX_LIMIT
    try:
        urls = _cdx(host, limit)
    except Exception as e:
        logging.warning("[EASM] content_discovery: Wayback CDX unavailable for [%s]: %s", host, e)
        return []
    if not urls:
        return []

    reg = get_registered_domain(host)
    paths = set()
    for u in urls:
        try:
            s = urlsplit(u if '://' in u else 'http://' + u)
        except ValueError:
            continue
        # CDX for a hostname can bleed in apex / sibling captures; keep anything
        # within the same registrable domain (still the same owner's surface).
        hn = (s.hostname or '').lower()
        if hn and reg and get_registered_domain(hn) != reg:
            continue
        p = s.path or '/'
        if s.query:
            p += '?' + s.query
        paths.add(p)

    interesting = sorted(p for p in paths if _INTERESTING_EXT.search(p) or _INTERESTING_KW.search(p))
    logging.info("[EASM] content_discovery: [%s] %d archived URL(s) -> %d path(s), %d of interest",
                 host, len(urls), len(paths), len(interesting))
    if not interesting:
        return []

    listed = interesting[:MAX_LISTED]
    issues = [_new_issue(
        'content-discovery-historical', "Historically archived URLs of interest (Wayback CDX)",
        "The Internet Archive holds %d archived URL(s) for [%s]; %d contain security-relevant paths, extensions, or parameters. These are endpoints that demonstrably existed and make a far better manual-review list than a blind path wordlist:\n%s"
        % (len(urls), host, len(interesting), '\n'.join(listed)),
        RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
        object_meta=','.join(listed[:50]),
        remediation="Review these paths against the live site. Any still serving administrative functionality, source, backups, config, credentials, or internal API surface should be removed or access-controlled.")]

    base = None
    for scheme in ('https', 'http'):
        if _http_get('%s://%s/' % (scheme, host)) is not None:
            base = '%s://%s' % (scheme, host)
            break
    live = []
    if base:
        for p in interesting[:MAX_LIVE_PROBE]:
            r = _http_get(base + p)
            if r is not None and r.status_code < 400 and r.status_code != 404:
                live.append('%s (HTTP %s)' % (p, r.status_code))
    if live:
        issues.append(_new_issue(
            'content-discovery-live', "Historically archived sensitive path(s) still reachable",
            "%d of the security-relevant archived path(s) for [%s] still return a non-error response:\n%s"
            % (len(live), host, '\n'.join(live)),
            RATING_LOW, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            object_meta=','.join(x.split(' ')[0] for x in live),
            remediation="Verify what each reachable path exposes and remove or authenticate anything sensitive."))
    return issues
