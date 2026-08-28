"""Technology stack discovery via HTTP headers, HTML fingerprinting, and
client-side JavaScript library detection (name + version only - reported as
products; ThreatWorx's backend handles mapping products to known CVEs, so
this module doesn't attempt any vulnerability correlation of its own).

Also covers two smaller checks that piggyback on the same page fetch/parse:
mixed content (HTTP resources loaded from an HTTPS page) and favicon hash
fingerprinting (a Shodan/Censys-style mmh3 hash of the favicon, useful for
correlating infrastructure or matching known phishing-kit/C2 panel
templates - reported as an asset tag, not a vulnerability finding)."""
import re
import base64
import logging
from urllib.parse import urljoin, urlparse

import requests

try:
    import builtwith
    HAVE_BUILTWITH = True
except ImportError:
    HAVE_BUILTWITH = False

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import mmh3
    HAVE_MMH3 = True
except ImportError:
    HAVE_MMH3 = False

from .constants import RATING_INFO, RATING_LOW, ISSUE_TYPE_WEB_APPLICATION, HTTP_TIMEOUT, USER_AGENT
from .util import _add_product, _new_issue, _http_get

# Generic CDN URL conventions: <cdn>/.../<package>[@/]<version>/... - these
# alone cover a large fraction of real-world sites, since they're the
# dominant public CDNs for JS libraries, without needing per-library
# signatures.
CDN_URL_PATTERNS = [
    re.compile(r'cdn\.jsdelivr\.net/npm/([a-zA-Z0-9_.\-]+)@(\d+\.\d+\.\d+[\w.\-]*)'),
    re.compile(r'cdn\.jsdelivr\.net/gh/[a-zA-Z0-9_.\-]+/([a-zA-Z0-9_.\-]+)@(\d+\.\d+\.\d+[\w.\-]*)'),
    re.compile(r'cdnjs\.cloudflare\.com/ajax/libs/([a-zA-Z0-9_.\-]+)/(\d+\.\d+\.\d+[\w.\-]*)'),
    re.compile(r'unpkg\.com/([a-zA-Z0-9_.\-]+)@(\d+\.\d+\.\d+[\w.\-]*)'),
    re.compile(r'ajax\.googleapis\.com/ajax/libs/([a-zA-Z0-9_.\-]+)/(\d+\.\d+\.\d+[\w.\-]*)'),
]

# Self-hosted-filename patterns for common libraries, used when a script
# isn't loaded from a recognized CDN (e.g. "/assets/js/jquery-3.6.0.min.js").
JS_FILENAME_PATTERNS = [
    ('jquery-ui', re.compile(r'jquery-ui[.\-](\d+\.\d+\.\d+)', re.I)),
    ('jquery', re.compile(r'jquery[.\-](\d+\.\d+\.\d+)', re.I)),
    ('bootstrap', re.compile(r'bootstrap[.\-](\d+\.\d+\.\d+)', re.I)),
    ('angular', re.compile(r'angular[.\-](\d+\.\d+\.\d+)', re.I)),
    ('vue', re.compile(r'vue[.\-](\d+\.\d+\.\d+)', re.I)),
    ('react', re.compile(r'react[.\-](\d+\.\d+\.\d+)', re.I)),
    ('lodash', re.compile(r'lodash[.\-](\d+\.\d+\.\d+)', re.I)),
    ('moment', re.compile(r'moment[.\-](\d+\.\d+\.\d+)', re.I)),
    ('modernizr', re.compile(r'modernizr[.\-](\d+\.\d+\.\d+)', re.I)),
    ('handlebars', re.compile(r'handlebars[.\-](\d+\.\d+\.\d+)', re.I)),
    ('underscore', re.compile(r'underscore[.\-](\d+\.\d+\.\d+)', re.I)),
    ('backbone', re.compile(r'backbone[.\-](\d+\.\d+\.\d+)', re.I)),
    ('popper', re.compile(r'popper(?:\.js)?[@.\-](\d+\.\d+\.\d+)', re.I)),
    ('chart.js', re.compile(r'chart(?:\.js)?[.\-](\d+\.\d+\.\d+)', re.I)),
    ('d3', re.compile(r'\bd3[.\-]v?(\d+\.\d+\.\d+)', re.I)),
]

# Content-banner patterns, used only as a fallback for scripts whose URL
# didn't reveal a version (e.g. a generic bundle name like "main.js"). Only a
# bounded number of such scripts are fetched per host (MAX_JS_CONTENT_FETCHES
# below), and only their first few KB - version banners are always near the
# top of the file in every convention seen here.
JS_CONTENT_PATTERNS = [
    ('jquery', re.compile(r'jQuery\s+v(\d+\.\d+\.\d+)')),
    ('jquery', re.compile(r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+[\w.\-]*)["\']')),
    ('bootstrap', re.compile(r'Bootstrap\s+v(\d+\.\d+\.\d+)')),
    ('angular', re.compile(r'AngularJS v(\d+\.\d+\.\d+)')),
    ('vue', re.compile(r'Vue\.js v(\d+\.\d+\.\d+)')),
    ('vue', re.compile(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+[\w.\-]*)["\']')),
    ('react', re.compile(r'React\s+v(\d+\.\d+\.\d+)')),
    ('lodash', re.compile(r'[Ll]odash[^0-9]{0,20}(\d+\.\d+\.\d+)')),
    ('moment', re.compile(r'moment\.version\s*=\s*["\'](\d+\.\d+\.\d+[\w.\-]*)["\']')),
    ('underscore', re.compile(r'Underscore\.js (\d+\.\d+\.\d+)')),
    ('backbone', re.compile(r'Backbone\.js (\d+\.\d+\.\d+)')),
    ('handlebars', re.compile(r'Handlebars v(\d+\.\d+\.\d+)')),
    ('modernizr', re.compile(r'Modernizr (\d+\.\d+\.\d+)')),
    ('chart.js', re.compile(r'Chart\.js v(\d+\.\d+\.\d+)')),
]

# Bound on how many scripts we'll fetch content for per host - most scripts
# resolve via the free CDN-URL/filename patterns above with no extra
# request; this only covers the remainder (e.g. an app's own bundle).
MAX_JS_CONTENT_FETCHES = 6


def _fetch_js_prefix(url, max_bytes=8192):
    """Fetches only the first few KB of a script - enough to catch a version
    banner comment - without downloading a potentially large minified bundle
    in full."""
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False, stream=True,
                             headers={'User-Agent': USER_AGENT})
        if resp.status_code != 200:
            resp.close()
            return None
        chunk = next(resp.iter_content(chunk_size=max_bytes), b'')
        resp.close()
        return chunk.decode('utf-8', errors='replace')
    except requests.exceptions.RequestException:
        return None


def _detect_js_libraries(html, base_url, products):
    if not HAVE_BS4:
        return
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception as e:
        logging.debug("HTML parsing error for [%s]: %s", base_url, str(e))
        return

    unresolved = []
    for script in soup.find_all('script'):
        src = script.get('src')
        if not src:
            continue
        abs_url = urljoin(base_url, src)
        matched = False
        for pattern in CDN_URL_PATTERNS:
            m = pattern.search(abs_url)
            if m:
                _add_product(products, '%s %s' % (m.group(1).lower(), m.group(2)))
                matched = True
                break
        if matched:
            continue
        for name, pattern in JS_FILENAME_PATTERNS:
            m = pattern.search(abs_url)
            if m:
                _add_product(products, '%s %s' % (name, m.group(1)))
                matched = True
                break
        if not matched:
            unresolved.append(abs_url)

    for url in unresolved[:MAX_JS_CONTENT_FETCHES]:
        content = _fetch_js_prefix(url)
        if not content:
            continue
        for name, pattern in JS_CONTENT_PATTERNS:
            m = pattern.search(content)
            if m:
                _add_product(products, '%s %s' % (name, m.group(1)))
                break


def _check_sri(html, base_url, host, asset_id):
    """Subresource Integrity: cross-origin (CDN-hosted) <script>/<link
    rel=stylesheet> tags should carry an integrity= hash, so a compromised
    CDN can't silently serve tampered content to the page. Only meaningful
    for cross-origin resources - same-origin ones are already implicitly
    trusted since the site operator serves them directly."""
    if not HAVE_BS4:
        return []
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return []

    missing = []
    for tag_name, attr in (('script', 'src'), ('link', 'href')):
        for el in soup.find_all(tag_name):
            if tag_name == 'link':
                rel = el.get('rel') or []
                if isinstance(rel, str):
                    rel = [rel]
                if 'stylesheet' not in [r.lower() for r in rel]:
                    continue
            url = el.get(attr)
            if not url:
                continue
            abs_url = urljoin(base_url, url)
            parsed = urlparse(abs_url)
            if parsed.netloc and parsed.netloc.lower() != host.lower() and not el.get('integrity'):
                missing.append(abs_url)

    if not missing:
        return []
    sample = ', '.join(missing[:10])
    more = ' (and %s more)' % (len(missing) - 10) if len(missing) > 10 else ''
    return [_new_issue(
        'sri-missing', "Cross-origin scripts/stylesheets missing Subresource Integrity",
        "[%s] loads [%s] cross-origin script/stylesheet resource(s) without a Subresource Integrity (integrity=) attribute: %s%s. If any of these third-party/CDN hosts is compromised, they could silently serve modified content that executes in the context of this site." % (host, len(missing), sample, more),
        RATING_LOW, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
        remediation="Add integrity= (and crossorigin=\"anonymous\") attributes to cross-origin <script>/<link> tags. Most CDNs (jsDelivr, cdnjs, unpkg) publish the correct integrity hash alongside each file version.")]


def _check_mixed_content(html, base_url, host, asset_id):
    """Only meaningful when the page itself was served over HTTPS - flags
    active/passive-content elements (script/link/iframe src or href, plus
    img/audio/video/source src) pointed at a plain http:// URL. Browsers
    block active mixed content (scripts, stylesheets, iframes) outright in
    most cases, but still load passive content (images/media) with a
    "not secure" warning and no request-level protection."""
    if not HAVE_BS4 or not base_url.startswith('https://'):
        return []
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return []

    active, passive = [], []
    active_tags = (('script', 'src'), ('link', 'href'), ('iframe', 'src'))
    passive_tags = (('img', 'src'), ('audio', 'src'), ('video', 'src'), ('source', 'src'))
    for tag_name, attr in active_tags + passive_tags:
        for el in soup.find_all(tag_name):
            url = el.get(attr)
            if not url or url.strip().lower().startswith('//'):
                continue  # protocol-relative URLs inherit the page's own scheme, not mixed content
            abs_url = urljoin(base_url, url)
            if abs_url.lower().startswith('http://'):
                (active if (tag_name, attr) in active_tags else passive).append(abs_url)

    if not active and not passive:
        return []
    bits = []
    if active:
        sample = ', '.join(active[:10])
        more = ' (and %s more)' % (len(active) - 10) if len(active) > 10 else ''
        bits.append("[%s] active resource(s) (script/stylesheet/iframe): %s%s" % (len(active), sample, more))
    if passive:
        sample = ', '.join(passive[:10])
        more = ' (and %s more)' % (len(passive) - 10) if len(passive) > 10 else ''
        bits.append("[%s] passive resource(s) (image/audio/video): %s%s" % (len(passive), sample, more))
    rating = RATING_LOW if active else RATING_INFO
    return [_new_issue(
        'mixed-content-found', "Mixed content: HTTP resources loaded on an HTTPS page",
        "[%s] is served over HTTPS but loads the following over plain HTTP: %s. Most modern browsers block active mixed content outright (so this may already be broken for visitors) and show a \"not secure\" warning for passive mixed content; either way it can be intercepted/tampered with by a network attacker." % (host, '; '.join(bits)),
        rating, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
        remediation="Change these resource URLs to https:// (or protocol-relative //), including any hardcoded in a CMS database/template rather than just the HTML source.")]


def _get_favicon_hash(html, base_url):
    """Computes a Shodan/Censys-compatible favicon hash: base64-encode the
    raw bytes with a newline inserted every 76 characters (Python's
    base64.encodebytes default, matching the mmh3-hashed convention those
    tools use), then take the signed 32-bit MurmurHash3 of that string. Used
    purely for infrastructure correlation (e.g. cross-referencing against a
    favicon-hash search engine) - not a vulnerability finding on its own, so
    it's reported as a tag rather than a config issue."""
    if not HAVE_MMH3:
        return None
    href = '/favicon.ico'
    if HAVE_BS4:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            link = soup.find('link', rel=re.compile('icon', re.I))
            if link and link.get('href'):
                href = link.get('href')
        except Exception:
            pass
    favicon_url = urljoin(base_url, href)
    try:
        resp = requests.get(favicon_url, timeout=HTTP_TIMEOUT, verify=False,
                             headers={'User-Agent': USER_AGENT})
        if resp.status_code != 200 or not resp.content:
            return None
        encoded = base64.encodebytes(resp.content)
        return mmh3.hash(encoded)
    except requests.exceptions.RequestException:
        return None
    except Exception as e:
        logging.debug("Favicon hashing failed for [%s]: %s", favicon_url, str(e))
        return None


def check_tech_stack(host, products, tags, asset_id):
    resp = None
    used_url = None
    for scheme in ('https', 'http'):
        url = "%s://%s/" % (scheme, host)
        resp = _http_get(url)
        if resp is not None:
            used_url = url
            break
    if resp is None:
        return []

    server_hdr = resp.headers.get('Server')
    if server_hdr:
        for tok in server_hdr.split(','):
            tok = tok.strip().replace('/', ' ').strip()
            if tok:
                _add_product(products, tok)
    powered_by = resp.headers.get('X-Powered-By')
    if powered_by:
        _add_product(products, powered_by.strip())
    if HAVE_BS4:
        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
            meta = soup.find('meta', attrs={'name': re.compile('generator', re.I)})
            if meta and meta.get('content'):
                _add_product(products, meta.get('content').strip())
        except Exception as e:
            logging.debug("HTML parsing error for [%s]: %s", used_url, str(e))

    if HAVE_BUILTWITH:
        try:
            techs = builtwith.builtwith(used_url, headers=dict(resp.headers), html=resp.text)
            for category, names in techs.items():
                for name in names:
                    _add_product(products, name)
        except Exception as e:
            logging.debug("builtwith detection failed for [%s]: %s", used_url, str(e))

    _detect_js_libraries(resp.text, used_url, products)

    favicon_hash = _get_favicon_hash(resp.text, used_url)
    if favicon_hash is not None:
        tag = 'FAVICON_HASH:%s' % favicon_hash
        if tag not in tags:
            tags.append(tag)

    issues = _check_sri(resp.text, used_url, host, asset_id)
    issues.extend(_check_mixed_content(resp.text, used_url, host, asset_id))
    return issues
