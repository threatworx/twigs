"""Best-effort version extraction for products that tech_stack detected
without a version. Runs a small curated set of version-disclosure probes
(well-known files / status endpoints per product) and folds any recovered
version back into the product list, so the backend CVE mapping is
version-accurate. Never removes a product; only enriches 'name' -> 'name
X.Y.Z'.
"""
import re
import logging

from .constants import RATING_INFO, ISSUE_TYPE_WEB_APPLICATION
from .util import _http_get, _new_issue

_HAS_VERSION = re.compile(r'\d+\.\d+')

# product-name substring -> (path, compiled regex capturing the version).
# The regex is matched against the response body and (joined) headers.
_PROBES = [
    ('tomcat',        '/RELEASE-NOTES.txt', re.compile(r'Apache Tomcat Version\s+([\d.]+)', re.I)),
    ('jenkins',       '/login',             re.compile(r'Jenkins ver\.?\s*([\d.]+)', re.I)),
    ('drupal',        '/CHANGELOG.txt',     re.compile(r'Drupal\s+([\d.]+),', re.I)),
    ('joomla',        '/administrator/manifests/files/joomla.xml', re.compile(r'<version>\s*([\d.]+)\s*</version>', re.I)),
    ('grafana',       '/api/health',        re.compile(r'"version"\s*:\s*"([^"]+)"')),
    ('gitlab',        '/help',              re.compile(r'GitLab\s+(?:Community|Enterprise)\s+Edition\s+([\d.]+)', re.I)),
    ('phpmyadmin',    '/README',            re.compile(r'Version\s+([\d.]+)', re.I)),
    ('kibana',        '/api/status',        re.compile(r'"number"\s*:\s*"([^"]+)"')),
    ('elasticsearch', '/',                  re.compile(r'"number"\s*:\s*"([^"]+)"')),
    ('wordpress',     '/feed/',             re.compile(r'wordpress\.org/\?v=([\d.]+)', re.I)),
    ('nginx',         '/',                  re.compile(r'nginx/([\d.]+)', re.I)),
    ('apache',        '/',                  re.compile(r'Apache/([\d.]+)', re.I)),
    ('openssl',       '/',                  re.compile(r'OpenSSL/([\w.]+)', re.I)),
    ('php',           '/',                  re.compile(r'PHP/([\w.]+)', re.I)),
]


def _bare_products(products):
    """lowercased bare name -> index, for product entries with no version."""
    out = {}
    for i, p in enumerate(products):
        if not _HAS_VERSION.search(p):
            out.setdefault(p.strip().lower(), i)
    return out


def probe_product_versions(host, products, asset_id, args):
    if getattr(args, 'no_version_probe', False) or not products:
        return []
    bare = _bare_products(products)
    if not bare:
        return []

    root = None
    for scheme in ('https', 'http'):
        if _http_get('%s://%s/' % (scheme, host)) is not None:
            root = '%s://%s' % (scheme, host)
            break
    if root is None:
        return []

    fetched = {}
    enriched = []
    for key, idx in bare.items():
        for needle, path, rx in _PROBES:
            if needle not in key:
                continue
            if path not in fetched:
                fetched[path] = _http_get(root + path)
            r = fetched[path]
            if r is None:
                continue
            hay = (r.text or '')[:20000] + '\n' + '\n'.join('%s: %s' % (k, v) for k, v in r.headers.items())
            m = rx.search(hay)
            if m:
                ver = m.group(1).strip()
                newname = '%s %s' % (products[idx], ver)
                if newname != products[idx] and not _HAS_VERSION.search(products[idx]):
                    enriched.append((products[idx], newname))
                    products[idx] = newname
                break

    if not enriched:
        return []
    logging.info("[EASM] version_probe: recovered %d product version(s) on [%s]", len(enriched), host)
    return [_new_issue(
        'tech-version-recovered', "Software version(s) recovered via version-disclosure endpoints",
        "Recovered a version for %d product(s) initially detected without one, via known version-disclosure endpoints (improves CVE-mapping accuracy): %s."
        % (len(enriched), '; '.join('%s -> %s' % (a, b) for a, b in enriched)),
        RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
        remediation="Informational for inventory accuracy. Separately, exposing precise version numbers (CHANGELOG.txt / RELEASE-NOTES.txt / verbose Server headers / status endpoints) assists attackers - suppress these where practical.")]
