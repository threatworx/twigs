"""Best-effort version extraction for products that tech_stack (or the
firewall/WAF check) detected without a version. Runs a small curated set of
version-disclosure probes (well-known files / status endpoints per product)
and folds any recovered version back into the product list, so the backend
CVE mapping is version-accurate. Never removes a product; only enriches
'name' -> 'name X.Y.Z'.

Covers the common web stack (Tomcat, Jenkins, Drupal, Joomla, Grafana,
GitLab, phpMyAdmin, Kibana, Elasticsearch, WordPress, nginx, Apache, OpenSSL,
PHP) plus the WAF/CDN products where a version can leak (ModSecurity via the
Server header, Wordfence via its WordPress-plugin readme, and - best effort -
F5 BIG-IP ASM / Citrix NetScaler-ADC / Fortinet FortiWeb / Barracuda WAF via
their appliance login pages). Managed cloud WAF/CDNs are versionless by
design and are not probed.
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

    # --- WAF / CDN -----------------------------------------------------------
    # Managed cloud WAF/CDN products - Cloudflare, Akamai, AWS WAF/CloudFront,
    # Imperva Incapsula (cloud), Sucuri, StackPath, DDoS-Guard, Azure Front
    # Door/WAF - are continuously-deployed SaaS with no customer-visible
    # version and no customer CVE surface, so there is deliberately nothing to
    # probe for them. The entries below cover the WAF products where a version
    # can actually leak:
    #   * ModSecurity  - version token in the Server header (older/default cfg)
    #   * Wordfence    - it is a WordPress plugin; exact version in its readme
    #   * F5 BIG-IP ASM / Citrix NetScaler-ADC / Fortinet FortiWeb / Barracuda
    #     WAF - best effort only: a build string on the appliance's own
    #     login/admin page, if one is exposed. A probe that matches nothing
    #     simply leaves the product name unchanged (no false positive).
    ('modsecurity',   '/',
     re.compile(r'mod[_ -]?security[/ ]v?(\d+\.\d+(?:\.\d+)?)', re.I)),
    ('wordfence',     '/wp-content/plugins/wordfence/readme.txt',
     re.compile(r'Stable tag:\s*(\d+\.\d+(?:\.\d+)*)', re.I)),
    ('f5 big-ip',     '/tmui/login.jsp',
     re.compile(r'BIG-?IP[^\d]{0,20}(\d+\.\d+(?:\.\d+){0,2})', re.I)),
    ('netscaler',     '/logon/LogonPoint/index.html',
     re.compile(r'(?:Citrix ADC|NetScaler(?:\s+Gateway)?|\bNS)[^\d]{0,15}(\d+\.\d+)', re.I)),
    ('netscaler',     '/vpn/index.html',
     re.compile(r'(?:Citrix ADC|NetScaler(?:\s+Gateway)?|\bNS)[^\d]{0,15}(\d+\.\d+)', re.I)),
    ('fortiweb',      '/login',
     re.compile(r'Forti(?:Web|Gate|OS)[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)', re.I)),
    ('fortiweb',      '/remote/login',
     re.compile(r'Forti(?:Web|Gate|OS)[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)', re.I)),
    ('barracuda',     '/',
     re.compile(r'Barracuda[^\n]{0,60}?(?:version|release|\bv)\s*(\d+\.\d+(?:\.\d+)*)', re.I)),
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
