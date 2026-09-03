"""Firewall / WAF discovery: known WAF/CDN signatures plus a generic
probe-response-differential heuristic for unrecognized security controls.
Each recognized WAF/CDN is also added to the asset's product list (name only,
no version) so ThreatWorx's backend can map it to any known CVEs - relevant
for on-prem appliances (F5 BIG-IP, Citrix NetScaler, FortiWeb, Barracuda);
harmless for managed cloud WAFs."""
import re

from .constants import RATING_INFO, RATING_LOW, ISSUE_TYPE_FIREWALL
from .util import _new_issue, _http_get, _add_product

# WAF/CDN products whose version is sometimes recoverable, and where from.
# Managed cloud WAFs are versionless by design and are not listed.
_MODSEC_VER_RE = re.compile(r'mod[_-]?security[/ ]v?(\d+\.\d+(?:\.\d+)?)', re.I)

WAF_SIGNATURES = [
    ('Cloudflare', {'headers': ['cf-ray', 'cf-cache-status'], 'server': ['cloudflare'], 'cookies': ['__cfduid', '__cflb', 'cf_clearance']}),
    ('Akamai', {'headers': ['x-akamai-transformed'], 'server': ['akamaighost']}),
    ('Imperva Incapsula', {'headers': ['x-iinfo', 'x-cdn'], 'cookies': ['visid_incap', 'incap_ses']}),
    ('AWS WAF/CloudFront', {'headers': ['x-amzn-requestid', 'x-amz-cf-id']}),
    ('Sucuri', {'headers': ['x-sucuri-id', 'x-sucuri-cache'], 'server': ['sucuri/cloudproxy']}),
    ('F5 BIG-IP ASM', {'cookies': ['ts=', 'bigipserver', 'tsprd'], 'headers': ['x-cnection']}),
    ('Barracuda', {'cookies': ['barra_counter_session']}),
    ('Fortinet FortiWeb', {'cookies': ['fortiwafsid']}),
    ('Citrix NetScaler', {'cookies': ['ns_af', 'citrix_ns_id'], 'headers': ['via']}),
    ('ModSecurity', {'server': ['mod_security', 'modsecurity']}),
    ('Wordfence', {'headers': ['x-wordfence']}),
    ('DDoS-Guard', {'server': ['ddos-guard'], 'headers': ['x-ddos-guard']}),
    ('StackPath', {'headers': ['x-sp-waf', 'x-hw']}),
    ('Azure Front Door/WAF', {'headers': ['x-azure-ref', 'x-fd-healthprobe']}),
]

WAF_PROBE_PATH = "/?easm=1' OR '1'='1' UNION SELECT NULL-- <script>alert(1)</script>../../../etc/passwd"


def check_waf(host, asset_id, products=None):
    issues = []
    if products is None:
        products = []
    baseline = None
    probe = None
    for scheme in ('https', 'http'):
        baseline = _http_get("%s://%s/" % (scheme, host))
        if baseline is not None:
            probe = _http_get("%s://%s%s" % (scheme, host, WAF_PROBE_PATH))
            break
    if baseline is None:
        return issues

    combined_headers = {k.lower(): v.lower() for k, v in baseline.headers.items()}
    if probe is not None:
        for k, v in probe.headers.items():
            combined_headers.setdefault(k.lower(), v.lower())
    cookie_names = ' '.join(baseline.cookies.keys()).lower()
    if probe is not None:
        cookie_names += ' ' + ' '.join(probe.cookies.keys()).lower()
    server_hdr = combined_headers.get('server', '')

    detected = []
    for waf_name, sig in WAF_SIGNATURES:
        matched = False
        for hdr in sig.get('headers', []):
            if hdr in combined_headers:
                matched = True
                break
        if not matched:
            for srv in sig.get('server', []):
                if srv in server_hdr:
                    matched = True
                    break
        if not matched:
            for ck in sig.get('cookies', []):
                if ck in cookie_names:
                    matched = True
                    break
        if matched:
            detected.append(waf_name)

    if detected:
        # Add each recognized WAF/CDN to the asset's product list. Managed
        # cloud WAFs are versionless; for ModSecurity a version is sometimes
        # exposed in the Server header, so fold it in when present.
        modsec_ver = _MODSEC_VER_RE.search(server_hdr)
        product_names = []
        for name in detected:
            if name == 'ModSecurity' and modsec_ver:
                name = 'ModSecurity ' + modsec_ver.group(1)
            product_names.append(name)
            _add_product(products, name)

        issues.append(_new_issue('waf-detected', "Web Application Firewall detected",
                                  "Detected the presence of the following WAF/CDN security control(s) in front of [%s]: %s. This provides a layer of protection against common web attacks (SQLi, XSS, bad bots, volumetric abuse). Added to the asset's product list%s." % (
                                      host, ', '.join(product_names),
                                      " with a version parsed from the Server header" if (modsec_ver and 'ModSecurity' in detected) else " (name only - WAF/CDN products rarely expose a version)"),
                                  RATING_INFO, asset_id, ISSUE_TYPE_FIREWALL,
                                  remediation="This is a positive finding; no action required. Periodically verify the WAF ruleset/managed-rules are current and cover the OWASP Top 10."))
    elif probe is not None and baseline.status_code != probe.status_code and probe.status_code in (403, 406, 429, 501):
        issues.append(_new_issue('waf-generic-detected', "Possible firewall/security control detected",
                                  "A request containing common attack patterns (SQLi/XSS-style payload) returned HTTP [%s] on [%s] while a baseline request returned HTTP [%s], suggesting the presence of an unidentified WAF, reverse proxy, or security control that is not in our known-signature list." % (probe.status_code, host, baseline.status_code),
                                  RATING_INFO, asset_id, ISSUE_TYPE_FIREWALL,
                                  remediation="This is a positive finding; no action required. Confirm the control is intentional and centrally managed."))
    else:
        issues.append(_new_issue('waf-not-detected', "No Web Application Firewall detected",
                                  "No known WAF/CDN signature was observed in front of [%s], and a request containing common attack patterns was not treated any differently than a baseline request. This means the application itself is the sole line of defense against web-layer attacks (SQLi, XSS, credential stuffing, scraping, volumetric abuse)." % host,
                                  RATING_LOW, asset_id, ISSUE_TYPE_FIREWALL,
                                  remediation="Consider deploying a Web Application Firewall or CDN-based security control (e.g. Cloudflare, AWS WAF, Azure Front Door WAF, ModSecurity) in front of internet-facing applications to add a layer of defense against common web attacks and absorb volumetric/bot abuse."))
    return issues

