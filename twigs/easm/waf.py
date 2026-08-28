"""Firewall / WAF discovery: known WAF/CDN signatures plus a generic
probe-response-differential heuristic for unrecognized security controls."""
from .constants import RATING_INFO, RATING_LOW, ISSUE_TYPE_FIREWALL
from .util import _new_issue, _http_get

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


def check_waf(host, asset_id):
    issues = []
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
        issues.append(_new_issue('waf-detected', "Web Application Firewall detected",
                                  "Detected the presence of the following WAF/CDN security control(s) in front of [%s]: %s. This provides a layer of protection against common web attacks (SQLi, XSS, bad bots, volumetric abuse)." % (host, ', '.join(detected)),
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

