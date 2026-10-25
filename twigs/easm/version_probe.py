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

Also home to check_php2shell, which compares the discovered PHP interpreter
version against the php2shell (CVE-2026-109618 / CVE-2026-109619) fixed
releases and reports each CVE as a HIGH finding with remediation.
"""
import re
import logging

from .constants import RATING_INFO, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_WEB_APPLICATION
from .util import _http_get, _new_issue, _add_product
from .tech_stack import PHP_BUILD_TAG

_HAS_VERSION = re.compile(r'\d+\.\d+')
_PHPINFO_RE = re.compile(r'<h1 class="p">\s*PHP Version\s+(\d+\.\d+\.\d+)', re.I)
PHPINFO_PATHS = ['/phpinfo.php', '/info.php']

# A PHP interpreter product, e.g. 'PHP', 'PHP 8.3.10', or a Server-header token
# like 'Apache 2.4.41 (Ubuntu) PHP 7.4.3'. The separator keeps phpMyAdmin out.
_PHP_PRODUCT_RE = re.compile(r'(?:^|\s)PHP(?:[ /](\d+)\.(\d+)(?:\.(\d+))?)?(?:\s|$|[-+~])', re.I)

# php2shell (disclosed 2026-10-21, CVSS v4.0 9.2, unauthenticated RCE in the
# interpreter on every web SAPI - mod_php, PHP-FPM, php-cgi, FrankenPHP,
# LiteSpeed). First fixed patch release per supported branch; 5.4 - 8.1 are
# affected and end-of-life (source backports only for 7.4 - 8.1).
PHP2SHELL_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PHP2SHELL_EOL_AFFECTED = ((5, 4), (8, 1))
PHP2SHELL_CVES = [
    ('CVE-2026-109618', "memory corruption in request start-up when an allocation fails (out-of-memory) while parsing crafted form-encoded / multipart request bodies",
     "set memory_limit=-1 in php.ini or a php_admin_value (not overridable by the application), paired with a front-end request body size limit (Apache LimitRequestBody / nginx client_max_body_size) and a container/cgroup memory limit. Do not use RLIMIT_AS/RLIMIT_DATA for this."),
    ('CVE-2026-109619', "use-after-free of stale per-request state reused by a later request on the same worker (session upload-progress handling, and fatal-error backtraces on PHP 8.5), also allowing memory disclosure",
     "set session.upload_progress.enabled=0 and, on PHP 8.5, fatal_error_backtraces=0 in php.ini (configuration loaded before request parsing, not ini_set())."),
]


def _php_version(products):
    """(found, (major, minor, patch-or-None) or None) for the PHP interpreter
    in the product list; found=True with no version means PHP is in use but
    its version is not disclosed."""
    found = False
    for p in products:
        m = _PHP_PRODUCT_RE.search(p)
        if not m:
            continue
        found = True
        if m.group(1):
            return True, (int(m.group(1)), int(m.group(2)), int(m.group(3)) if m.group(3) else None)
    return found, None


def _php2shell_status(ver):
    """'affected', 'eol-affected', 'fixed', 'not-affected' or 'undetermined'."""
    branch = ver[:2]
    if branch in PHP2SHELL_FIXED:
        if ver[2] is None:
            return 'undetermined'
        return 'affected' if ver[2] < PHP2SHELL_FIXED[branch] else 'fixed'
    lo, hi = PHP2SHELL_EOL_AFFECTED
    if lo <= branch <= hi:
        return 'eol-affected'
    return 'not-affected'


def _phpinfo_version(host):
    """PHP version from a publicly exposed phpinfo() page, or None."""
    for scheme in ('https', 'http'):
        for path in PHPINFO_PATHS:
            r = _http_get('%s://%s%s' % (scheme, host, path))
            m = _PHPINFO_RE.search((r.text or '')[:20000]) if r is not None and r.status_code == 200 else None
            if m:
                return m.group(1)
    return None


def check_php2shell(host, products, tags, asset_id, args):
    """Reports CVE-2026-109618 / CVE-2026-109619 (php2shell) against the PHP
    interpreter version found by product discovery. Version based only - no
    exploit traffic is sent."""
    found, ver = _php_version(products)
    if not found:
        return []
    # PHP seen but version incomplete: try phpinfo() ourselves when
    # probe_product_versions hasn't already (it is off in --quick mode, and it
    # only enriches a bare 'PHP', not a 'PHP 8.3' missing its patch level)
    if (ver is None and getattr(args, 'no_version_probe', False)) or (ver is not None and ver[2] is None):
        info_ver = _phpinfo_version(host)
        if info_ver:
            bare = [i for i, p in enumerate(products) if p.strip().lower() == 'php']
            if bare:
                products[bare[0]] = 'PHP ' + info_ver
            found, ver = True, tuple(int(x) for x in info_ver.split('.'))
    cves = [c for c, _, _ in PHP2SHELL_CVES]
    build = next((t[len(PHP_BUILD_TAG):] for t in tags if t.startswith(PHP_BUILD_TAG)), None)
    status = _php2shell_status(ver) if ver else 'undetermined'
    verstr = '.'.join(str(v) for v in ver if v is not None) if ver else None

    if verstr:
        # PHP may only have been seen inside another product string (e.g. an
        # nmap / Server-header token) - make sure the asset lists it on its own
        _add_product(products, 'PHP ' + verstr)
    if status in ('not-affected', 'fixed'):
        return []

    if status == 'undetermined':
        what = ("PHP %s (no patch level disclosed)" % verstr) if verstr else "PHP (version not disclosed - e.g. expose_php=Off, detected from the PHPSESSID cookie)"
        return [_new_issue(
            'php-php2shell-undetermined', "PHP in use - php2shell exposure (CVE-2026-109618 / CVE-2026-109619) cannot be ruled out",
            "Host [%s] runs %s. The exact version could not be determined remotely, so it is unknown whether the critical unauthenticated RCE vulnerabilities CVE-2026-109618 and CVE-2026-109619 (php2shell, CVSS v4.0 9.2, exploited in the wild) are fixed. A hidden version is not a patched one." % (host, what),
            RATING_MEDIUM, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host, cve=cves,
            remediation="Confirm the PHP version used by the web server (phpinfo() or php-fpm -v / the Apache module, not just the CLI binary) and make sure it is 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later, or a vendor package carrying the fix. If not, follow the remediation for the CVE-2026-109618 / CVE-2026-109619 findings: upgrade, restart all workers, and apply the interim ini mitigations until patched.")]

    if status == 'eol-affected':
        target = "upgrade to a supported branch (8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later). PHP %d.%d is end-of-life: PHP 7.4 - 8.1 only have minimal source backports from the PHP security team, and 5.4 - 7.3 have no upstream fix, so only a supported branch or a vendor/LTS-patched package (with its advisory confirming the fix) resolves this" % ver[:2]
    else:
        target = "upgrade to PHP %d.%d.%d or later (fixed releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12)" % (ver[0], ver[1], PHP2SHELL_FIXED[ver[:2]])
    banner = verstr + (' (build %s)' % build if build else '')
    backport = (" The version banner carries a distribution build suffix [%s]: the vendor may have backported the fix without changing the upstream version, so confirm against the vendor's advisory for that exact package before closing this finding." % build) if build else ""

    issues = []
    for cve, flaw, interim in PHP2SHELL_CVES:
        issues.append(_new_issue(
            'php-%s' % cve.lower(), "PHP vulnerable to %s (php2shell unauthenticated RCE)" % cve,
            "Host [%s] reports PHP %s, which is affected by %s: %s. Disclosed 2026-10-21 alongside its companion php2shell CVE, it is rated CVSS v4.0 9.2 and lets an unauthenticated remote attacker execute code as the web server/PHP worker user. Every SAPI that serves HTTP is in scope (mod_php - highest risk, as the flaw is reached before any application code runs - PHP-FPM, php-cgi, FrankenPHP, LiteSpeed), default configurations are vulnerable, and exploitation has been observed in the wild.%s"
            % (host, banner, cve, flaw, backport),
            RATING_HIGH, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host, object_meta='PHP ' + banner, cve=[cve],
            remediation=(
                "1) Patch: %s. For OS packages apply the vendor's PHP security update (Ubuntu/Debian/RHEL/SUSE, Remi, Sury PPA, hosting panels); rebuild and redeploy container images based on affected php:* images; separately update self-compiled or application-bundled interpreters. Updating Composer dependencies does not fix this. "
                "2) Restart or replace every PHP worker (php-fpm, Apache with mod_php, LiteSpeed, FrankenPHP) - an upgraded package is not in effect until the old processes are gone. "
                "3) Interim mitigation until patched (reduces exposure, does not fix it): %s Restart workers after the change. Size-based WAF rules alone do not help; vendor WAF rules for the known vectors and restricting public access to the application are stop-gaps. "
                "4) Verify via the web SAPI (phpinfo() or the FPM/Apache module version, not the CLI php -v) and re-scan; review PHP/web server error logs for unexplained memory-exhaustion fatals and worker segmentation faults since mid-October 2026, and investigate any unexpected process launched by the web server user. "
                "5) After patching, set expose_php=Off and remove phpinfo() pages so the interpreter version is not disclosed.")
                % (target, interim)))
    return issues

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
    ('php',           '/phpinfo.php',       _PHPINFO_RE),
    ('php',           '/info.php',          _PHPINFO_RE),

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
            # whole-word match, so e.g. the 'php' probes never fire for phpmyadmin
            if not re.search(r'\b%s\b' % re.escape(needle), key):
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
