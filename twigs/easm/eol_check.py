"""End-of-life (EOL) software detection.

Matches the products already discovered for a host (nmap service/CPE
strings, Server / X-Powered-By headers, HTML generator tags, JS library
detection, version-disclosure probes) and the Windows build / OS evidence
parsed from nmap (NTLM Product_Version, smb-os-discovery, OS fingerprint)
against a bundled lifecycle table, and raises one finding per end-of-life
product release on the host.

This runs inside twigs so EOL findings do not depend on the backend's
product -> lifecycle mapping. Design rules, to keep findings reliable:

  * A finding is raised only when EVERY release the evidence could mean is
    past its end date. E.g. NTLM build 6.3.9600 is Windows Server 2012 R2 or
    Windows 8.1 - both EOL, so it is reported; IIS 10.0 is Server 2016-2025 /
    Windows 10/11 - not all EOL, so it is not. Unknown releases or a missing
    version never produce a finding.
  * Severity reflects how final the end of support is: HIGH once vendor
    support and any paid extended security updates (ESU) are over, MEDIUM
    while a paid ESU programme could still be covering the system, LOW for
    a release whose support ends within APPROACHING_DAYS.
  * A distribution build marker (Ubuntu, Debian, CentOS/RHEL "el7", "-fips",
    the PHP_BUILD: tag, ...) lowers the severity one level and says so: the
    distribution may still backport fixes to an upstream-EOL version.
  * Evidence that is only an nmap OS-fingerprint guess is capped at MEDIUM.
  * Per-product caps (client-side JS libraries, nginx branches which have no
    formal vendor EOL) keep those at MEDIUM or below.

The lifecycle table below is maintained by hand. Dates are the vendor's
final security-support date (Microsoft: end of extended support; ESU: end
of the last paid Extended Security Updates year). Sources: Microsoft
Lifecycle Policy, php.net/supported-versions, httpd.apache.org,
tomcat.apache.org, openssl-library.org/policies/releasestrat, nginx.org,
endoflife.date. A release whose end date is not yet published is listed
with None and is never reported.
"""
import re
import logging
from datetime import date, timedelta

from .constants import RATING_LOW, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_EOL
from .tech_stack import PHP_BUILD_TAG
from .util import _new_issue

APPROACHING_DAYS = 90

D = date


# ---------------------------------------------------------------------------
# Lifecycle data: family -> {cycle: (label, eol, esu_end)}
# ---------------------------------------------------------------------------

WINDOWS_CYCLES = {
    'server-2000':     ('Windows 2000 Server', D(2010, 7, 13), None),
    'server-2003':     ('Windows Server 2003', D(2015, 7, 14), None),
    'server-2003r2':   ('Windows Server 2003 R2', D(2015, 7, 14), None),
    'server-2008':     ('Windows Server 2008', D(2020, 1, 14), D(2024, 1, 9)),
    'server-2008r2':   ('Windows Server 2008 R2', D(2020, 1, 14), D(2024, 1, 9)),
    'server-2012':     ('Windows Server 2012', D(2023, 10, 10), D(2026, 10, 13)),
    'server-2012r2':   ('Windows Server 2012 R2', D(2023, 10, 10), D(2026, 10, 13)),
    'server-2016':     ('Windows Server 2016', D(2027, 1, 12), None),
    'server-2019':     ('Windows Server 2019', D(2029, 1, 9), None),
    'server-2022':     ('Windows Server 2022', D(2031, 10, 14), None),
    'server-2025':     ('Windows Server 2025', D(2034, 10, 10), None),
    'xp':              ('Windows XP', D(2014, 4, 8), None),
    'vista':           ('Windows Vista', D(2017, 4, 11), None),
    '7':               ('Windows 7', D(2020, 1, 14), D(2023, 1, 10)),
    '8':               ('Windows 8', D(2016, 1, 12), None),
    '8.1':             ('Windows 8.1', D(2023, 1, 10), None),
    '10-1507':         ('Windows 10 1507 (LTSB 2015)', D(2025, 10, 14), None),
    '10-1607':         ('Windows 10 1607 (LTSB 2016)', D(2026, 10, 13), None),
    '10-1809':         ('Windows 10 1809 (LTSC 2019)', D(2029, 1, 9), None),
    '10-sac':          ('Windows 10 (pre-22H2 release)', D(2023, 5, 9), None),
    '10-ltsc2021':     ('Windows 10 Enterprise LTSC 2021', D(2027, 1, 12), None),
    '10-iot-ltsc2021': ('Windows 10 IoT Enterprise LTSC 2021', D(2032, 1, 13), None),
    '10-22h2':         ('Windows 10 22H2', D(2025, 10, 14), D(2028, 10, 10)),
    '11-21h2':         ('Windows 11 21H2', D(2024, 10, 8), None),
    '11-22h2':         ('Windows 11 22H2', D(2025, 10, 14), None),
    '11-23h2':         ('Windows 11 23H2', D(2026, 11, 10), None),
    '11-24h2':         ('Windows 11 24H2', D(2027, 10, 12), None),
    '11-ltsc2024':     ('Windows 11 Enterprise LTSC 2024', D(2029, 10, 9), None),
    '11-25h2':         ('Windows 11 25H2', None, None),
}

# NT build number (the third field of NTLM Product_Version / smb-os-discovery)
# -> every Windows release that shares it.
WINDOWS_BUILDS = {
    2195: ['server-2000'],
    2600: ['xp'],
    3790: ['server-2003', 'server-2003r2', 'xp'],
    6000: ['vista'],
    6001: ['server-2008', 'vista'],
    6002: ['server-2008', 'vista'],
    6003: ['server-2008', 'vista'],
    7600: ['server-2008r2', '7'],
    7601: ['server-2008r2', '7'],
    9200: ['server-2012', '8'],
    9600: ['server-2012r2', '8.1'],
    10240: ['10-1507'],
    10586: ['10-sac'],
    14393: ['server-2016', '10-1607'],
    15063: ['10-sac'],
    16299: ['10-sac'],
    17134: ['10-sac'],
    17763: ['server-2019', '10-1809'],
    18362: ['10-sac'],
    18363: ['10-sac'],
    19041: ['10-sac'],
    19042: ['10-sac'],
    19043: ['10-sac'],
    19044: ['10-ltsc2021', '10-iot-ltsc2021'],
    19045: ['10-22h2'],
    20348: ['server-2022'],
    22000: ['11-21h2'],
    22621: ['11-22h2'],
    22631: ['11-23h2'],
    26100: ['server-2025', '11-24h2', '11-ltsc2024'],
    26200: ['11-25h2'],
}

_SERVER_ORDER = ['server-2000', 'server-2003', 'server-2003r2', 'server-2008', 'server-2008r2',
                 'server-2012', 'server-2012r2', 'server-2016', 'server-2019', 'server-2022', 'server-2025']
_CLIENT_ORDER = ['xp', 'vista', '7', '8', '8.1', '10', '11']
_CLIENT_EXPAND = {
    '10': ['10-1507', '10-1607', '10-1809', '10-sac', '10-ltsc2021', '10-iot-ltsc2021', '10-22h2'],
    '11': ['11-21h2', '11-22h2', '11-23h2', '11-24h2', '11-ltsc2024', '11-25h2'],
}

# IIS ships with (and is supported for the life of) its Windows release.
IIS_TO_WINDOWS = {
    '5.0': ['server-2000'],
    '5.1': ['xp'],
    '6.0': ['server-2003', 'server-2003r2', 'xp'],
    '7.0': ['server-2008', 'vista'],
    '7.5': ['server-2008r2', '7'],
    '8.0': ['server-2012', '8'],
    '8.5': ['server-2012r2', '8.1'],
    # 10.0 = Server 2016/2019/2022/2025 and Windows 10/11: undeterminable
}

MSSQL_CYCLES = {
    '2000':   ('Microsoft SQL Server 2000', D(2013, 4, 9), None),
    '2005':   ('Microsoft SQL Server 2005', D(2016, 4, 12), None),
    '2008':   ('Microsoft SQL Server 2008', D(2019, 7, 9), D(2023, 7, 11)),
    '2008r2': ('Microsoft SQL Server 2008 R2', D(2019, 7, 9), D(2023, 7, 11)),
    '2012':   ('Microsoft SQL Server 2012', D(2022, 7, 12), D(2025, 7, 8)),
    '2014':   ('Microsoft SQL Server 2014', D(2024, 7, 9), D(2027, 7, 13)),
    '2016':   ('Microsoft SQL Server 2016', D(2026, 7, 14), D(2029, 7, 10)),
    '2017':   ('Microsoft SQL Server 2017', D(2027, 10, 12), None),
    '2019':   ('Microsoft SQL Server 2019', D(2030, 1, 8), None),
    '2022':   ('Microsoft SQL Server 2022', D(2033, 1, 11), None),
    '2025':   ('Microsoft SQL Server 2025', None, None),
}
# (major, minor) of the product build -> release
MSSQL_BUILD_MAJOR = {
    (8, 0): '2000', (9, 0): '2005', (10, 0): '2008', (10, 50): '2008r2', (11, 0): '2012',
    (12, 0): '2014', (13, 0): '2016', (14, 0): '2017', (15, 0): '2019', (16, 0): '2022', (17, 0): '2025',
}
# Final service pack per release: (build, name). A build below it is also
# missing every later cumulative/security update.
MSSQL_FINAL_SP = {
    '2005': (5000, 'SP4'), '2008': (6000, 'SP4'), '2008r2': (6000, 'SP3'),
    '2012': (7001, 'SP4'), '2014': (6024, 'SP3'), '2016': (6300, 'SP3'),
}

PHP_CYCLES = {
    '5.2': ('PHP 5.2', D(2011, 1, 6), None),
    '5.3': ('PHP 5.3', D(2014, 8, 14), None),
    '5.4': ('PHP 5.4', D(2015, 9, 3), None),
    '5.5': ('PHP 5.5', D(2016, 7, 21), None),
    '5.6': ('PHP 5.6', D(2018, 12, 31), None),
    '7.0': ('PHP 7.0', D(2019, 1, 10), None),
    '7.1': ('PHP 7.1', D(2019, 12, 1), None),
    '7.2': ('PHP 7.2', D(2020, 11, 30), None),
    '7.3': ('PHP 7.3', D(2021, 12, 6), None),
    '7.4': ('PHP 7.4', D(2022, 11, 28), None),
    '8.0': ('PHP 8.0', D(2023, 11, 26), None),
    '8.1': ('PHP 8.1', D(2025, 12, 31), None),
    '8.2': ('PHP 8.2', D(2026, 12, 31), None),
    '8.3': ('PHP 8.3', D(2027, 12, 31), None),
    '8.4': ('PHP 8.4', D(2028, 12, 31), None),
    '8.5': ('PHP 8.5', D(2029, 12, 31), None),
}

APACHE_CYCLES = {
    '1.3': ('Apache HTTP Server 1.3', D(2010, 2, 3), None),
    '2.0': ('Apache HTTP Server 2.0', D(2013, 7, 10), None),
    '2.2': ('Apache HTTP Server 2.2', D(2017, 7, 11), None),
    '2.4': ('Apache HTTP Server 2.4', None, None),
}

# nginx supports only the current stable and mainline branches: a branch
# stops receiving fixes when the next stable branch ships.
NGINX_CYCLES = {
    '1.8':  ('nginx 1.8', D(2016, 4, 26), None),
    '1.9':  ('nginx 1.9', D(2016, 4, 26), None),
    '1.10': ('nginx 1.10', D(2017, 4, 12), None),
    '1.11': ('nginx 1.11', D(2017, 4, 12), None),
    '1.12': ('nginx 1.12', D(2018, 4, 17), None),
    '1.13': ('nginx 1.13', D(2018, 4, 17), None),
    '1.14': ('nginx 1.14', D(2019, 4, 23), None),
    '1.15': ('nginx 1.15', D(2019, 4, 23), None),
    '1.16': ('nginx 1.16', D(2020, 4, 21), None),
    '1.17': ('nginx 1.17', D(2020, 4, 21), None),
    '1.18': ('nginx 1.18', D(2021, 4, 20), None),
    '1.19': ('nginx 1.19', D(2021, 4, 20), None),
    '1.20': ('nginx 1.20', D(2022, 5, 24), None),
    '1.21': ('nginx 1.21', D(2022, 5, 24), None),
    '1.22': ('nginx 1.22', D(2023, 4, 11), None),
    '1.23': ('nginx 1.23', D(2023, 4, 11), None),
    '1.24': ('nginx 1.24', D(2024, 4, 23), None),
    '1.25': ('nginx 1.25', D(2024, 4, 23), None),
    '1.26': ('nginx 1.26', D(2025, 4, 23), None),
    '1.27': ('nginx 1.27', D(2025, 4, 23), None),
}

TOMCAT_CYCLES = {
    '5.5':  ('Apache Tomcat 5.5', D(2012, 9, 30), None),
    '6.0':  ('Apache Tomcat 6.0', D(2016, 12, 31), None),
    '7.0':  ('Apache Tomcat 7.0', D(2021, 3, 31), None),
    '8.0':  ('Apache Tomcat 8.0', D(2018, 6, 30), None),
    '8.5':  ('Apache Tomcat 8.5', D(2024, 3, 31), None),
    '9.0':  ('Apache Tomcat 9.0', None, None),
    '10.0': ('Apache Tomcat 10.0', D(2022, 10, 31), None),
    '10.1': ('Apache Tomcat 10.1', None, None),
    '11.0': ('Apache Tomcat 11.0', None, None),
}

OPENSSL_CYCLES = {
    '0.9.8': ('OpenSSL 0.9.8', D(2015, 12, 31), None),
    '1.0.0': ('OpenSSL 1.0.0', D(2015, 12, 31), None),
    '1.0.1': ('OpenSSL 1.0.1', D(2016, 12, 31), None),
    '1.0.2': ('OpenSSL 1.0.2', D(2019, 12, 31), None),
    '1.1.0': ('OpenSSL 1.1.0', D(2019, 9, 11), None),
    '1.1.1': ('OpenSSL 1.1.1', D(2023, 9, 11), None),
    '3.0':   ('OpenSSL 3.0', D(2026, 9, 7), None),
    '3.1':   ('OpenSSL 3.1', D(2025, 3, 14), None),
    '3.2':   ('OpenSSL 3.2', D(2025, 11, 23), None),
    '3.3':   ('OpenSSL 3.3', D(2026, 4, 9), None),
    '3.4':   ('OpenSSL 3.4', D(2026, 10, 22), None),
    '3.5':   ('OpenSSL 3.5', D(2030, 4, 8), None),
}

JQUERY_CYCLES = {
    '1': ('jQuery 1.x', D(2016, 6, 9), None),
    '2': ('jQuery 2.x', D(2016, 6, 9), None),
    '3': ('jQuery 3.x', None, None),
    '4': ('jQuery 4.x', None, None),
}

ANGULARJS_CYCLES = {
    '1': ('AngularJS 1.x', D(2021, 12, 31), None),
}

BOOTSTRAP_CYCLES = {
    '2': ('Bootstrap 2', D(2013, 8, 19), None),
    '3': ('Bootstrap 3', D(2019, 7, 24), None),
    '4': ('Bootstrap 4', D(2023, 1, 1), None),
    '5': ('Bootstrap 5', None, None),
}

DRUPAL_CYCLES = {
    '6':  ('Drupal 6', D(2016, 2, 24), None),
    '7':  ('Drupal 7', D(2025, 1, 5), None),
    '8':  ('Drupal 8', D(2021, 11, 2), None),
    '9':  ('Drupal 9', D(2023, 11, 1), None),
    '10': ('Drupal 10', None, None),
    '11': ('Drupal 11', None, None),
}

JOOMLA_CYCLES = {
    '3': ('Joomla 3', D(2023, 8, 17), None),
    '4': ('Joomla 4', D(2025, 10, 17), None),
    '5': ('Joomla 5', None, None),
}

# family -> metadata. 'floor': versions older than the oldest listed cycle
# are treated as EOL "no later than" that cycle's date. 'cap': max rating.
FAMILIES = {
    'windows': {'cycles': WINDOWS_CYCLES, 'remediation':
                "Upgrade or migrate the host to a supported Windows Server release (2019, 2022 or 2025). If the system is enrolled in Microsoft Extended Security Updates, confirm the enrolment is current and the latest ESU updates are installed. Until it is replaced, remove its services (RDP, SMB, SQL, IIS, Exchange) from direct internet exposure, e.g. behind a VPN or a patched reverse proxy."},
    'mssql':   {'cycles': MSSQL_CYCLES, 'remediation':
                "Upgrade to a supported SQL Server release (2019, 2022 or later) or migrate the database, and apply the latest cumulative update. If the instance is covered by Extended Security Updates, confirm the latest ESU update is installed. SQL Server should not be reachable from the internet: restrict TCP 1433 / UDP 1434 to the application hosts that need it."},
    'php':     {'cycles': PHP_CYCLES, 'floor': True, 'remediation':
                "Upgrade the PHP interpreter used by the web server to a supported branch (see php.net/supported-versions) and restart all PHP workers. If the version comes from a distribution package, check whether the distribution still provides security updates for it. Set expose_php=Off afterwards so the version is not disclosed."},
    'apache':  {'cycles': APACHE_CYCLES, 'floor': True, 'remediation':
                "Upgrade to Apache HTTP Server 2.4 (latest release). If httpd comes from a distribution package, confirm the distribution release itself is still supported. Set ServerTokens Prod afterwards so the version is not disclosed."},
    'nginx':   {'cycles': NGINX_CYCLES, 'floor': True, 'cap': RATING_MEDIUM, 'remediation':
                "Upgrade to the current nginx stable or mainline branch: nginx only fixes the latest stable and mainline branches. If nginx comes from a distribution package, confirm the distribution still provides security updates for it. Set server_tokens off afterwards."},
    'tomcat':  {'cycles': TOMCAT_CYCLES, 'floor': True, 'remediation':
                "Upgrade to a supported Apache Tomcat branch (9.0, 10.1 or 11.0). Moving from 8.5/9.0 to 10.x+ involves the javax -> jakarta namespace change, so plan application testing. Hide the version from error pages and the Server header afterwards."},
    'openssl': {'cycles': OPENSSL_CYCLES, 'floor': True, 'remediation':
                "Upgrade the OpenSSL library used by the service to a supported release (3.5 LTS or a newer supported release) and restart the service. If OpenSSL comes from the operating system, confirm the OS release still receives security updates (e.g. RHEL's 1.0.2k-fips / 3.0 builds are patched by Red Hat). Remove the OpenSSL version from the Server header."},
    'jquery':  {'cycles': JQUERY_CYCLES, 'cap': RATING_MEDIUM, 'remediation':
                "Upgrade the page's jQuery to the current release (3.7+/4.x) and re-test the pages that use it (the jQuery Migrate plugin helps find breaking changes). Remove any copies of the old version from the web root and CDN references."},
    'angularjs': {'cycles': ANGULARJS_CYCLES, 'cap': RATING_MEDIUM, 'remediation':
                  "AngularJS (1.x) is no longer maintained. Migrate the application to a supported framework (e.g. current Angular), or use a commercially supported AngularJS fork until it is migrated."},
    'bootstrap': {'cycles': BOOTSTRAP_CYCLES, 'cap': RATING_LOW, 'remediation':
                  "Upgrade the front-end to Bootstrap 5 (or later) and remove the old Bootstrap assets from the site."},
    'drupal':  {'cycles': DRUPAL_CYCLES, 'floor': True, 'remediation':
                "Upgrade to a supported Drupal major version (10 or 11), or use a commercial Drupal 7 extended-support vendor until the migration is done. Remove CHANGELOG.txt and other version-disclosing files from the web root."},
    'joomla':  {'cycles': JOOMLA_CYCLES, 'floor': True, 'remediation':
                "Upgrade to a supported Joomla major version (5.x) and its compatible extensions. Remove version-disclosing files (e.g. administrator/manifests/files/joomla.xml) from public access."},
}

_RATING_ORDER = [RATING_LOW, RATING_MEDIUM, RATING_HIGH]


# ---------------------------------------------------------------------------
# Product string -> (family, [cycles], version)
# ---------------------------------------------------------------------------

_DISTRO_RE = re.compile(
    r'ubuntu|debian|\bdeb\d|centos|red\s?hat|rhel|\.el\d|\bel\d+\b|fedora|suse|amzn|amazon\s*linux|'
    r'\bfips\b|raspbian|almalinux|rocky|oracle\s*linux|alpine|\+deb|bpo\d', re.I)

_WIN_SKIP_RE = re.compile(r'\b(?:ce|embedded|phone|mobile|iot|xbox|rt)\b', re.I)
_WIN_TOKEN_RE = re.compile(
    r'\b(?:server\s+)?(2000|2003|2008|2012|2016|2019|2022|2025)(\s*r2)?\b|\b(xp|vista|8\.1|7|8|10|11)\b', re.I)
_WIN_BUILD_RE = re.compile(r'\b(\d{1,2})\.(\d{1,2})\.(\d{4,5})\b')

_IIS_RE = re.compile(r'\b(?:microsoft[ -]iis(?:\s+httpd)?|internet\s+information\s+services|iis)\s+(\d+\.\d+)\b', re.I)
_MSSQL_RE = re.compile(r'\bsql\s+server(?:\s+(2000|2005|2008|2012|2014|2016|2017|2019|2022|2025)(\s+r2)?)?', re.I)
_MSSQL_BUILD_RE = re.compile(r'\b(\d{1,2})\.(\d{1,2})\.(\d{3,4})(?:\.\d+)?\b')
_PHP_RE = re.compile(r'(?:^|[\s(])php[ /](\d+)(?:\.(\d+))?(?:\.(\d+))?', re.I)
_APACHE_RE = re.compile(r'\bapache(?:\s+httpd|\s+http\s+server)?[ /](\d+)\.(\d+)(?:\.(\d+))?', re.I)
_NGINX_RE = re.compile(r'\bnginx[ /](\d+)\.(\d+)(?:\.(\d+))?', re.I)
_TOMCAT_RE = re.compile(r'\btomcat[ /](\d+)\.(\d+)(?:\.(\d+))?', re.I)
_OPENSSL_RE = re.compile(r'\bopenssl[ /](\d+)\.(\d+)\.(\d+)([a-z]{0,2})', re.I)
_JQUERY_RE = re.compile(r'^jquery\s+v?(\d+)\.(\d+)(?:\.(\d+))?', re.I)
_ANGULARJS_RE = re.compile(r'^angular(?:\.js|js)?\s+v?1\.(\d+)(?:\.(\d+))?', re.I)
_BOOTSTRAP_RE = re.compile(r'^bootstrap\s+v?(\d+)\.(\d+)(?:\.(\d+))?', re.I)
_DRUPAL_RE = re.compile(r'\bdrupal\s+(\d+)(?:\.(\d+))?', re.I)
_JOOMLA_RE = re.compile(r'\bjoomla\b!?[^0-9]{0,60}?\b(\d+)\.(\d+)(?:\.(\d+))?', re.I)


def _windows_from_name(text):
    """Windows release names ('Windows Server 2008 R2 - 2012', 'Windows 7 or
    Windows Server 2008 R2', CPE 'microsoft windows server 2012 r2', smb
    'Windows Server 2012 R2 Standard 9600') -> list of cycles, or None."""
    low = text.lower()
    idx = low.find('windows')
    if idx < 0:
        return None
    low = low[idx + len('windows'):]
    low = low.split('(')[0]  # smb-os-discovery repeats the name in parens
    if _WIN_SKIP_RE.search(low):
        return None
    # A trailing NT build number is the most precise evidence
    m = re.search(r'\b(\d{4,5})\b', low)
    if m and int(m.group(1)) in WINDOWS_BUILDS and int(m.group(1)) not in (2000, 2003, 2008, 2012, 2016, 2019, 2022, 2025):
        return list(WINDOWS_BUILDS[int(m.group(1))])
    tokens = []
    for tm in _WIN_TOKEN_RE.finditer(low):
        if tm.group(1):
            year = tm.group(1)
            tokens.append(('s', 'server-%s%s' % (year, 'r2' if tm.group(2) else ''), tm.start(), tm.end()))
        else:
            tokens.append(('c', tm.group(3), tm.start(), tm.end()))
    if not tokens:
        return None
    is_range = len(tokens) == 2 and '-' in low[tokens[0][3]:tokens[1][2]]
    if is_range:
        (f1, a, _, _), (f2, b, _, _) = tokens
        if f1 != f2:
            return None  # mixed client/server range: membership unknown
        order = _SERVER_ORDER if f1 == 's' else _CLIENT_ORDER
        if a not in order or b not in order:
            return None
        i, j = sorted((order.index(a), order.index(b)))
        picked = order[i:j + 1]
    else:
        picked = [t[1] for t in tokens]
    out = []
    for p in picked:
        for c in _CLIENT_EXPAND.get(p, [p]):
            if c in WINDOWS_CYCLES and c not in out:
                out.append(c)
    return out or None


def _windows_from_build(version):
    m = _WIN_BUILD_RE.search(version or '')
    if not m:
        return None
    build = int(m.group(3))
    return list(WINDOWS_BUILDS[build]) if build in WINDOWS_BUILDS else None


def _cycle_tuple(c):
    return tuple(int(x) for x in c.split('.'))


def _prefix_cycles(family, parts):
    """Cycles of `family` matching the known version parts.
    Returns (cycles, older_than_listed) or (None, False)."""
    cycles = FAMILIES[family]['cycles']
    want = tuple(parts)
    exact = '.'.join(str(p) for p in want)
    if exact in cycles:
        return [exact], False
    picked = [c for c in cycles if _cycle_tuple(c)[:len(want)] == want]
    if picked:
        return picked, False
    if FAMILIES[family].get('floor'):
        oldest = min(cycles, key=_cycle_tuple)
        if want < _cycle_tuple(oldest)[:len(want)]:
            return [oldest], True
    return None, False


def _vjoin(groups):
    return '.'.join(g for g in groups if g)


def match_product(text):
    """Product string -> list of (family, [cycles], version, older_than_listed).
    One string can name several products, e.g. a Server header
    'Apache 2.4.41 (Ubuntu) OpenSSL 1.1.1f PHP 7.4.3'."""
    out = []
    if not text:
        return out
    s = text.strip()

    iis = _IIS_RE.search(s)
    if iis and iis.group(1) in IIS_TO_WINDOWS:
        out.append(('windows', list(IIS_TO_WINDOWS[iis.group(1)]), 'IIS ' + iis.group(1), False))

    sql = _MSSQL_RE.search(s)
    if sql:
        release, build = None, ''
        bm = _MSSQL_BUILD_RE.search(s[sql.end():])
        if bm and (int(bm.group(1)), int(bm.group(2))) in MSSQL_BUILD_MAJOR:
            # the build from the TDS pre-login response is authoritative
            release = MSSQL_BUILD_MAJOR[(int(bm.group(1)), int(bm.group(2)))]
            build = bm.group(0)
        elif sql.group(1):
            release = sql.group(1) + ('r2' if sql.group(2) else '')
        if release in MSSQL_CYCLES:
            out.append(('mssql', [release], build, False))

    if not iis and not sql and 'windows' in s.lower():
        cyc = _windows_from_name(s)
        if cyc:
            out.append(('windows', cyc, '', False))

    m = _PHP_RE.search(s)
    if m:
        parts = [int(m.group(1))] + ([int(m.group(2))] if m.group(2) else [])
        cyc, old = _prefix_cycles('php', parts)
        if cyc:
            out.append(('php', cyc, _vjoin(m.groups()), old))

    for family, rx in (('apache', _APACHE_RE), ('nginx', _NGINX_RE), ('tomcat', _TOMCAT_RE)):
        m = rx.search(s)
        if m:
            cyc, old = _prefix_cycles(family, [int(m.group(1)), int(m.group(2))])
            if cyc:
                out.append((family, cyc, _vjoin(m.groups()), old))

    m = _OPENSSL_RE.search(s)
    if m:
        a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3))
        cyc, old = _prefix_cycles('openssl', [a, b] if a >= 3 else [a, b, c])
        if cyc:
            out.append(('openssl', cyc, '%d.%d.%d%s' % (a, b, c, m.group(4) or ''), old))

    m = _JQUERY_RE.search(s)
    if m and m.group(1) in JQUERY_CYCLES:
        out.append(('jquery', [m.group(1)], _vjoin(m.groups()), False))

    m = _ANGULARJS_RE.search(s)
    if m:
        out.append(('angularjs', ['1'], '1.' + _vjoin(m.groups()), False))

    m = _BOOTSTRAP_RE.search(s)
    if m and m.group(1) in BOOTSTRAP_CYCLES:
        out.append(('bootstrap', [m.group(1)], _vjoin(m.groups()), False))

    for family, rx in (('drupal', _DRUPAL_RE), ('joomla', _JOOMLA_RE)):
        m = rx.search(s)
        if m:
            cyc, old = _prefix_cycles(family, [int(m.group(1))])
            if cyc:
                out.append((family, cyc, _vjoin(m.groups()), old))
    return out


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _status(cycles_meta, today):
    """cycles_meta: list of (label, eol, esu). Returns (status, eol, end):
    status is 'eol', 'esu', 'approaching' or None, judged on the LATEST date
    among the candidate releases, so every candidate must be past it."""
    if any(eol is None for _, eol, _ in cycles_meta):
        return None, None, None
    eol = max(e for _, e, _ in cycles_meta)
    end = max((esu or e) for _, e, esu in cycles_meta)
    if today > end:
        return 'eol', eol, end
    if today > eol:
        return 'esu', eol, end
    if (eol - today) <= timedelta(days=APPROACHING_DAYS):
        return 'approaching', eol, end
    return None, eol, end


def _lower(rating):
    return _RATING_ORDER[max(0, _RATING_ORDER.index(rating) - 1)]


def _cap(rating, cap):
    if cap is None:
        return rating
    return _RATING_ORDER[min(_RATING_ORDER.index(rating), _RATING_ORDER.index(cap))]


def _collect_evidence(products, tags, host_result):
    """-> list of {family, cycles, version, older, port, source, text, guess, distro}"""
    raw = []
    hr = host_result or {}
    for p in hr.get('ports') or []:
        if p.get('product'):
            text = ' '.join(x for x in (p.get('product'), p.get('version'), p.get('extrainfo')) if x)
            raw.append((text, p.get('port'), 'service banner (nmap -sV)', False))
    for o in hr.get('os_names') or []:
        raw.append((o['name'], o.get('port'), o.get('source', 'OS detection'), o.get('guess', False)))
    for prod in products or []:
        raw.append((prod, None, 'detected product', False))

    php_build = any(t.startswith(PHP_BUILD_TAG) for t in (tags or []))
    out = []
    for b in hr.get('windows_builds') or []:
        cyc = _windows_from_build(b.get('version'))
        if cyc:
            out.append({'family': 'windows', 'cycles': cyc, 'version': b['version'], 'older': False,
                        'port': b.get('port'), 'source': 'NTLM Product_Version (%s)' % b.get('source'),
                        'text': None, 'guess': False, 'distro': False, 'precision': 3})
    for text, port, source, guess in raw:
        for family, cycles, version, older in match_product(text):
            out.append({'family': family, 'cycles': cycles, 'version': version, 'older': older,
                        'port': port, 'source': source, 'text': text, 'guess': guess,
                        'distro': bool(_DISTRO_RE.search(text)) or (family == 'php' and php_build),
                        'precision': _precision(family, cycles, version, text, guess)})
    return out


def _precision(family, cycles, version, text, guess):
    """How exactly a piece of evidence identifies a Windows release:
    3 = NT build number, 2 = one named release, 1 = a range / several
    releases / derived from the IIS version, 0 = OS-fingerprint guess."""
    if guess:
        return 0
    if family != 'windows':
        return 2
    if version.startswith('IIS'):
        return 1
    low = text.lower().split('(')[0]
    if any(int(b) in WINDOWS_BUILDS for b in re.findall(r'\b(\d{4,5})\b', low)
           if b not in ('2000', '2003', '2008', '2012', '2016', '2019', '2022', '2025')):
        return 3
    return 2 if len(cycles) == 1 else 1


def _group(evidence):
    """Group evidence by (family, candidate releases). Evidence naming a
    superset of another group's releases (e.g. 'Windows Server 2012 R2' vs
    build 9600 = 2012 R2 / 8.1, or 'PHP 7' vs 'PHP 7.4') folds into the
    narrowest matching group, so one product gives one finding."""
    groups = {}
    for e in evidence:
        groups.setdefault((e['family'], frozenset(e['cycles'])), []).append(e)
    keys = sorted(groups, key=lambda k: len(k[1]))
    merged = {}
    for k in keys:
        target = next((t for t in merged if t[0] == k[0] and t[1] < k[1]), None)
        if target is not None:
            merged[target].extend(groups[k])
        else:
            merged[k] = list(groups[k])
    # A host has one OS: Windows evidence less precise than the best reading
    # (e.g. nmap's SMB '2008 R2 - 2012' range vs the NTLM build 6.3.9600)
    # joins an overlapping best group as corroboration, or is set aside and
    # only mentioned in that group's finding - it never raises its own.
    win = [k for k in merged if k[0] == 'windows']
    if win:
        prec = {k: max(e['precision'] for e in merged[k]) for k in win}
        top = max(prec.values())
        best = [k for k in win if prec[k] == top]
        for k in win:
            if prec[k] == top:
                continue
            target = next((t for t in best if t[1] & k[1]), None)
            evs = merged.pop(k)
            if target is not None:
                merged[target].extend(evs)
            else:
                merged[best[0]].extend(dict(e, overridden=True) for e in evs)
    return merged


def _issue(host, asset_id, family, cycles, evs, today):
    meta = FAMILIES[family]
    overridden = [e for e in evs if e.get('overridden')]
    evs = [e for e in evs if not e.get('overridden')]
    cycles = sorted(cycles, key=lambda c: list(meta['cycles']).index(c))
    cmeta = [meta['cycles'][c] for c in cycles]
    status, eol, end = _status(cmeta, today)
    if status is None:
        return None

    rating = _cap({'eol': RATING_HIGH, 'esu': RATING_MEDIUM, 'approaching': RATING_LOW}[status], meta.get('cap'))
    guess = all(e['guess'] for e in evs)      # only an OS-fingerprint guess
    distro = any(e['distro'] for e in evs)
    if status != 'approaching':
        if distro:
            rating = _lower(rating)
        if guess:
            rating = _cap(rating, RATING_MEDIUM)

    label = ' / '.join(l for l, _, _ in cmeta)
    versions = sorted({e['version'] for e in evs if e['version']})
    ports = sorted({e['port'] for e in evs if e['port']})
    older = all(e['older'] for e in evs)
    when = ("no later than %s" % eol.isoformat()) if older else ("on %s" % eol.isoformat())
    sources = []
    for e in evs:
        s = e['source'] + (' on port %s' % e['port'] if e['port'] else '') + ' [%s]' % (e['text'] or e['version'])
        if s not in sources:
            sources.append(s)

    if status == 'approaching':
        title = "Software approaching end of life: %s (support ends %s)" % (label, eol.isoformat())
        body = ("Host [%s] runs %s. Vendor security support for this release ends on %s (in %d days); after that it receives no further security fixes."
                % (host, label, eol.isoformat(), (eol - today).days))
    elif status == 'esu':
        title = "End-of-life software: %s" % label
        body = ("Host [%s] runs %s. Vendor support ended %s. Only systems enrolled in the vendor's paid Extended Security Updates programme (available until %s) still receive security fixes; a system that is not enrolled is unpatched against every vulnerability disclosed since."
                % (host, label, when, end.isoformat()))
    else:
        title = "End-of-life software: %s" % label
        esu_txt = (" Paid Extended Security Updates also ended on %s." % end.isoformat()) if end != eol else ""
        body = ("Host [%s] runs %s. Vendor support ended %s.%s It receives no security fixes, so every vulnerability disclosed since then remains open on this internet-facing host."
                % (host, label, when, esu_txt))
    if older:
        body += " The detected version (%s) is older than every release in the lifecycle table." % ', '.join(versions)
    if len(cycles) > 1:
        body += " The evidence matches more than one release (%s); every one of them is past the date above." % label
    if family == 'mssql':
        body += _mssql_sp_note(cycles[0], versions)
    body += " Evidence: %s." % '; '.join(sources)
    if distro and status != 'approaching':
        body += (" The version string carries an operating-system distribution marker: the distribution may still backport security fixes to this upstream release, so check the distribution's support status for this package before closing the finding (severity lowered one level for this reason).")
    if guess:
        body += " The release was inferred only from nmap OS fingerprinting, which is approximate; confirm it on the host."
    if overridden:
        body += (" Less precise evidence pointed to a different release (%s); the more precise evidence above takes precedence."
                 % '; '.join(sorted({'%s%s [%s]' % (e['source'], ' on port %s' % e['port'] if e['port'] else '',
                                                    e['text'] or e['version']) for e in overridden})))

    object_id = '%s:%s' % (host, ports[0]) if len(ports) == 1 else host
    object_meta = label + ((' ' + ', '.join(versions)) if versions else '')
    twc_id = 'eol-%s-%s' % (family, '-'.join(re.sub(r'[^a-z0-9]+', '', c.lower()) for c in cycles))
    logging.info("[EASM] %s: %s - %s (rating %s)", host, title, status, rating)
    return _new_issue(twc_id, title, body, rating, asset_id, ISSUE_TYPE_EOL,
                      object_id=object_id, object_meta=object_meta, remediation=meta['remediation'])


def check_eol(host, products, tags, host_result, asset_id, args=None, today=None):
    """One finding per end-of-life (or soon end-of-life) product release
    seen on the host. host_result is the nmap result for the host (or None)."""
    if getattr(args, 'no_eol_check', False):
        return []
    today = today or date.today()
    issues = []
    for (family, cycles), evs in _group(_collect_evidence(products, tags, host_result)).items():
        try:
            issue = _issue(host, asset_id, family, cycles, evs, today)
        except Exception as e:  # a data/table problem must never break the scan
            logging.debug("[EASM] %s: EOL evaluation failed for %s: %s", host, family, e)
            continue
        if issue:
            issues.append(issue)
    return issues


def _mssql_sp_note(release, versions):
    final = MSSQL_FINAL_SP.get(release)
    if not final:
        return ''
    for v in versions:
        m = _MSSQL_BUILD_RE.search(v)
        if m and int(m.group(3)) < final[0]:
            return (" The reported build [%s] also predates the release's final service pack (%s, build %d), so it is missing every update published after that build."
                    % (v, final[1], final[0]))
    return ''
