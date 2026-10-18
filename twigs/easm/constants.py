"""Shared constants for the twigs.easm package: config-issue type labels,
severity ratings, and the small set of tunables/data-tables genuinely used
across more than one check module (RISKY_PORTS/TLS_PORT_HINTS are used by
both nmap_discovery and ssl_checks). Data tables that are only used by a
single check module (e.g. WAF_SIGNATURES, EXPOSED_PANEL_CHECKS) live in that
module instead, to keep this file small and each table next to the code that
uses it.
"""

HTTP_TIMEOUT = 10
# A short, aggressive timeout for speculative probes against uncommon /
# non-default-web ports that are closed or silently filtered on the
# overwhelming majority of targets (e.g. ai_services.py's per-port LLM/vector-DB
# signature checks). A real service on one of these ports responds almost
# instantly, so this does not risk missing a genuine match - it just avoids
# waiting out the full HTTP_TIMEOUT for every port that goes nowhere. Not used
# for checks against an already-confirmed-live base host/port (e.g.
# exposed_panels.py's path probes), where the connection itself is not in
# question.
PROBE_TIMEOUT_SHORT = 3
DNS_TIMEOUT = 4

USER_AGENT = 'Mozilla/5.0 (compatible; twigs-easm/1.0; +https://threatwatch.io)'

# ---------------------------------------------------------------------------
# Config issue types (EASM specific taxonomy, reported via config_issues)
# ---------------------------------------------------------------------------
ISSUE_TYPE_PORTS = 'Open Ports'
ISSUE_TYPE_SSL = 'SSL'
ISSUE_TYPE_DNS = 'DNS'
ISSUE_TYPE_EMAIL_SECURITY = 'Email Security'
ISSUE_TYPE_FIREWALL = 'Firewall'
ISSUE_TYPE_EXPOSED_PANEL = 'Exposed Panel'
ISSUE_TYPE_API = 'API'
ISSUE_TYPE_WEB_APPLICATION = 'Web Application'
ISSUE_TYPE_TYPOSQUATTING = 'Typosquatting'
ISSUE_TYPE_SUBDOMAIN = 'Subdomain Discovery'
ISSUE_TYPE_WHOIS = 'WHOIS'
ISSUE_TYPE_RANSOMWARE = 'Ransomware'
ISSUE_TYPE_ASN = 'ASN/Netblock'
ISSUE_TYPE_HTTP_HEADERS = 'HTTP Security Headers'
ISSUE_TYPE_CREDENTIAL_LEAK = 'Credential Leak'
ISSUE_TYPE_SHADOW_AI = 'Shadow AI'

RATING_INFO = '1'
RATING_LOW = '2'
RATING_MEDIUM = '3'
RATING_HIGH = '4'
RATING_CRITICAL = '5'

# Well known ports for services that should generally not be exposed to the
# public internet. Used to elevate the severity of otherwise generic open
# port findings (nmap_discovery), and to fall back to when --top-ports can't
# be combined with an explicit -p list.
RISKY_PORTS = {
    21: ('FTP', RATING_MEDIUM),
    23: ('Telnet', RATING_HIGH),
    25: ('SMTP', RATING_LOW),
    135: ('MS RPC', RATING_HIGH),
    139: ('NetBIOS', RATING_HIGH),
    445: ('SMB', RATING_HIGH),
    1433: ('MS SQL Server', RATING_HIGH),
    1521: ('Oracle DB', RATING_HIGH),
    2049: ('NFS', RATING_HIGH),
    2375: ('Docker (unencrypted)', RATING_CRITICAL),
    27017: ('MongoDB', RATING_HIGH),
    3306: ('MySQL', RATING_HIGH),
    3389: ('RDP', RATING_HIGH),
    5432: ('PostgreSQL', RATING_HIGH),
    5900: ('VNC', RATING_HIGH),
    5984: ('CouchDB', RATING_HIGH),
    6379: ('Redis', RATING_HIGH),
    9200: ('Elasticsearch', RATING_HIGH),
    9300: ('Elasticsearch transport', RATING_HIGH),
    11211: ('Memcached', RATING_HIGH),
    27018: ('MongoDB', RATING_HIGH),
}

TLS_PORT_HINTS = [443, 8443, 993, 995, 465, 636, 989, 990, 3269, 5986]
