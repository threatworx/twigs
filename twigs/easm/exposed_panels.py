"""Exposed admin panel / dev-tool / misconfiguration probing: CI/CD and
artifact tooling, database admin UIs, monitoring dashboards, secrets
management, Kubernetes Dashboard, Docker Registry API, and information
disclosure (phpinfo(), mod_status, exposed .git/.svn/.env/backup files).
Each signature is matched on more than just "path returns 200" - a
distinctive header or body signature is required - to avoid false positives
on sites that return 200 for any path (custom error pages, SPA catch-all
routing, etc.)."""
import re

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_EXPOSED_PANEL
from .util import _new_issue, _http_get

# Known exposed admin panels / dev tools / misconfigurations. Each entry is
# matched on more than just "path returns 200" - a distinctive header or body
# signature is required - to avoid false positives on sites that return 200
# for any path (custom error pages, SPA catch-all routing, etc.).
EXPOSED_PANEL_CHECKS = [
    {
        'name': 'Exposed .git repository', 'path': '/.git/HEAD', 'body_prefix': 'ref: refs/',
        'rating': RATING_CRITICAL,
        'description': "The Git repository's HEAD file is publicly accessible, indicating the .git directory (source history, commit messages, and potentially embedded secrets/credentials) may be downloadable.",
        'remediation': "Remove the .git directory from the web root, or configure the web server to deny access to it (e.g. an Nginx 'location ~ /\\.git' deny rule, or an Apache <DirectoryMatch> block). Rotate any credentials that may be present in the repository's history.",
    },
    {
        'name': 'Exposed .env file', 'path': '/.env',
        'body_contains_any': ['APP_KEY=', 'DB_PASSWORD=', 'DB_USERNAME=', 'SECRET_KEY=', 'AWS_SECRET_ACCESS_KEY=', 'API_KEY='],
        'not_html': True, 'rating': RATING_CRITICAL,
        'description': "A .env file containing application configuration - potentially including database credentials, API keys, and other secrets - is publicly accessible.",
        'remediation': "Remove the .env file from the web root (environment files should never be served by the web server), and rotate any credentials it may have exposed.",
    },
    {
        'name': 'Jenkins', 'path': '/', 'header_contains': {'x-jenkins': None}, 'rating': RATING_HIGH,
        'description': "A Jenkins CI/CD server appears to be exposed to the internet (identified via the X-Jenkins response header). Unauthenticated or weakly-protected Jenkins instances are a common path to full remote code execution via script consoles, build triggers, or plugin vulnerabilities.",
        'remediation': "Restrict access to Jenkins to a VPN/trusted network, enforce authentication and authorization (disable anonymous read/build access), keep Jenkins and plugins patched, and disable the Groovy script console for non-admins.",
    },
    {
        'name': 'Elasticsearch', 'path': '/', 'body_contains_any': ['"cluster_name"', '"you know, for search"'],
        'not_html': True, 'rating': RATING_CRITICAL,
        'description': "An Elasticsearch instance appears to be exposed to the internet without authentication, identified via its root API response. Unauthenticated Elasticsearch commonly allows full read/write access to indexed data.",
        'remediation': "Restrict access to Elasticsearch to a VPN/trusted network, enable authentication (e.g. security plugin), and ensure it is never directly exposed to the internet.",
    },
    {
        'name': 'Kibana', 'path': '/', 'header_contains': {'kbn-name': None}, 'rating': RATING_HIGH,
        'description': "A Kibana instance appears to be exposed to the internet (identified via the kbn-name response header), typically indicating the backing Elasticsearch cluster's data is also reachable/browsable.",
        'remediation': "Restrict access to Kibana to a VPN/trusted network and enforce authentication.",
    },
    {
        'name': 'Grafana', 'path': '/api/health', 'body_contains_any': ['"database"', '"commit"'],
        'not_html': True, 'rating': RATING_MEDIUM,
        'description': "A Grafana instance appears to be exposed to the internet, identified via its health-check API. Grafana dashboards can expose internal metrics/topology, and older versions have had authentication-bypass and plugin RCE vulnerabilities.",
        'remediation': "Restrict access to Grafana to a VPN/trusted network, enforce authentication, disable anonymous/viewer access if not required, and keep Grafana patched.",
    },
    {
        'name': 'Prometheus', 'path': '/graph', 'body_contains_any': ['Prometheus Time Series Collection and Processing Server'],
        'rating': RATING_MEDIUM,
        'description': "A Prometheus server appears to be exposed to the internet. Prometheus typically has no authentication by default and can expose detailed internal metrics, service topology, and target endpoints.",
        'remediation': "Restrict access to Prometheus to a VPN/trusted network and place it behind an authenticating reverse proxy.",
    },
    {
        'name': 'Kubernetes Dashboard', 'path': '/', 'body_contains_any': ['Kubernetes Dashboard'],
        'rating': RATING_CRITICAL,
        'description': "A Kubernetes Dashboard instance appears to be exposed to the internet. If authentication/RBAC is misconfigured, this can allow full control over the cluster.",
        'remediation': "Restrict access to the Kubernetes Dashboard to a VPN/trusted network, enforce authentication, and apply least-privilege RBAC bindings for the dashboard's service account.",
    },
    {
        'name': 'CouchDB', 'path': '/', 'body_contains_any': ['"couchdb":"Welcome"', '"couchdb": "Welcome"'],
        'not_html': True, 'rating': RATING_CRITICAL,
        'description': "An Apache CouchDB instance appears to be exposed to the internet without authentication, identified via its root API welcome response. A fresh/misconfigured CouchDB install with no admin user allows full anonymous read/write access.",
        'remediation': "Restrict access to CouchDB to a VPN/trusted network and enable admin-party protection (configure an [admins] user) - an unconfigured install allows full anonymous access.",
    },
    {
        'name': 'Docker Registry API', 'path': '/v2/', 'header_contains': {'docker-distribution-api-version': 'registry/2.0'},
        'rating': RATING_HIGH,
        'description': "A Docker Registry v2 API appears to be exposed to the internet, identified via its distinctive response header. Unauthenticated registries can expose proprietary container images (and any secrets baked into them) and, if writable, allow pushing malicious images.",
        'remediation': "Restrict access to the registry to a VPN/trusted network and require authentication for pull/push operations.",
    },
    {
        'name': 'phpMyAdmin', 'path': '/phpmyadmin/', 'body_contains_any': ['phpMyAdmin'], 'rating': RATING_MEDIUM,
        'description': "A phpMyAdmin instance appears to be exposed to the internet. This is a common target for credential brute-forcing and known CVEs.",
        'remediation': "Restrict access to phpMyAdmin to a VPN/trusted network or an IP allow-list, enforce strong unique credentials/MFA, and keep it patched.",
    },
    {
        'name': 'Adminer', 'path': '/adminer.php', 'body_contains_any': ['Adminer'], 'rating': RATING_MEDIUM,
        'description': "An Adminer database management tool appears to be exposed to the internet. Like phpMyAdmin, this is a common target for credential attacks and has had multiple RCE-class CVEs (e.g. via crafted database server responses).",
        'remediation': "Remove Adminer from production web roots, or restrict access to a VPN/trusted network with strong authentication.",
    },
    {
        'name': 'Spring Boot Actuator env endpoint', 'path': '/actuator/env',
        'body_contains_any': ['"propertySources"', '"activeProfiles"'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "A Spring Boot Actuator 'env' endpoint appears to be exposed to the internet, potentially disclosing environment variables, configuration properties, and secrets.",
        'remediation': "Disable or restrict Spring Boot Actuator endpoints in production (management.endpoints.web.exposure.include), or place them behind authentication on a separate management port that is not internet-facing.",
    },
    {
        'name': 'Apache Tomcat Manager (open)', 'path': '/manager/html',
        'body_contains_any': ['Tomcat Web Application Manager', 'Manager - List Applications'], 'rating': RATING_CRITICAL,
        'description': "The Apache Tomcat Manager application is exposed to the internet and accessible without authentication, allowing deployment of arbitrary WAR files - a common path to full remote code execution.",
        'remediation': "Restrict access to /manager to a VPN/trusted network, require strong unique credentials (never the tomcat/tomcat or admin/admin defaults), and remove the Manager application entirely if it is not needed.",
    },
    {
        'name': 'Apache Tomcat Manager (auth required)', 'path': '/manager/html', 'status_codes': [401],
        'header_contains': {'www-authenticate': 'tomcat manager application'}, 'rating': RATING_LOW,
        'description': "The Apache Tomcat Manager application is exposed to the internet (identified via its WWW-Authenticate realm) and requires authentication. While not itself a vulnerability, this is a common brute-force/credential-stuffing target and a known path to RCE if credentials are weak.",
        'remediation': "Restrict access to /manager to a VPN/trusted network or IP allow-list, and confirm strong unique credentials are in use (never the tomcat/tomcat or admin/admin defaults).",
    },
    {
        'name': 'Portainer', 'path': '/', 'body_contains_any': ['<title>Portainer</title>'], 'rating': RATING_HIGH,
        'description': "A Portainer (Docker/Kubernetes management UI) instance appears to be exposed to the internet. If authentication is not enforced, this allows full control over the underlying container/cluster infrastructure.",
        'remediation': "Restrict access to Portainer to a VPN/trusted network, ensure the initial admin account is set and uses a strong password (unclaimed instances allow the first visitor to set the admin password), and keep it patched.",
    },
    {
        'name': 'Nexus Repository Manager', 'path': '/', 'body_contains_any': ['Nexus Repository Manager'], 'rating': RATING_HIGH,
        'description': "A Sonatype Nexus Repository Manager instance appears to be exposed to the internet. Nexus has had multiple unauthenticated RCE-class CVEs, and exposed repositories can leak proprietary packages/artifacts.",
        'remediation': "Restrict access to Nexus to a VPN/trusted network, enforce authentication, disable anonymous access, and keep it patched to the latest version.",
    },
    {
        'name': 'JFrog Artifactory', 'path': '/artifactory/webapp/', 'body_contains_any': ['JFrog Artifactory'], 'rating': RATING_HIGH,
        'description': "A JFrog Artifactory instance appears to be exposed to the internet, potentially leaking proprietary build artifacts/packages if anonymous access is enabled.",
        'remediation': "Restrict access to Artifactory to a VPN/trusted network, disable anonymous access, and enforce authentication for all repositories.",
    },
    {
        'name': 'SonarQube', 'path': '/', 'body_contains_any': ['<title>SonarQube</title>'], 'rating': RATING_MEDIUM,
        'description': "A SonarQube code-quality/security-analysis instance appears to be exposed to the internet. If anonymous access is enabled, this can leak source code snippets, project structure, and known vulnerability findings for scanned projects.",
        'remediation': "Restrict access to SonarQube to a VPN/trusted network, disable the 'Anyone' default permission template, and enforce authentication.",
    },
    {
        'name': 'Apache NiFi', 'path': '/nifi/', 'body_contains_any': ['<title>NiFi</title>'], 'rating': RATING_HIGH,
        'description': "An Apache NiFi dataflow management instance appears to be exposed to the internet. NiFi has an RCE history and, if unauthenticated, allows creating/modifying dataflows that can execute arbitrary code or scripts.",
        'remediation': "Restrict access to NiFi to a VPN/trusted network and enforce authentication (single-user or LDAP/OIDC).",
    },
    {
        'name': 'GitLab (self-hosted)', 'path': '/users/sign_in',
        'body_contains_any': ['Sign in · GitLab', 'content="GitLab"'], 'rating': RATING_INFO,
        'description': "A self-hosted GitLab sign-in page was found. This is informational - the sign-in page itself is not a vulnerability - but confirms the presence and reachability of a self-hosted GitLab instance, useful for version/CVE-targeted follow-up and for confirming it should be internet-facing at all.",
        'remediation': "Confirm this instance is intended to be internet-facing. If so, ensure it is kept patched (GitLab has had multiple critical unauthenticated RCE CVEs), 2FA is enforced, and public sign-up is disabled unless required.",
    },
    {
        'name': 'Neo4j Browser', 'path': '/browser/', 'body_contains_any': ['Neo4j Browser'], 'rating': RATING_HIGH,
        'description': "A Neo4j Browser instance appears to be exposed to the internet. Neo4j has historically shipped with no authentication by default, allowing direct read/write access to the graph database.",
        'remediation': "Restrict access to Neo4j to a VPN/trusted network and confirm dbms.security.auth_enabled is set (authentication is required by default in current versions, but older/misconfigured instances may not enforce it).",
    },
    {
        'name': 'Mongo Express', 'path': '/', 'body_contains_any': ['<title>Mongo Express</title>'], 'rating': RATING_CRITICAL,
        'description': "A Mongo Express (MongoDB web admin UI) instance appears to be exposed to the internet. This tool is commonly deployed with no authentication in development, giving direct browse/edit access to all databases and collections.",
        'remediation': "Restrict access to Mongo Express to a VPN/trusted network and enable its basic-auth configuration (ME_CONFIG_BASICAUTH_*), or remove it from any internet-facing environment entirely.",
    },
    {
        'name': 'Redis Commander', 'path': '/', 'body_contains_any': ['<title>Redis Commander'], 'rating': RATING_CRITICAL,
        'description': "A Redis Commander (Redis web admin UI) instance appears to be exposed to the internet, potentially giving direct browse/edit access to Redis data (which frequently includes session tokens, cache of sensitive data, or queued jobs).",
        'remediation': "Restrict access to Redis Commander to a VPN/trusted network and enable its authentication configuration, or remove it from any internet-facing environment entirely.",
    },
    {
        'name': 'pgAdmin', 'path': '/', 'body_contains_any': ['<title>pgAdmin'], 'rating': RATING_HIGH,
        'description': "A pgAdmin (PostgreSQL web admin UI) instance appears to be exposed to the internet. If the initial login is unset/weak, this can give direct access to connected PostgreSQL databases.",
        'remediation': "Restrict access to pgAdmin to a VPN/trusted network and ensure a strong, unique master password is set.",
    },
    {
        'name': 'HashiCorp Vault', 'path': '/v1/sys/health', 'body_contains_any': ['"initialized"', '"sealed"'],
        'not_html': True, 'rating': RATING_HIGH,
        'description': "A HashiCorp Vault instance appears to be exposed to the internet, identified via its health API. Vault is typically used to store highly sensitive secrets (credentials, keys, certificates); any misconfiguration here (e.g. a permissive default policy, or the root token still in use) is high impact.",
        'remediation': "Restrict access to Vault to a VPN/trusted network, confirm it is unsealed only as intended and that no overly permissive default policies or root tokens remain in routine use, and enable audit logging.",
    },
    {
        'name': 'Zabbix', 'path': '/', 'body_contains_any': ['<title>Zabbix'], 'rating': RATING_MEDIUM,
        'description': "A Zabbix monitoring frontend appears to be exposed to the internet. Zabbix has had multiple authentication-bypass and RCE-class CVEs, and exposes internal infrastructure/monitoring topology once authenticated (or via unauthenticated bugs).",
        'remediation': "Restrict access to Zabbix to a VPN/trusted network, enforce strong unique credentials, and keep it patched to the latest version.",
    },
    {
        'name': 'Webmin', 'path': '/', 'status_codes': [401], 'header_contains': {'www-authenticate': 'webmin'},
        'rating': RATING_MEDIUM,
        'description': "A Webmin server administration panel appears to be exposed to the internet (identified via its WWW-Authenticate realm). Webmin has a long history of authentication-bypass and RCE-class CVEs, and grants full server administration if compromised.",
        'remediation': "Restrict access to Webmin to a VPN/trusted network or IP allow-list, enforce strong unique credentials, and keep it patched to the latest version.",
    },
    {
        'name': 'phpinfo() exposure', 'path': '/phpinfo.php', 'body_contains_any': ['phpinfo()', 'PHP Version'],
        'not_html': False, 'rating': RATING_MEDIUM,
        'description': "A phpinfo() page is publicly accessible, disclosing detailed server configuration: PHP version and loaded extensions/modules, filesystem paths, environment variables, and sometimes internal network details - all useful reconnaissance for further attacks.",
        'remediation': "Remove phpinfo() debug pages from any internet-facing environment.",
    },
    {
        'name': 'phpinfo() exposure (info.php)', 'path': '/info.php', 'body_contains_any': ['phpinfo()', 'PHP Version'],
        'not_html': False, 'rating': RATING_MEDIUM,
        'description': "A phpinfo() page is publicly accessible, disclosing detailed server configuration: PHP version and loaded extensions/modules, filesystem paths, environment variables, and sometimes internal network details - all useful reconnaissance for further attacks.",
        'remediation': "Remove phpinfo() debug pages from any internet-facing environment.",
    },
    {
        'name': 'Apache mod_status', 'path': '/server-status', 'body_contains_any': ['Apache Server Status for'],
        'rating': RATING_MEDIUM,
        'description': "The Apache mod_status page is publicly accessible, leaking a live view of in-flight requests - including other visitors' request URLs (which may contain session tokens or other sensitive query-string data), source IPs, and internal server topology.",
        'remediation': "Restrict /server-status to localhost/trusted networks only (e.g. an Apache <Location> block with 'Require local'), or disable mod_status if not needed.",
    },
    {
        'name': 'Exposed .svn repository', 'path': '/.svn/entries', 'body_contains_any': ['svn:wc:ra_dav', 'dir\n'],
        'not_html': True, 'rating': RATING_HIGH,
        'description': "A Subversion working-copy metadata file is publicly accessible, indicating the .svn directory (and potentially the full source history it tracks) may be downloadable.",
        'remediation': "Remove the .svn directory from the web root, or configure the web server to deny access to it, the same way as for an exposed .git directory.",
    },
    {
        'name': 'Exposed web.config.bak', 'path': '/web.config.bak', 'body_contains_any': ['<configuration>', '<system.web>'],
        'not_html': True, 'rating': RATING_HIGH,
        'description': "A backup of an ASP.NET web.config file is publicly accessible, potentially disclosing connection strings, application secrets, and internal configuration.",
        'remediation': "Remove backup/.bak configuration files from the web root - they are not protected by the web.config's own <system.webServer> rules the way the live file is.",
    },
    {
        'name': 'Exposed wp-config.php.bak', 'path': '/wp-config.php.bak',
        'body_contains_any': ["define('DB_", 'define("DB_', 'DB_PASSWORD'], 'not_html': True, 'rating': RATING_CRITICAL,
        'description': "A backup of a WordPress wp-config.php file is publicly accessible, disclosing database credentials, authentication salts/keys, and other secrets in plaintext.",
        'remediation': "Remove backup/.bak copies of wp-config.php from the web root, and rotate the exposed database credentials and WordPress secret keys/salts.",
    },
    {
        'name': 'Exposed docker-compose.yml', 'path': '/docker-compose.yml',
        'body_contains_all': ['services:'], 'not_html': True, 'rating': RATING_MEDIUM,
        'description': "A docker-compose.yml file is publicly accessible at the web root, potentially disclosing internal service topology, image names/versions, exposed ports, and any credentials or secrets embedded in environment variables.",
        'remediation': "Remove docker-compose.yml (and similar deployment manifests) from the web root - these should never be served by the web server. Rotate any credentials that may have been embedded in it.",
    },
    {
        'name': 'Exposed AWS credentials file', 'path': '/.aws/credentials',
        'body_contains_any': ['aws_access_key_id', 'aws_secret_access_key'], 'not_html': True, 'rating': RATING_CRITICAL,
        'description': "An AWS credentials file is publicly accessible at the web root, disclosing an AWS access key ID and secret access key in plaintext.",
        'remediation': "Remove the .aws directory from the web root immediately, and treat the exposed key pair as compromised - deactivate/rotate it in IAM and review CloudTrail for any unauthorized use.",
    },
    {
        'name': 'Exposed .htpasswd file', 'path': '/.htpasswd',
        'body_contains_any': [':$apr1$', ':{SHA}', ':$2y$'], 'not_html': True, 'rating': RATING_HIGH,
        'description': "An .htpasswd file (Apache Basic Auth credential store) is publicly accessible, disclosing password hashes that can be attacked offline to recover the plaintext passwords they protect.",
        'remediation': "Remove or relocate .htpasswd outside the web root (or deny access to dotfiles via server config), and rotate the exposed credentials.",
    },
    {
        'name': 'Exposed private key (id_rsa)', 'path': '/id_rsa',
        'body_contains_any': ['-----BEGIN OPENSSH PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----'],
        'not_html': True, 'rating': RATING_CRITICAL,
        'description': "A private SSH/TLS key file is publicly accessible at the web root, potentially allowing an attacker to impersonate this host or authenticate as whatever principal the key was issued for.",
        'remediation': "Remove the private key from the web root immediately, and treat it as compromised - revoke/replace it (and any certificate issued for it) and audit for unauthorized use.",
    },
    {
        'name': 'Exposed .npmrc file', 'path': '/.npmrc',
        'body_contains_any': ['_authToken=', '_auth='], 'not_html': True, 'rating': RATING_HIGH,
        'description': "An .npmrc file is publicly accessible at the web root, potentially disclosing an npm registry auth token that could be used to publish malicious packages or download private packages under this identity.",
        'remediation': "Remove .npmrc from the web root, and rotate the exposed npm auth token (npm token revoke).",
    },
    {
        'name': 'Exposed database backup', 'path': '/backup.sql',
        'body_contains_any': ['CREATE TABLE', 'INSERT INTO', '-- MySQL dump', 'PostgreSQL database dump'],
        'not_html': True, 'rating': RATING_HIGH,
        'description': "A SQL database dump/backup file is publicly accessible at the web root, potentially disclosing the full contents of an application database (user records, credentials, business data).",
        'remediation': "Remove database backup/dump files from the web root - they should never be served by the web server. Store backups outside the webroot with restricted access, and rotate any credentials the dump may contain.",
    },
]

def _panel_signature_matches(resp, check):
    headers = {k.lower(): v for k, v in resp.headers.items()}
    if 'header_contains' in check:
        for hname, hval in check['header_contains'].items():
            if hname not in headers:
                return False
            if hval is not None and hval.lower() not in headers[hname].lower():
                return False
        return True
    if 'body_prefix' in check:
        return resp.text.startswith(check['body_prefix'])
    if 'body_contains_any' in check or 'body_contains_all' in check:
        body = resp.text
        if check.get('not_html') and re.search(r'<html|<!doctype', body[:500], re.IGNORECASE):
            return False
        if 'body_contains_all' in check:
            return all(sig in body for sig in check['body_contains_all'])
        return any(sig in body for sig in check['body_contains_any'])
    return False


def check_exposed_panels(host, asset_id):
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    found = []
    for check in EXPOSED_PANEL_CHECKS:
        resp = _http_get(base + check['path'])
        if resp is None or resp.status_code not in check.get('status_codes', [200]):
            continue
        if not _panel_signature_matches(resp, check):
            continue
        found.append(check['name'])
        issues.append(_new_issue(
            'exposed-panel-%s' % re.sub(r'[^a-z0-9]+', '-', check['name'].lower()).strip('-'),
            "Exposed %s detected" % check['name'],
            "%s Found at [%s]." % (check['description'], base + check['path']),
            check['rating'], asset_id, ISSUE_TYPE_EXPOSED_PANEL, object_id=base + check['path'],
            remediation=check['remediation']))

    if not found:
        issues.append(_new_issue(
            'exposed-panel-none-found', "No exposed admin panels or misconfigurations detected",
            "Checked [%s] known admin-panel/dev-tool/misconfiguration signatures (CI/CD tools, database management UIs, secrets managers, monitoring dashboards, exposed .git/.env/backup files, and information-disclosure endpoints) against [%s] and found none exposed." % (len(EXPOSED_PANEL_CHECKS), host),
            RATING_INFO, asset_id, ISSUE_TYPE_EXPOSED_PANEL, object_id=host,
            remediation="No action required. This checks a curated, high-confidence signature list, not an exhaustive one - periodic re-scanning is still worthwhile as new services get deployed."))
    return issues

