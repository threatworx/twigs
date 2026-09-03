"""Calibrated content / directory brute force.

A small, high-signal path list rather than a generic dirbuster wordlist, run
with soft-404 fingerprinting: three random paths are requested first to learn
what "not found" looks like on this host (status, body length, a normalised
body hash, and any blanket redirect), and a candidate is only reported when
its response is materially different from that baseline. High-value hits
(exposed VCS metadata, .env files, DB dumps, private keys) are additionally
content-verified before being rated.

This complements content_discovery (which mines the Wayback CDX for paths
that demonstrably existed) with an active probe for paths that may never have
been archived.
"""
import re
import hashlib
import logging
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL,
                        ISSUE_TYPE_WEB_APPLICATION, HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue

WORKERS = 12
RANDOM_PROBES = 3
LEN_TOLERANCE = 0.15        # +/- fraction of baseline length still "same as 404"
MAX_LISTED = 100

# Curated, high-signal. Ordered roughly by value; grouped only for readability.
CURATED_PATHS = [
    # --- VCS / SCM metadata
    '.git/HEAD', '.git/config', '.git/logs/HEAD', '.gitignore',
    '.svn/entries', '.svn/wc.db', '.hg/requires', '.bzr/README',
    # --- environment / secrets / config
    '.env', '.env.local', '.env.production', '.env.dev', '.env.backup',
    'config.php.bak', 'config.php~', 'wp-config.php.bak', 'wp-config.php~',
    'settings.py.bak', 'application.yml', 'application.properties',
    'appsettings.json', 'config.json', 'config.yml', 'config.yaml',
    'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile',
    '.aws/credentials', '.aws/config', '.npmrc', '.dockercfg', '.docker/config.json',
    '.ssh/id_rsa', 'id_rsa', 'id_dsa', '.htpasswd', '.netrc',
    # --- backups / dumps
    'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.tgz', 'www.zip',
    'site.zip', 'html.zip', 'db.sql', 'dump.sql', 'database.sql', 'data.sql',
    'db_backup.sql', '1.sql', 'latest.sql', 'mysql.sql',
    # --- build / CI / dependency manifests
    'package.json', 'package-lock.json', 'composer.json', 'composer.lock',
    'yarn.lock', 'Gemfile', 'Gemfile.lock', 'webpack.config.js',
    '.travis.yml', '.gitlab-ci.yml', '.circleci/config.yml', 'Jenkinsfile',
    '.github/workflows/', 'phpunit.xml',
    # --- framework debug / status / metrics
    'server-status', 'server-info', 'nginx_status', 'status',
    'actuator', 'actuator/env', 'actuator/health', 'actuator/heapdump',
    'actuator/mappings', 'metrics', 'debug/vars', 'debug/pprof/',
    '_profiler/', 'telescope/requests', 'horizon/api/stats', 'elmah.axd',
    'trace.axd', 'phpinfo.php', 'info.php', 'test.php',
    # --- panels / tools / editors
    'phpmyadmin/', 'pma/', 'adminer.php', 'adminer/', 'console', 'wp-admin/',
    'administrator/', 'admin/', 'manager/html', 'solr/', 'jenkins/',
    '.vscode/settings.json', '.idea/workspace.xml', '.DS_Store',
    # --- IaC / state
    'terraform.tfstate', '.terraform/terraform.tfstate', 'ansible.cfg',
    'inventory.ini', 'kustomization.yaml',
    # --- api / auth surface
    'graphql', 'graphiql', 'swagger-ui.html', 'api-docs', 'wp-json/wp/v2/users',
    'xmlrpc.php', '.well-known/openid-configuration', 'crossdomain.xml',
    'clientaccesspolicy.xml',
    # --- logs
    'storage/logs/laravel.log', 'logs/', 'log/', 'debug.log', 'error.log',
    'npm-debug.log',
]

# path -> (compiled body signature, is_critical) for content verification.
_VERIFY = {
    '.git/HEAD': (re.compile(rb'ref:\s+refs/'), False),
    '.git/config': (re.compile(rb'\[core\]'), False),
    '.git/logs/HEAD': (re.compile(rb'^[0-9a-f]{40} '), False),
    '.svn/entries': (re.compile(rb'^(8|9|10|11|12)\r?\n|svn:'), False),
    '.svn/wc.db': (re.compile(rb'SQLite format 3\x00'), False),
    '.hg/requires': (re.compile(rb'(revlogv1|dotencode|store)'), False),
    '.env': (re.compile(rb'(?m)^[A-Z][A-Z0-9_]*='), True),
    '.env.local': (re.compile(rb'(?m)^[A-Z][A-Z0-9_]*='), True),
    '.env.production': (re.compile(rb'(?m)^[A-Z][A-Z0-9_]*='), True),
    '.env.dev': (re.compile(rb'(?m)^[A-Z][A-Z0-9_]*='), True),
    '.env.backup': (re.compile(rb'(?m)^[A-Z][A-Z0-9_]*='), True),
    '.aws/credentials': (re.compile(rb'aws_secret_access_key', re.I), True),
    '.aws/config': (re.compile(rb'\[(default|profile )'), False),
    '.npmrc': (re.compile(rb'(_authToken|_auth|_password)=', re.I), True),
    '.dockercfg': (re.compile(rb'"auth"\s*:'), True),
    '.docker/config.json': (re.compile(rb'"auths"\s*:'), True),
    '.ssh/id_rsa': (re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----'), True),
    'id_rsa': (re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----'), True),
    'id_dsa': (re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----'), True),
    '.htpasswd': (re.compile(rb'^[^:\s]+:[\$A-Za-z0-9./]{4,}', re.M), True),
    '.netrc': (re.compile(rb'(machine|login|password)\s', re.I), True),
    'wp-config.php.bak': (re.compile(rb"DB_PASSWORD"), True),
    'wp-config.php~': (re.compile(rb"DB_PASSWORD"), True),
    'config.php.bak': (re.compile(rb'<\?php'), True),
    'config.php~': (re.compile(rb'<\?php'), True),
    'appsettings.json': (re.compile(rb'"ConnectionStrings"', re.I), True),
    'application.properties': (re.compile(rb'(?m)^(spring\.|server\.|datasource)'), False),
    'application.yml': (re.compile(rb'(?m)^(spring:|server:|datasource:)'), False),
    'terraform.tfstate': (re.compile(rb'"terraform_version"'), True),
    '.terraform/terraform.tfstate': (re.compile(rb'"terraform_version"'), True),
    '.DS_Store': (re.compile(rb'\x00\x00\x00\x01Bud1'), False),
    'package.json': (re.compile(rb'"(dependencies|name|version)"\s*:'), False),
    'composer.lock': (re.compile(rb'"packages"\s*:'), False),
    'actuator/heapdump': (re.compile(rb'^\x00|JAVA PROFILE|HPROF'), True),
    'actuator/env': (re.compile(rb'"(propertySources|activeProfiles)"'), False),
    'phpinfo.php': (re.compile(rb'<title>phpinfo\(\)'), False),
    'info.php': (re.compile(rb'<title>phpinfo\(\)'), False),
    'server-status': (re.compile(rb'Apache Server Status'), False),
}
_DUMP_RE = re.compile(rb'(INSERT INTO|CREATE TABLE|-- MySQL dump|PostgreSQL database dump|DROP TABLE IF EXISTS)', re.I)
_SENSITIVE_PREFIX = ('.git', '.svn', '.hg', '.bzr', '.env', '.aws', '.ssh',
                     'id_rsa', 'id_dsa', '.htpasswd', '.netrc', '.npmrc',
                     '.dockercfg', 'backup', 'dump', 'db', 'database', 'data.sql',
                     'terraform', 'wp-config', 'config.php', 'actuator/heapdump')


def _norm_hash(body):
    b = re.sub(rb'\s+', b' ', (body or b'')[:4000].lower())
    b = re.sub(rb'[0-9a-f]{8,}', b'', b)      # ids / csrf tokens / timestamps
    return hashlib.md5(b).hexdigest()


def _rand():
    import secrets
    return secrets.token_hex(12)


def _get(session, url):
    try:
        return session.get(url, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=False,
                           headers={'User-Agent': USER_AGENT})
    except requests.exceptions.RequestException:
        return None


def _baseline(session, base):
    """Learn this host's 'not found' signature. Returns a dict, or None if the
    site is unreachable / too unstable to calibrate."""
    samples = []
    for suffix in ('', '.php', '/', '.json', '.bak'):
        r = _get(session, '%s/%s%s' % (base, _rand(), suffix))
        if r is None:
            continue
        loc_host_path = ''
        if r.is_redirect or r.status_code in (301, 302, 307, 308):
            lp = urlsplit(r.headers.get('Location', ''))
            loc_host_path = (lp.netloc + lp.path).rstrip('/')
        samples.append((r.status_code, len(r.content or b''), _norm_hash(r.content), loc_host_path))
        if len(samples) >= RANDOM_PROBES:
            break
    if not samples:
        return None
    statuses = {s[0] for s in samples}
    hashes = {s[2] for s in samples}
    redirects = {s[3] for s in samples if s[3]}
    avg_len = sum(s[1] for s in samples) / len(samples)
    return {
        'statuses': statuses, 'hashes': hashes,
        'redirect_targets': redirects, 'avg_len': avg_len,
        'blanket_200': statuses == {200},
        'blanket_redirect': len(redirects) == 1 and all(s[3] for s in samples),
    }


def _is_soft404(resp, base):
    if resp is None:
        return True
    st = resp.status_code
    if st in (301, 302, 307, 308):
        lp = urlsplit(resp.headers.get('Location', ''))
        tgt = (lp.netloc + lp.path).rstrip('/')
        if base['blanket_redirect'] and tgt in base['redirect_targets']:
            return True
        if base['blanket_redirect'] and not base['redirect_targets']:
            return True
        return tgt in base['redirect_targets']
    if st not in base['statuses']:
        return False
    if _norm_hash(resp.content) in base['hashes']:
        return True
    blen = len(resp.content or b'')
    if base['avg_len'] and abs(blen - base['avg_len']) <= LEN_TOLERANCE * max(base['avg_len'], 1):
        return True
    return False


def _classify(path, resp, base):
    """Returns (severity, kind, note) or None to drop the hit."""
    st = resp.status_code
    body = resp.content or b''
    verifier = _VERIFY.get(path)
    is_dump = path.endswith('.sql') or path in ('www.zip', 'site.zip', 'html.zip', 'backup.zip', 'backup.tgz', 'backup.tar.gz')

    if st in (200, 203, 206):
        if verifier:
            rx, critical = verifier
            if rx.search(body):
                return (RATING_CRITICAL if critical else RATING_HIGH, 'verified',
                        'content matches the expected signature')
            return None            # 200 but wrong content -> catch-all page, drop
        if is_dump and _DUMP_RE.search(body[:8192]):
            return (RATING_CRITICAL, 'verified', 'response body contains SQL dump statements')
        if is_dump and body[:2] == b'PK':
            return (RATING_HIGH, 'verified', 'response is a ZIP archive')
        if len(body) == 0:
            return None
        return (RATING_MEDIUM, 'exists', 'returns HTTP 200')
    if st in (401, 403):
        if path.lower().startswith(_SENSITIVE_PREFIX):
            return (RATING_LOW, 'protected',
                    'returns HTTP %d - the sensitive path exists but is access-controlled' % st)
        return None
    if st in (500, 503):
        if 500 not in base['statuses'] and 503 not in base['statuses']:
            return (RATING_LOW, 'error', 'returns HTTP %d - the path is handled by the application' % st)
        return None
    return None


def _load_wordlist(args):
    wl = getattr(args, 'dir_brute_wordlist', None)
    if not wl:
        return list(CURATED_PATHS)
    try:
        with open(wl, 'r', encoding='utf-8', errors='replace') as fh:
            out = [ln.strip().lstrip('/') for ln in fh if ln.strip() and not ln.startswith('#')]
        return out[:2000] or list(CURATED_PATHS)
    except OSError as e:
        logging.warning("[EASM] dir_brute: cannot read --dir_brute_wordlist %s: %s", wl, e)
        return list(CURATED_PATHS)


def check_dir_brute(host, asset_id, args):
    if getattr(args, 'no_dir_brute', False) or not HAVE_REQUESTS:
        return []

    session = requests.Session()
    base = None
    for scheme in ('https', 'http'):
        try:
            session.get('%s://%s/' % (scheme, host), timeout=HTTP_TIMEOUT, verify=False,
                        headers={'User-Agent': USER_AGENT})
            base = '%s://%s' % (scheme, host)
            break
        except requests.exceptions.RequestException:
            continue
    if base is None:
        return []

    baseline = _baseline(session, base)
    if baseline is None:
        return []

    paths = _load_wordlist(args)

    def _probe(path):
        r = _get(session, '%s/%s' % (base, path))
        if _is_soft404(r, baseline):
            return None
        verdict = _classify(path, r, baseline)
        if verdict is None:
            return None
        sev, kind, note = verdict
        # On a blanket-200 host, only content-verified hits mean anything.
        if baseline['blanket_200'] and kind != 'verified':
            return None
        return (sev, kind, path, r.status_code, note)

    hits = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(_probe, p) for p in paths]
        for fut in as_completed(futs):
            try:
                h = fut.result()
            except Exception:
                h = None
            if h:
                hits.append(h)

    if not hits:
        return [_new_issue(
            'dir-brute-none', "No sensitive paths found by calibrated brute force",
            "Probed [%d] curated high-signal path(s) against [%s] with soft-404 fingerprinting and found nothing exposed." % (len(paths), host),
            RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            remediation="No action required. This is a small curated list, not an exhaustive content-discovery crawl.")]

    issues = []
    grouped = []
    grouped_kinds = set()
    for sev, kind, path, status, note in sorted(hits, key=lambda x: (-int(x[0]), x[2])):
        if kind == 'verified':
            title = "Sensitive file exposed: /%s" % path
            issues.append(_new_issue(
                'dir-brute-exposed-%s' % re.sub(r'[^a-z0-9]+', '-', path.lower()).strip('-'),
                title,
                "[%s/%s] is reachable without authentication (HTTP %d) and %s. Exposed VCS metadata, environment files, credentials, private keys, or database dumps typically hand an attacker source code, secrets, or direct data access."
                % (base, path, status, note),
                sev, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id='%s/%s' % (base, path),
                remediation="Remove this file from the web root immediately and rotate any credential, key, or token it exposed. Block dotfile/metadata directories (.git, .svn, .env, .aws, .ssh) at the web server or CDN, and serve application config from outside the document root."))
        else:
            grouped.append('/%s (HTTP %d - %s)' % (path, status, note))
            grouped_kinds.add(kind)

    if grouped:
        listed = grouped[:MAX_LISTED]
        more = '' if len(grouped) <= MAX_LISTED else ' (and %d more)' % (len(grouped) - MAX_LISTED)
        # A group of only 403/401 ("path is handled but access-controlled") or
        # 5xx hits is weak signal - often just the web server's default deny
        # rules for dotfiles/VCS dirs - so rate it LOW. A real 200 in the group
        # means something is actually being served: MEDIUM.
        if 'exists' in grouped_kinds:
            rating, headline = RATING_MEDIUM, "returned %d responsive path(s)" % len(grouped)
        else:
            rating, headline = RATING_LOW, ("returned %d path(s) that exist but are access-controlled or error out" % len(grouped))
        issues.append(_new_issue(
            'dir-brute-paths', "Calibrated path brute force found responsive paths",
            "Probing curated high-signal paths against [%s] (with soft-404 fingerprinting to suppress catch-all pages) %s - each differs from this host's not-found response%s:\n%s"
            % (host, headline, more, '\n'.join(listed)),
            rating, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=host,
            object_meta=','.join(g.split(' ')[0] for g in grouped[:50]),
            remediation="Review each path. Anything exposing admin functionality, debug/metrics endpoints, build manifests, backups, or config should be removed or placed behind authentication and a network ACL. Paths that only return 403 are usually the web server's default protection and are lower priority."))
    return issues
