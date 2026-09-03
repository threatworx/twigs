"""OpenAPI active probing.

api_discovery reports that a spec exists and *states* which operations declare
no security scheme. This module verifies that claim at runtime: it re-fetches
the spec, then issues a bounded set of GET / HEAD requests (never a write
method) to the documented operations that (a) declare no authentication and
(b) can be addressed without guessing required parameters, and reports which
ones actually return data with no credentials versus which are really
protected (401 / 403).
"""
import re
import logging
from urllib.parse import urljoin, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH,
                        ISSUE_TYPE_API, HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, _http_get, get_registered_domain

try:
    from .api_discovery import (OPENAPI_SPEC_PATHS, _try_parse_openapi_spec,
                                _openapi_has_security_scheme)
except Exception:                       # pragma: no cover - defensive
    OPENAPI_SPEC_PATHS = ['/swagger.json', '/openapi.json', '/v3/api-docs', '/v2/api-docs']

    def _try_parse_openapi_spec(text):
        return None

    def _openapi_has_security_scheme(spec):
        return False

MAX_PROBE = 40          # documented operations probed per host
WORKERS = 8
_SAFE_METHODS = ('get', 'head')
_LOGIN_RE = re.compile(r'(login|signin|sign-in|auth|sso|oauth|account/login)', re.I)


def _spec_base(site_base, spec, spec_url):
    """Best-effort resolution of the API base URL from the spec, constrained
    to the same registrable domain as the host being scanned (never chase a
    spec onto third-party infrastructure)."""
    site_host = urlsplit(site_base).hostname or ''
    reg = get_registered_domain(site_host) if site_host else ''

    candidate = None
    servers = spec.get('servers')
    if isinstance(servers, list) and servers and isinstance(servers[0], dict) and servers[0].get('url'):
        candidate = urljoin(spec_url, servers[0]['url'])
    else:
        host = spec.get('host')
        if host:
            scheme = 'https'
            schemes = spec.get('schemes')
            if isinstance(schemes, list) and schemes:
                scheme = 'https' if 'https' in schemes else schemes[0]
            candidate = '%s://%s%s' % (scheme, host, spec.get('basePath', '') or '')
        elif spec.get('basePath'):
            candidate = urljoin(site_base + '/', spec['basePath'].lstrip('/'))

    if not candidate:
        return site_base.rstrip('/')

    chost = urlsplit(candidate).hostname or ''
    if chost and reg and get_registered_domain(chost) != reg:
        # spec points off-domain - fall back to the site itself
        path = urlsplit(candidate).path or ''
        return (site_base.rstrip('/') + path).rstrip('/')
    return candidate.rstrip('/')


def _fill_params(path, op):
    """Return a concrete path if every {param} can be filled from an
    example / default / enum in the operation's parameter list, else None.
    No blind dummy values - an unknown id could hit real data."""
    needed = re.findall(r'\{([^}]+)\}', path)
    if not needed:
        return path
    params = op.get('parameters') if isinstance(op.get('parameters'), list) else []
    values = {}
    for p in params:
        if not isinstance(p, dict) or p.get('in') != 'path':
            continue
        name = p.get('name')
        schema = p.get('schema') if isinstance(p.get('schema'), dict) else {}
        val = (p.get('example') if p.get('example') is not None else
               p.get('default') if p.get('default') is not None else
               schema.get('example') if schema.get('example') is not None else
               schema.get('default') if schema.get('default') is not None else None)
        if val is None:
            enum = schema.get('enum') or p.get('enum')
            if isinstance(enum, list) and enum:
                val = enum[0]
        if val is not None and name:
            values[name] = val
    out = path
    for n in needed:
        if n not in values:
            return None
        out = out.replace('{%s}' % n, str(values[n]))
    return out


def _safe_operations(spec):
    """[(method, resolved_path)] for GET/HEAD operations that declare no
    effective security and whose path can be built without guessing."""
    global_security = spec.get('security')
    ops = []
    for path, methods in (spec.get('paths') or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in _SAFE_METHODS or not isinstance(op, dict):
                continue
            effective = op.get('security', global_security)
            if effective:                       # declares auth - not our target
                continue
            resolved = _fill_params(path, op)
            if resolved is None:
                continue
            ops.append((method.upper(), resolved))
    # de-dup, stable order
    seen = set()
    uniq = []
    for m, p in ops:
        if (m, p) not in seen:
            seen.add((m, p))
            uniq.append((m, p))
    return uniq[:MAX_PROBE]


def _probe(api_base, method, path):
    url = api_base + ('' if path.startswith('/') else '/') + path
    try:
        resp = requests.request(method, url, timeout=HTTP_TIMEOUT, verify=False,
                                allow_redirects=False,
                                headers={'User-Agent': USER_AGENT, 'Accept': 'application/json, */*'})
    except requests.exceptions.RequestException:
        return (method, path, url, None, 0, '')
    body = resp.content or b''
    loc = resp.headers.get('Location', '')
    return (method, path, url, resp.status_code, len(body), loc)


def check_openapi_probe(host, asset_id, args):
    if getattr(args, 'no_openapi_probe', False) or not HAVE_REQUESTS:
        return []

    site_base = None
    for scheme in ('https', 'http'):
        if _http_get('%s://%s/' % (scheme, host)) is not None:
            site_base = '%s://%s' % (scheme, host)
            break
    if site_base is None:
        return []

    spec = None
    spec_url = None
    for p in OPENAPI_SPEC_PATHS:
        r = _http_get(site_base + p)
        if r is None or r.status_code != 200:
            continue
        parsed = _try_parse_openapi_spec(r.text)
        if parsed:
            spec, spec_url = parsed, site_base + p
            break
    if not spec:
        return []

    ops = _safe_operations(spec)
    if not ops:
        return []

    api_base = _spec_base(site_base, spec, spec_url)
    logging.info("[EASM] openapi_probe: [%s] probing %d documented no-auth GET/HEAD op(s) under %s",
                 host, len(ops), api_base)

    reachable, protected, not_found, inconclusive = [], [], [], []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(_probe, api_base, m, p) for m, p in ops]
        for fut in as_completed(futs):
            method, path, url, status, blen, loc = fut.result()
            label = '%s %s' % (method, path)
            if status is None:
                inconclusive.append(label)
            elif status in (200, 203, 206):
                reachable.append('%s -> HTTP %s, %d byte(s)' % (label, status, blen))
            elif status == 204:
                reachable.append('%s -> HTTP 204 (empty)' % label)
            elif status in (401, 403):
                protected.append(label)
            elif status in (301, 302, 307, 308):
                (protected if _LOGIN_RE.search(loc or '') else inconclusive).append(
                    '%s -> HTTP %s %s' % (label, status, loc[:120]))
            elif status == 404:
                not_found.append(label)
            else:
                inconclusive.append('%s -> HTTP %s' % (label, status))

    issues = []
    spec_says_open = not _openapi_has_security_scheme(spec)

    if reachable:
        listed = reachable[:30]
        more = '' if len(reachable) <= 30 else ' (and %d more)' % (len(reachable) - 30)
        issues.append(_new_issue(
            'openapi-unauth-endpoints-live', "Documented API endpoints reachable without authentication",
            "The OpenAPI spec at [%s] documents operations that declare no authentication. Sending an unauthenticated GET/HEAD to each, %d returned a non-error response (data served with no credentials)%s:\n%s"
            % (spec_url, len(reachable), more, '\n'.join(listed)),
            RATING_HIGH, asset_id, ISSUE_TYPE_API, object_id=api_base,
            object_meta=','.join(x.split(' -> ')[0] for x in reachable[:50]),
            remediation="Confirm each of these endpoints is intended to be fully public and read-only. Put authentication/authorization in front of any that expose customer, account, internal, or configuration data, and remove them from the public spec if they are not meant to be discoverable. Rate-limit the rest."))
    elif protected and len(protected) >= 3 and not inconclusive:
        issues.append(_new_issue(
            'openapi-endpoints-protected', "Documented no-auth API endpoints actually enforce authentication",
            "The OpenAPI spec at [%s] marks %d GET/HEAD operation(s) as requiring no authentication, but every one probed returned HTTP 401/403 - runtime access control is stricter than the spec advertises."
            % (spec_url, len(protected)),
            RATING_INFO, asset_id, ISSUE_TYPE_API, object_id=api_base,
            remediation="Update the spec's security metadata to match reality so it does not understate the API's protection (and so scanners/consumers are not misled). No access-control change needed."))
    elif reachable or protected or inconclusive:
        detail = ("Actively probed %d documented no-auth GET/HEAD operation(s) from the OpenAPI spec at [%s]: "
                  "%d reachable, %d protected (401/403), %d not found (spec drift), %d inconclusive."
                  % (len(ops), spec_url, len(reachable), len(protected), len(not_found), len(inconclusive)))
        if spec_says_open:
            detail += " The spec also defines no security scheme anywhere."
        issues.append(_new_issue(
            'openapi-endpoints-probed', "OpenAPI documented endpoints actively probed",
            detail, RATING_LOW, asset_id, ISSUE_TYPE_API, object_id=api_base,
            remediation="Review any reachable endpoint listed as an api-openapi finding above. Align the spec's security metadata with the API's real behaviour."))
    return issues
