"""API discovery/testing: OpenAPI/Swagger spec discovery (with parsing for
endpoint count and unauthenticated endpoints), GraphQL introspection, CORS
misconfiguration (arbitrary origin reflection), and verbose error/stack-trace
disclosure. Deliberately excludes anything resembling load/rate-limit testing
(would require request bursts against a third party) or BOLA/IDOR/business-
logic testing (requires authenticated context, not just passive discovery)."""
import re
import json
import yaml
import logging

import requests

from .constants import RATING_INFO, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_API, HTTP_TIMEOUT, USER_AGENT
from .util import _http_get, _new_issue

OPENAPI_SPEC_PATHS = [
    '/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs',
    '/api-docs', '/api/swagger.json', '/api/openapi.json',
    '/swagger/v1/swagger.json', '/openapi.yaml', '/swagger.yaml',
    '/apidocs', '/apispec.json', '/apispec_1.json',
]

GRAPHQL_PATHS = ['/graphql', '/graphql/', '/api/graphql', '/v1/graphql', '/query']
GRAPHQL_INTROSPECTION_QUERY = {'query': '{__schema{queryType{name}}}'}

# Deliberately a plain JSON syntax error (not an injection payload) - this
# reliably short-circuits at the framework's body-parsing middleware in
# virtually all stacks, before any business logic/route handler runs, so it
# is safe to send to any endpoint including ones that would otherwise mutate
# state.
MALFORMED_JSON_BODY = '{"malformed": tru'

STACK_TRACE_SIGNATURES = [
    'Traceback (most recent call last)', 'django.core.exceptions',
    'at java.', 'at org.springframework', 'Exception in thread',
    'System.Exception', 'at System.', 'Microsoft.AspNetCore',
    'node_modules/', 'TypeError: ', '    at Object.',
    'Fatal error:', 'Stack trace:', '#0 {main}',
    'SQLSTATE[', 'ORA-0', 'You have an error in your SQL syntax',
]


def _try_parse_openapi_spec(text):
    spec = None
    try:
        spec = json.loads(text)
    except Exception:
        try:
            spec = yaml.safe_load(text)
        except Exception:
            return None
    if not isinstance(spec, dict):
        return None
    if ('swagger' not in spec and 'openapi' not in spec) or not isinstance(spec.get('paths'), dict):
        return None
    return spec


def _openapi_has_security_scheme(spec):
    """True if the spec defines *any* security scheme anywhere (Swagger 2.0
    securityDefinitions or OpenAPI 3.x components.securitySchemes/security).
    A spec with none of these doesn't model authentication at all, which is a
    different (weaker) signal than a spec that defines a scheme and then
    explicitly excludes specific operations from it."""
    if spec.get('securityDefinitions') or spec.get('security'):
        return True
    components = spec.get('components')
    if isinstance(components, dict) and components.get('securitySchemes'):
        return True
    return False


def _openapi_endpoint_stats(spec):
    """Returns (total_operation_count, list_of_unauthenticated_operations),
    counting path+method operations consistently in both."""
    global_security = spec.get('security')
    total = 0
    unauth = []
    for path, ops in spec.get('paths', {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ('get', 'post', 'put', 'delete', 'patch', 'options', 'head'):
                continue
            if not isinstance(op, dict):
                continue
            total += 1
            effective_security = op.get('security', global_security)
            if not effective_security:
                unauth.append('%s %s' % (method.upper(), path))
    return total, unauth


def _slugify(value):
    return re.sub(r'[^a-z0-9]+', '-', value.lower()).strip('-')


def check_api_discovery(host, asset_id):
    issues = []
    base = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            base = "%s://%s" % (scheme, host)
            break
    if base is None:
        return issues

    found_anything = False
    followup_targets = []

    # 1. OpenAPI/Swagger spec discovery
    for path in OPENAPI_SPEC_PATHS:
        resp = _http_get(base + path)
        if resp is None or resp.status_code != 200:
            continue
        spec = _try_parse_openapi_spec(resp.text)
        if not spec:
            continue
        found_anything = True
        followup_targets.append(base + path)
        has_security_scheme = _openapi_has_security_scheme(spec)
        endpoint_count, unauth = _openapi_endpoint_stats(spec)
        info = spec.get('info') if isinstance(spec.get('info'), dict) else {}
        title = info.get('title')
        detail = "An OpenAPI/Swagger specification%s was found at [%s], declaring [%s] endpoint(s)." % (
            (' for "%s"' % title) if title else '', base + path, endpoint_count)

        if not has_security_scheme:
            # The spec doesn't define a security scheme anywhere - this is a
            # documentation gap, not confirmed open access: many APIs enforce
            # authentication via mechanisms (API gateways, custom middleware,
            # query-param tokens) that standard OpenAPI security metadata
            # doesn't capture, so this must not be reported as if every
            # operation were verified unauthenticated.
            rating = RATING_MEDIUM
            detail += (" The spec does not define any authentication/security scheme for any endpoint. This does not confirm the live API is actually unauthenticated - "
                       "many APIs enforce access control via mechanisms (gateways, custom middleware, query-param tokens) that aren't reflected in OpenAPI security metadata - "
                       "but it is a documentation gap worth fixing regardless, and it does mean this spec gives no assurance about which operations require authentication.")
            remediation = "Add accurate security/securityDefinitions metadata to the spec so consumers (and scanners) can tell which endpoints require authentication. Independently verify actual runtime access control for write/delete operations rather than relying on this spec."
        elif unauth:
            sample = ', '.join(unauth[:10])
            more = ' (and %s more)' % (len(unauth) - 10) if len(unauth) > 10 else ''
            rating = RATING_HIGH
            detail += " [%s] of these endpoint(s) explicitly declare no authentication requirement in the spec, despite a security scheme being defined for the rest: %s%s." % (len(unauth), sample, more)
            remediation = "Verify this is intentional (public/read-only endpoints) rather than a missing security requirement on these specific operations - unauthenticated write/delete operations are particularly high risk."
        else:
            rating = RATING_MEDIUM
            detail += " All endpoints declare an authentication requirement in the spec (this reflects the spec's stated intent, not independently verified access control)."
            remediation = "No action required beyond confirming the spec itself should be public."

        issues.append(_new_issue(
            'api-openapi-spec-%s' % _slugify(path),
            "OpenAPI/Swagger specification exposed" + (" with unauthenticated endpoints" if (has_security_scheme and unauth) else ""),
            detail, rating, asset_id, ISSUE_TYPE_API, object_id=base + path,
            remediation="Publishing an API spec is often intentional - confirm it is meant to be public. " + remediation))
        break

    # 2. GraphQL introspection
    for path in GRAPHQL_PATHS:
        url = base + path
        try:
            resp = requests.post(url, json=GRAPHQL_INTROSPECTION_QUERY, timeout=HTTP_TIMEOUT, verify=False,
                                  headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/json'})
        except requests.exceptions.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        schema = ((data.get('data') or {}).get('__schema') or {}) if isinstance(data.get('data'), dict) else {}
        query_type = schema.get('queryType') if isinstance(schema, dict) else None
        if isinstance(query_type, dict) and query_type.get('name'):
            found_anything = True
            followup_targets.append(url)
            issues.append(_new_issue(
                'api-graphql-introspection-%s' % _slugify(path),
                "GraphQL introspection enabled",
                "A GraphQL endpoint was found at [%s] with introspection enabled, allowing the full API schema (types, fields, mutations, including any not used by the official client) to be queried and mapped by anyone." % url,
                RATING_MEDIUM, asset_id, ISSUE_TYPE_API, object_id=url,
                remediation="Disable introspection in production (most GraphQL server libraries support this via a configuration flag), or restrict it to authenticated/internal callers only."))
            break
        elif data.get('errors') or 'data' in data:
            found_anything = True
            followup_targets.append(url)
            issues.append(_new_issue(
                'api-graphql-found-%s' % _slugify(path),
                "GraphQL endpoint found (introspection appears disabled)",
                "A GraphQL endpoint was found at [%s]. Introspection appears to be disabled or restricted, which is good practice." % url,
                RATING_INFO, asset_id, ISSUE_TYPE_API, object_id=url,
                remediation="No action required. Confirm introspection is intentionally disabled in production."))
            break

    # 3. CORS misconfiguration - test the site root plus anything discovered above
    fake_origin = 'https://easm-cors-probe.invalid'
    for url in [base + '/'] + followup_targets:
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False,
                                 headers={'User-Agent': USER_AGENT, 'Origin': fake_origin})
        except requests.exceptions.RequestException:
            continue
        acao = resp.headers.get('Access-Control-Allow-Origin')
        acac = (resp.headers.get('Access-Control-Allow-Credentials') or '').lower() == 'true'
        if acao == fake_origin:
            found_anything = True
            rating = RATING_CRITICAL if acac else RATING_MEDIUM
            impact = ("with the requesting browser's cookies/session included (Access-Control-Allow-Credentials: true), enabling cross-site data theft"
                      if acac else "and read the response, though without Access-Control-Allow-Credentials the impact is limited to non-authenticated data")
            issues.append(_new_issue(
                'api-cors-misconfig-%s' % _slugify(url),
                "CORS misconfiguration: arbitrary origin reflected" + (" with credentials allowed" if acac else ""),
                "[%s] reflects an arbitrary, attacker-controlled Origin header back in the Access-Control-Allow-Origin response header. This allows any website to make cross-origin requests to this endpoint %s." % (url, impact),
                rating, asset_id, ISSUE_TYPE_API, object_id=url,
                remediation="Do not reflect arbitrary Origin header values. Validate Origin against an explicit allow-list of trusted domains, and never combine a reflected/wildcard origin with Access-Control-Allow-Credentials: true."))
            break

    # 4. Verbose error / stack trace disclosure
    for url in [base + '/'] + followup_targets:
        try:
            resp = requests.post(url, data=MALFORMED_JSON_BODY, timeout=HTTP_TIMEOUT, verify=False,
                                  headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/json'})
        except requests.exceptions.RequestException:
            continue
        matched_sig = next((sig for sig in STACK_TRACE_SIGNATURES if sig in resp.text), None)
        if matched_sig:
            found_anything = True
            issues.append(_new_issue(
                'api-verbose-error-%s' % _slugify(url),
                "Verbose error/stack trace disclosure",
                "Sending a deliberately malformed JSON request body to [%s] produced a response containing what appears to be a framework stack trace or internal error detail (matched signature: \"%s\"). Verbose error output can disclose internal file paths, framework/library versions, and code structure useful for further attacks." % (url, matched_sig),
                RATING_MEDIUM, asset_id, ISSUE_TYPE_API, object_id=url,
                remediation="Disable debug/verbose error output in production (e.g. Flask/Django DEBUG=False, ASP.NET Core developer exception page only in Development, Spring Boot server.error.include-stacktrace=never), and return generic error responses to clients while logging full details server-side only."))
            break

    if not found_anything:
        issues.append(_new_issue(
            'api-discovery-none-found', "No exposed API surface findings",
            "Checked for OpenAPI/Swagger specifications, GraphQL endpoints (with introspection), CORS misconfiguration, and verbose error disclosure against [%s] and found nothing to report." % host,
            RATING_INFO, asset_id, ISSUE_TYPE_API, object_id=host,
            remediation="No action required. This checks a curated set of common paths/behaviors, not an exhaustive one."))
    return issues

