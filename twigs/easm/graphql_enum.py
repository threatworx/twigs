"""GraphQL deep enumeration.

Goes beyond the single introspection probe in api_discovery:

  * introspection ON  -> dump and summarise the schema: root query / mutation
    / subscription field counts, total type count, the mutation (state-
    changing) root field names, and any field whose name looks sensitive
    (password / token / admin / delete / impersonate / ...).
  * introspection OFF -> recover field names anyway via the server's
    "Did you mean ...?" field-suggestion behaviour and a small root-field
    wordlist, and flag an exposed GraphiQL / Playground console, query
    batching (request-amplification / brute-force aid), and GET-based query
    execution (CSRF).

One bounded pass against the first responding GraphQL endpoint found.
"""
import re
import json
import logging

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH,
                        ISSUE_TYPE_API, HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, _http_get

try:
    from .api_discovery import GRAPHQL_PATHS
except Exception:                       # pragma: no cover - defensive
    GRAPHQL_PATHS = ['/graphql', '/graphql/', '/api/graphql', '/v1/graphql', '/query']

FULL_INTROSPECTION = {'query': (
    'query{__schema{queryType{name} mutationType{name} subscriptionType{name} '
    'types{name kind fields{name} inputFields{name}}}}')}

SENSITIVE_RE = re.compile(
    r'(?:^|_)(?:password|passwd|secret|secrets|token|tokens|apikey|api_key|'
    r'credential|credentials|private|privatekey|ssn|creditcard|card_number|'
    r'admin|superuser|impersonate|internal|debug|sudo|role|roles|permission|'
    r'permissions|grant|revoke|delete|destroy|drop|truncate|reset|disable)', re.I)

ROOT_FIELD_WORDLIST = [
    'user', 'users', 'me', 'viewer', 'currentUser', 'account', 'accounts',
    'node', 'nodes', 'search', 'admin', 'adminUser', 'organization',
    'organizations', 'team', 'teams', 'project', 'projects', 'order', 'orders',
    'product', 'products', 'customer', 'customers', 'payment', 'payments',
    'invoice', 'invoices', 'file', 'files', 'session', 'sessions', 'secret',
    'secrets', 'config', 'settings', 'apiKey', 'apiKeys', 'token', 'tokens',
    'role', 'roles', 'permission', 'permissions',
]

_SUGGEST_RE = re.compile(r'did you mean', re.I)
_NO_FIELD_RE = re.compile(r"cannot query field|isn't defined|is not defined|"
                          r"unknown field|no field", re.I)
_NEEDS_SUBFIELD_RE = re.compile(r"must have a selection of subfields|"
                                r"of type .* must have a sub selection", re.I)
_CONSOLE_MARKERS = ('graphiql', 'graphql playground', 'playground-request',
                    '__apollo_devtools', 'apollo-server-landing-page',
                    'graphql-playground')


def _slug(value):
    return re.sub(r'[^a-z0-9]+', '-', value.lower()).strip('-') or 'root'


def _post(url, payload, as_form=False):
    try:
        if as_form:
            return requests.post(url, data=payload, timeout=HTTP_TIMEOUT, verify=False,
                                 allow_redirects=False,
                                 headers={'User-Agent': USER_AGENT,
                                          'Content-Type': 'application/x-www-form-urlencoded'})
        return requests.post(url, json=payload, timeout=HTTP_TIMEOUT, verify=False,
                             allow_redirects=False,
                             headers={'User-Agent': USER_AGENT,
                                      'Content-Type': 'application/json'})
    except requests.exceptions.RequestException:
        return None


def _json(resp):
    if resp is None:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _error_text(data):
    if not isinstance(data, dict):
        return ''
    errs = data.get('errors')
    if not isinstance(errs, list):
        return ''
    return ' '.join(str(e.get('message', '')) for e in errs if isinstance(e, dict))


def _looks_like_graphql(data):
    if not isinstance(data, dict):
        return False
    if 'data' in data:
        return True
    return bool(_error_text(data))


def _find_endpoint(base):
    for path in GRAPHQL_PATHS:
        url = base + path
        data = _json(_post(url, {'query': '{__typename}'}))
        if _looks_like_graphql(data):
            return url, data
    return None, None


def _introspect(url):
    data = _json(_post(url, FULL_INTROSPECTION))
    if not isinstance(data, dict):
        return None
    schema = (data.get('data') or {}).get('__schema') if isinstance(data.get('data'), dict) else None
    if not isinstance(schema, dict) or not schema.get('queryType'):
        return None
    return schema


def _summarise_schema(schema):
    types = [t for t in schema.get('types', []) if isinstance(t, dict)]
    type_names = {t.get('name') for t in types}
    qt = (schema.get('queryType') or {}).get('name')
    mt = (schema.get('mutationType') or {}).get('name')
    st = (schema.get('subscriptionType') or {}).get('name')

    def _root_fields(root_name):
        for t in types:
            if t.get('name') == root_name:
                return [f.get('name') for f in (t.get('fields') or []) if isinstance(f, dict) and f.get('name')]
        return []

    queries = _root_fields(qt)
    mutations = _root_fields(mt)
    subscriptions = _root_fields(st)

    all_fields = set(queries) | set(mutations) | set(subscriptions)
    for t in types:
        for f in (t.get('fields') or []):
            if isinstance(f, dict) and f.get('name'):
                all_fields.add(f['name'])
    sensitive = sorted(f for f in all_fields if SENSITIVE_RE.search(f or ''))
    # ignore the introspection meta-types when counting
    real_types = sorted(n for n in type_names if n and not n.startswith('__'))
    return {
        'query_fields': sorted(queries), 'mutations': sorted(mutations),
        'subscriptions': sorted(subscriptions), 'type_count': len(real_types),
        'sensitive': sensitive,
    }


def _field_exists(url, field):
    """Probe a single root field. Returns True if the server's error message
    indicates the field is real (needs a sub-selection / bad args) rather than
    unknown."""
    data = _json(_post(url, {'query': '{%s}' % field}))
    if not isinstance(data, dict):
        return False
    if isinstance(data.get('data'), dict) and field in data['data']:
        return True
    msg = _error_text(data)
    if not msg:
        return False
    if _NO_FIELD_RE.search(msg):
        return False
    if _NEEDS_SUBFIELD_RE.search(msg) or 'argument' in msg.lower():
        return True
    return False


def check_graphql_enum(host, asset_id, args):
    if getattr(args, 'no_graphql_enum', False) or not HAVE_REQUESTS:
        return []

    base = None
    for scheme in ('https', 'http'):
        if _http_get('%s://%s/' % (scheme, host)) is not None:
            base = '%s://%s' % (scheme, host)
            break
    if base is None:
        return []

    url, _probe = _find_endpoint(base)
    if not url:
        return []

    issues = []
    schema = _introspect(url)

    if schema:
        s = _summarise_schema(schema)
        detail = ("GraphQL endpoint [%s] has introspection enabled and returned its full schema: "
                  "%d type(s), %d root query field(s), %d mutation (state-changing) root field(s), %d subscription(s)."
                  % (url, s['type_count'], len(s['query_fields']), len(s['mutations']), len(s['subscriptions'])))
        if s['mutations']:
            sample = ', '.join(s['mutations'][:30])
            detail += " Mutation root fields: %s%s." % (sample, ' ...' if len(s['mutations']) > 30 else '')
        rating = RATING_MEDIUM
        if s['sensitive']:
            detail += (" Fields with sensitive-looking names are exposed in the schema: %s%s."
                       % (', '.join(s['sensitive'][:40]), ' ...' if len(s['sensitive']) > 40 else ''))
            if s['mutations']:
                rating = RATING_HIGH
        issues.append(_new_issue(
            'graphql-introspection-schema', "GraphQL introspection exposes full schema",
            detail, rating, asset_id, ISSUE_TYPE_API, object_id=url,
            object_meta=','.join((s['mutations'] + s['sensitive'])[:50]),
            remediation="Disable introspection in production (a config flag in every major GraphQL server library) or restrict it to authenticated internal callers. Independently confirm that the sensitive/mutating fields above enforce authorization server-side - a hidden schema is not an access control."))
    else:
        recovered = []
        suggestion = False
        # 1. field-suggestion oracle
        bogus = _json(_post(url, {'query': '{qqzzbogusfield}'}))
        if _SUGGEST_RE.search(_error_text(bogus) or ''):
            suggestion = True
        # 2. small root-field wordlist
        for field in ROOT_FIELD_WORDLIST:
            try:
                if _field_exists(url, field):
                    recovered.append(field)
            except Exception:
                continue
        if suggestion or recovered:
            detail = "GraphQL endpoint [%s] has introspection disabled" % url
            if suggestion:
                detail += (", but still returns \"Did you mean ...?\" field suggestions, which let the schema be reconstructed field by field despite introspection being off")
            if recovered:
                detail += (". Probing a small list of common root field names confirmed %d of them exist: %s"
                           % (len(recovered), ', '.join(recovered)))
            detail += "."
            issues.append(_new_issue(
                'graphql-field-suggestion', "GraphQL schema recoverable despite introspection being disabled",
                detail, RATING_MEDIUM, asset_id, ISSUE_TYPE_API, object_id=url,
                object_meta=','.join(recovered[:50]),
                remediation="Turn off field-suggestion / \"Did you mean\" hints in production (e.g. graphql-js: set a custom validation rule or a formatError that strips suggestions; Apollo Server: disable in production). Disabling introspection alone is not sufficient."))

    # --- checks that apply regardless of introspection state ---------------
    get_resp = None
    try:
        get_resp = requests.get(url, params={'query': '{__typename}'}, timeout=HTTP_TIMEOUT,
                                verify=False, allow_redirects=False,
                                headers={'User-Agent': USER_AGENT})
    except requests.exceptions.RequestException:
        pass
    gdata = _json(get_resp)
    if isinstance(gdata, dict) and isinstance(gdata.get('data'), dict) and gdata['data'].get('__typename'):
        issues.append(_new_issue(
            'graphql-get-exec', "GraphQL executes queries sent via HTTP GET",
            "GraphQL endpoint [%s] executes operations supplied in the query string of a GET request. GET-executable GraphQL is reachable via simple cross-site requests and cacheable by intermediaries, widening CSRF and cache-poisoning exposure." % url,
            RATING_LOW, asset_id, ISSUE_TYPE_API, object_id=url,
            remediation="Accept GraphQL operations only over POST with Content-Type application/json, and reject GET (or restrict GET to persisted/allow-listed queries). Enable CSRF-prevention mode if your server offers it (e.g. Apollo Server csrfPrevention)."))

    batch = _json(_post(url, [{'query': '{__typename}'}, {'query': '{__typename}'}]))
    if isinstance(batch, list) and len(batch) == 2:
        issues.append(_new_issue(
            'graphql-batching', "GraphQL query batching enabled",
            "GraphQL endpoint [%s] accepts a JSON array of operations in one request (query batching). Batching lets an attacker run many operations per HTTP request, amplifying brute-force / credential-stuffing against mutations and bypassing per-request rate limits." % url,
            RATING_LOW, asset_id, ISSUE_TYPE_API, object_id=url,
            remediation="Disable array-based batching in production if unused, or enforce a low per-request operation cap plus query-cost/depth limiting and rate limiting that accounts for batched operations."))

    console_resp = _http_get(url)
    if console_resp is not None and console_resp.status_code == 200:
        body_l = (console_resp.text or '')[:20000].lower()
        if any(m in body_l for m in _CONSOLE_MARKERS):
            issues.append(_new_issue(
                'graphql-console-exposed', "GraphQL IDE console exposed (GraphiQL / Playground)",
                "GraphQL endpoint [%s] serves an interactive in-browser IDE (GraphiQL or GraphQL Playground) to unauthenticated visitors. These consoles auto-run introspection and give an attacker a ready-made query workbench against the API." % url,
                RATING_MEDIUM, asset_id, ISSUE_TYPE_API, object_id=url,
                remediation="Disable the GraphiQL / Playground / Apollo landing page in production, or gate it behind authentication and an internal network ACL."))

    if not issues:
        issues.append(_new_issue(
            'graphql-hardened', "GraphQL endpoint found and appears hardened",
            "A GraphQL endpoint was found at [%s]: introspection is disabled, no \"Did you mean\" field suggestions were returned, no interactive console is exposed, GET execution and query batching are not enabled." % url,
            RATING_INFO, asset_id, ISSUE_TYPE_API, object_id=url,
            remediation="No action required. Confirm query depth/cost limiting and rate limiting are also in place."))
    return issues
