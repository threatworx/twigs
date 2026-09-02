"""SaaS tenant discovery for a domain.

A large share of an organisation's real attack surface is not hosted by the
organisation at all - it is SaaS tenants it owns: the SSO portal, the wiki,
the ticketing system, the code org, the file share. This module derives the
organisation's identity (org_identity.derive), then:

  1. PASSIVE  - reads MX / SPF and Entra ID's unauthenticated discovery
                endpoints to confirm tenants with zero brute force.
  2. ACTIVE   - probes each candidate slug against a registry of SaaS
                providers (one HTTPS GET per provider/slug), confirming a
                tenant only on a provider-specific response fingerprint,
                never on bare DNS existence.
  3. ENRICH   - on a *confirmed* tenant, runs unauthenticated read-only
                checks for real misconfiguration: anonymous Confluence/Jira
                read, open Slack email-domain signup, exposed AWS SSO portal,
                on-prem federation (ADFS) endpoints, ServiceNow version
                disclosure, GitHub org repos (optionally secret-scanned with
                --github_repo_scan).

Everything is unauthenticated and read-only. No credentials are ever
submitted (that is a separate, explicitly opt-in capability). Every network
call is bounded; a provider that errors is skipped. Disable the whole module
with --no_saas_discovery.
"""
import io
import os
import re
import tarfile
import logging
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL,
                        ISSUE_TYPE_EXPOSED_PANEL, ISSUE_TYPE_WEB_APPLICATION,
                        ISSUE_TYPE_CREDENTIAL_LEAK, HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, get_registered_domain, HAVE_DNSPYTHON, _get_dns_resolver, _resolve_record
from . import org_identity
from .js_analysis import _SECRET_RULES

WORKERS = 20
HDRS = {'User-Agent': USER_AGENT}

# GitHub repo secret-scan bounds (opt-in path only)
GH_TARBALL_CAP = 15 * 1024 * 1024
GH_MEMBER_CAP = 512 * 1024
GH_TEXT_EXT = ('.js', '.ts', '.py', '.rb', '.go', '.java', '.php', '.sh', '.yml', '.yaml',
               '.json', '.env', '.txt', '.cfg', '.conf', '.ini', '.tf', '.tfvars',
               '.properties', '.xml', '.pem', '.key', '.md', '.gradle', '.rs', '.pl')
_INTERNAL_REPO_RE = re.compile(
    r'(?i)\b(infra|infrastructure|terraform|deploy|deployment|backend|internal|ops|devops|'
    r'secret|secrets|credential|vault|private|k8s|kube|helm|ansible|pipeline|ci-?cd|config)\b')


def _get(url, timeout=HTTP_TIMEOUT, headers=None, allow_redirects=False):
    if not HAVE_REQUESTS:
        return None
    try:
        h = dict(HDRS)
        if headers:
            h.update(headers)
        return requests.get(url, timeout=timeout, headers=h, verify=False,
                            allow_redirects=allow_redirects)
    except requests.exceptions.RequestException:
        return None


def _body(resp, n=4000):
    return (getattr(resp, 'text', '') or '')[:n]


def _redirects_offhost(resp, host):
    """True if `resp` is a redirect whose target leaves `host` - the tell-tale
    that a probed <slug>.<provider> subdomain does NOT exist and the provider
    is bouncing us to its marketing / 'tenant closed' page."""
    loc = resp.headers.get('Location', '') if resp is not None else ''
    if not loc:
        return False
    tgt = urlsplit(loc if '//' in loc else '//' + loc).hostname or host
    return tgt != host and not tgt.endswith('.' + host)


# ---------------------------------------------------------------------------
# Provider registry
#
# Each provider: name, category, and a probe(slug) -> list of Tenant.
# A Tenant is (host, url, [issue, ...]) where the issues are the enrichment
# findings for that confirmed tenant (may be empty). host='' for providers
# keyed off the domain rather than a per-tenant hostname.
# ---------------------------------------------------------------------------

def _p_okta(slug, ctx):
    """Okta serves a wildcard 'Sign In' page (200, x-okta-request-id header,
    oktacdn assets) for *any* <anything>.okta.com, so the landing page proves
    nothing. The only reliable unauthenticated existence oracle is the OIDC
    discovery document: a real org returns 200 with issuer=https://<host>; a
    non-existent org returns 403 errorCode E0000006."""
    tenants = []
    for host in ('%s.okta.com' % slug, '%s.oktapreview.com' % slug):
        oidc = _get('https://%s/.well-known/openid-configuration' % host)
        if oidc is None or oidc.status_code != 200:
            continue
        try:
            issuer = (oidc.json().get('issuer') or '').rstrip('/')
        except ValueError:
            continue
        if issuer != 'https://' + host:
            continue
        issues = []
        if host.endswith('oktapreview.com'):
            issues.append(_mk('saas-okta-preview', "Okta non-production tenant exposed (%s)" % host,
                              "A non-production Okta tenant [%s] for this organisation is internet-reachable. Non-prod IdP tenants frequently run weaker authentication and MFA policies than production while still holding real user data." % host,
                              RATING_LOW, ctx, host,
                              "Confirm this tenant is still needed. Restrict access (Okta Network Zones / ThreatInsight) or decommission it, and ensure its sign-on policies are no weaker than production."))
        reg = _get('https://%s/signin/register' % host, allow_redirects=False)
        if reg is not None and reg.status_code == 200 and re.search(r'(?i)self[- ]?service|create (an )?account|registration', _body(reg)):
            issues.append(_mk('saas-okta-open-registration', "Okta self-service registration enabled (%s)" % host,
                              "The Okta tenant [%s] exposes an enabled self-service registration page (/signin/register). On a workforce tenant this lets an unauthenticated visitor create an account in the identity provider." % host,
                              RATING_MEDIUM, ctx, host,
                              "If self-registration is not a deliberate requirement, disable it (Directory > Self-Service Registration). If it is, ensure it is gated by email-domain allow-listing and admin approval."))
        issues.append(_mk('saas-okta-tenant', "Okta tenant: %s" % host,
                          "Okta tenant [%s] confirmed via its public OIDC discovery document (issuer %s)." % (host, issuer),
                          RATING_INFO, ctx, host,
                          "Enforce phishing-resistant MFA, disable self-service registration unless required, and restrict administrator access by Okta Network Zone."))
        tenants.append((host, 'https://' + host + '/', issues))
    return tenants


def _p_entra(slug, ctx):
    """Microsoft Entra ID / M365 - keyed off the domain, not the slug."""
    if ctx.get('_entra_done'):
        return []
    ctx['_entra_done'] = True
    domain = ctx['domain']
    oidc = _get('https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration' % domain)
    if oidc is None or oidc.status_code != 200 or 'issuer' not in _body(oidc):
        return []
    tenant_guid = None
    try:
        m = re.search(r'login\.microsoftonline\.com/([0-9a-f-]{36})/', oidc.json().get('issuer', ''))
        tenant_guid = m.group(1) if m else None
    except ValueError:
        pass
    issues = []
    realm = _get('https://login.microsoftonline.com/getuserrealm.srf?login=user@%s&json=1' % domain,
                 allow_redirects=True)
    brand, ns_type, auth_url = None, None, None
    if realm is not None and realm.status_code == 200:
        try:
            j = realm.json()
            raw_brand = j.get('FederationBrandName') or j.get('DomainName')
            # FederationBrandName is often a registrar privacy-proxy string
            # ("Data Protected", "Domains By Proxy") for domains parked at a
            # host - only keep it if it reads like a real name.
            brand = raw_brand if (raw_brand and org_identity._clean(raw_brand)) else None
            ns_type = j.get('NameSpaceType')
            auth_url = j.get('AuthURL')
        except ValueError:
            pass
    detail = "Microsoft Entra ID / Microsoft 365 tenant confirmed for [%s]" % domain
    if brand:
        detail += ' (brand name "%s")' % brand
    if tenant_guid:
        detail += "; tenant ID %s" % tenant_guid
    detail += ". Derived from unauthenticated OpenID Connect / getuserrealm discovery endpoints."
    issues.append(_mk('saas-entra-tenant', "Microsoft Entra ID / M365 tenant", detail,
                      RATING_INFO, ctx, 'login.microsoftonline.com/' + domain, None))
    if ns_type and ns_type.lower() == 'federated' and auth_url:
        sts_host = re.sub(r'^https?://', '', auth_url).split('/')[0].lower()
        managed = bool(re.search(r'(?:^|\.)(godaddy|okta|microsoftonline|onelogin|pingidentity|'
                                 r'pingone|duosecurity|jumpcloud|cloudflareaccess|auth0|google|'
                                 r'accounts\.google|centrify|miniorange)\.com$', sts_host))
        if managed:
            issues.append(_mk('saas-entra-federation', "Microsoft 365 identity federated to %s" % sts_host,
                              "The Entra ID tenant for [%s] federates authentication to the managed identity provider at [%s] (from getuserrealm AuthURL). This maps the organisation's real login provider - a compromise or misconfiguration there is a full tenant compromise - but it is not an endpoint you can assess directly." % (domain, sts_host),
                              RATING_LOW, ctx, sts_host,
                              "Confirm [%s] is an expected, sanctioned IdP for this tenant. Ensure MFA / conditional access is enforced at that provider and that no stale federation trust remains." % sts_host))
        else:
            issues.append(_mk('saas-entra-federation', "Microsoft 365 federated authentication via %s" % sts_host,
                              "The Entra ID tenant for [%s] federates authentication to an STS at [%s] (from getuserrealm AuthURL) that appears self-hosted (not a known managed IdP). This is typically AD FS / PingFederate / Shibboleth - internet-facing authentication infrastructure worth assessing directly." % (domain, sts_host),
                              RATING_MEDIUM, ctx, sts_host,
                              "Add %s as an EASM seed and assess it directly (patch level, supported version, pre-auth exposure). Ensure the STS is behind MFA and, where possible, a WAF or reverse proxy." % sts_host))
    return [('login.microsoftonline.com/' + domain, oidc.url, issues)]


def _p_google(slug, ctx):
    if ctx.get('_google_done'):
        return []
    ctx['_google_done'] = True
    if not ctx.get('google_mx'):
        return []
    domain = ctx['domain']
    issues = []
    sites = _get('https://sites.google.com/a/%s/' % domain, allow_redirects=True)
    if sites is not None and sites.status_code == 200 and 'google' in _body(sites).lower():
        issues.append(_mk('saas-google-sites', "Legacy Google Sites present for %s" % domain,
                          "A classic Google Sites space (sites.google.com/a/%s/) responds. Classic Sites are frequently left world-readable and carry internal documentation." % domain,
                          RATING_LOW, ctx, 'sites.google.com/a/' + domain,
                          "Inventory every classic Site under this domain and confirm sharing is restricted to the organisation; migrate or delete abandoned sites."))
    issues.append(_mk('saas-google-workspace', "Google Workspace tenant", ("Domain [%s] receives mail via Google Workspace (MX). The organisation's identity, mail and file-sharing surface is in Google Workspace." % domain),
                      RATING_INFO, ctx, domain, None))
    return [(domain, 'mx://google', issues)]


def _p_github(slug, ctx):
    tenants = []
    api = _get('https://api.github.com/orgs/%s' % slug,
               headers={'Accept': 'application/vnd.github+json'}, allow_redirects=True)
    if api is None or api.status_code != 200:
        return []
    try:
        j = api.json()
    except ValueError:
        return []
    if (j.get('type') or '').lower() != 'organization':
        return []
    host = 'github.com/' + slug
    issues = [_mk('saas-github-org', "GitHub organisation: %s" % slug,
                  "GitHub organisation [github.com/%s] confirmed (%s public repo(s)%s). Public repositories and the org's members are attacker reconnaissance and, if a repo leaks a credential, a direct breach path." % (
                      slug, j.get('public_repos', '?'),
                      '; "%s"' % j['name'] if j.get('name') else ''),
                  RATING_INFO, ctx, host, None)]
    pages = _get('https://%s.github.io/' % slug, allow_redirects=True)
    if pages is not None and pages.status_code == 200:
        issues.append(_mk('saas-github-pages', "GitHub Pages site: %s.github.io" % slug,
                          "A GitHub Pages site is published at https://%s.github.io/ . It is a live web asset for this organisation - assess it directly (headers, secrets in built JS, exposed source maps)." % slug,
                          RATING_INFO, ctx, '%s.github.io' % slug,
                          "Add %s.github.io as an EASM seed. Confirm the Pages site is intentional and contains no build artefacts, tokens or internal docs." % slug))
    issues.extend(_github_repos(slug, ctx))
    tenants.append((host, 'https://' + host, issues))
    return tenants


def _github_repos(org, ctx):
    args = ctx['args']
    issues = []
    token = getattr(args, 'github_token', None) or os.environ.get('GITHUB_TOKEN')
    h = {'Accept': 'application/vnd.github+json'}
    if token:
        h['Authorization'] = 'Bearer ' + token
    repos = []
    for page in (1, 2):
        r = _get('https://api.github.com/orgs/%s/repos?type=public&sort=pushed&per_page=100&page=%d' % (org, page),
                 headers=h, allow_redirects=True)
        if r is None or r.status_code != 200:
            if r is not None and r.status_code == 403 and r.headers.get('X-RateLimit-Remaining') == '0':
                logging.warning("[EASM] saas_discovery: GitHub API rate-limited (set GITHUB_TOKEN / --github_token)")
            break
        try:
            batch = r.json()
        except ValueError:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
    if not repos:
        return issues

    internal = sorted({x['name'] for x in repos
                       if _INTERNAL_REPO_RE.search(x.get('name', '') or '')
                       or _INTERNAL_REPO_RE.search(x.get('description') or '')})
    if internal:
        issues.append(_mk('saas-github-internal-repo', "Internal-looking public repositories in GitHub org %s" % org,
                          "The public GitHub org [%s] contains repositories whose names/descriptions suggest internal infrastructure or configuration:\n%s"
                          % (org, '\n'.join(internal[:50])),
                          RATING_LOW, ctx, 'github.com/' + org,
                          "Review each: confirm it is meant to be public and contains no credentials, internal hostnames, or infrastructure-as-code that discloses your environment. Move genuinely internal code to a private repo."))

    if not getattr(args, 'github_repo_scan', False):
        return issues

    max_repos = getattr(args, 'github_max_repos', 15) or 15
    max_kb = (getattr(args, 'github_max_repo_mb', 20) or 20) * 1024
    scanned, findings = [], []
    for repo in repos:
        if len(scanned) >= max_repos:
            break
        if repo.get('fork') or repo.get('archived') or repo.get('size', 0) > max_kb:
            continue
        name = repo['name']
        branch = repo.get('default_branch') or 'main'
        tb = _get('https://api.github.com/repos/%s/%s/tarball/%s' % (org, name, branch),
                  headers=h, timeout=HTTP_TIMEOUT * 3, allow_redirects=True)
        if tb is None or tb.status_code != 200 or not tb.content:
            continue
        scanned.append(name)
        try:
            tf = tarfile.open(fileobj=io.BytesIO(tb.content[:GH_TARBALL_CAP]), mode='r:gz')
            with tf:
                for member in tf:
                    if not member.isfile() or member.size > GH_MEMBER_CAP:
                        continue
                    path = member.name.split('/', 1)[-1]
                    if not path.lower().endswith(GH_TEXT_EXT):
                        continue
                    try:
                        data = tf.extractfile(member).read().decode('utf-8', 'replace')
                    except Exception:
                        continue
                    for label, rx in _SECRET_RULES:
                        m = rx.search(data)
                        if m:
                            val = m.group(0)
                            findings.append('%s: %s  (%s @ %s)' % (
                                label, (val[:16] + '...') if len(val) > 20 else val, path, name))
        except Exception as e:
            logging.debug("[EASM] saas_discovery: tarball scan failed for %s/%s: %s", org, name, e)
            continue
    if findings:
        sev = RATING_CRITICAL if any(k in f for f in findings for k in
                                     ('AWS secret access key', 'AWS access key id', 'Private key block', 'Stripe live secret key')) else RATING_HIGH
        issues.append(_mk('saas-github-repo-secret', "Credential/secret pattern(s) in public GitHub org repositories",
                          "Secret-like pattern(s) were found in public repositories of GitHub org [%s] (scanned %d repo(s)). Public repo history is fully readable - treat every match as compromised until proven a false positive:\n%s"
                          % (org, len(scanned), '\n'.join(sorted(set(findings))[:100])),
                          sev, ctx, 'github.com/' + org,
                          "Revoke and rotate every matched credential now. Purge it from git history (or delete/privatise the repo), and enable GitHub push protection / secret scanning on the org."))
    elif scanned:
        issues.append(_mk('saas-github-repo-scan-clean', "Public GitHub org repositories scanned - no secrets found",
                          "Scanned %d public repo(s) of GitHub org [%s] for credential patterns and found none." % (len(scanned), org),
                          RATING_INFO, ctx, 'github.com/' + org, None))
    return issues


def _p_atlassian(slug, ctx):
    host = '%s.atlassian.net' % slug
    r = _get('https://' + host + '/', allow_redirects=False)
    if r is None:
        return []
    b = _body(r)
    ok = (r.status_code in (200, 302, 303, 401, 403) and
          ('atlassian' in b.lower() or 'x-arequestid' in {k.lower() for k in r.headers}
           or 'id.atlassian.com' in r.headers.get('Location', '')))
    if not ok:
        return []
    issues = []
    conf = _get('https://%s/wiki/rest/api/content?limit=1' % host, allow_redirects=False)
    if conf is not None and conf.status_code == 200 and '"results"' in _body(conf):
        issues.append(_mk('saas-atlassian-anon-confluence', "Anonymous Confluence access on %s" % host,
                          "Confluence on [%s] returns content to an unauthenticated request (/wiki/rest/api/content). Anonymous access to a corporate wiki routinely exposes runbooks, architecture, and credentials pasted into pages." % host,
                          RATING_HIGH, ctx, host,
                          "In Confluence: Administration > Security > disable 'Anonymous access' (site level) and audit every space's permissions for the 'anonymous' entry. Review what was reachable."))
    jira = _get('https://%s/rest/api/2/project' % host, allow_redirects=False)
    if jira is not None and jira.status_code == 200 and jira.text.strip().startswith('['):
        try:
            n = len(jira.json())
        except ValueError:
            n = 0
        if n:
            issues.append(_mk('saas-atlassian-anon-jira', "Anonymous Jira project browsing on %s" % host,
                              "Jira on [%s] lists %d project(s) to an unauthenticated request (/rest/api/2/project). Anonymous Jira access exposes issue contents, internal project structure and often user email addresses." % (host, n),
                              RATING_HIGH, ctx, host,
                              "In Jira: remove the 'Anonymous' / 'Public' access from the default permission scheme and each project's permission scheme; disable 'Anonymous access' at the site level."))
    if not issues:
        issues.append(_mk('saas-atlassian-tenant', "Atlassian Cloud tenant: %s" % host,
                          "Atlassian Cloud tenant [%s] (Jira / Confluence) confirmed. No anonymous read access detected on the REST endpoints checked." % host,
                          RATING_INFO, ctx, host,
                          "Confirm the tenant is managed. Enforce SSO, verify approved-domain auto-join is disabled unless intended, and review external collaborator access."))
    return [(host, 'https://' + host + '/', issues)]


def _p_slack(slug, ctx):
    host = '%s.slack.com' % slug
    r = _get('https://' + host + '/', allow_redirects=False)
    if r is None or r.status_code >= 400 or _redirects_offhost(r, host):
        return []      # non-existent Slack workspace -> 404
    full = _get('https://' + host + '/', allow_redirects=True)
    if full is None:
        return []
    b = _body(full, 60000)
    if not re.search(r'"(team_name|workspace_name|active_team_id)"\s*:', b) and 'data-props' not in b:
        # too weak a match - avoid a false positive on Slack's marketing pages
        return []
    issues = []
    m = re.search(r'"approved_email_domains?":"([^"]+)"', b) or re.search(r'approvedEmailDomains["\']?\s*[:=]\s*["\']([^"\']+)', b)
    if m and m.group(1).strip():
        issues.append(_mk('saas-slack-open-signup', "Slack workspace allows email-domain self-signup: %s" % host,
                          "The Slack workspace [%s] permits anyone with an email address in domain(s) [%s] to join without an invite. Anyone who can obtain such a mailbox (e.g. via a takeover of an unrelated service) joins the corporate workspace." % (host, m.group(1)),
                          RATING_MEDIUM, ctx, host,
                          "In Slack: Settings > disable 'Allow people to sign up' for the approved email domain(s), or restrict joining to invitation only / SSO provisioning."))
    else:
        issues.append(_mk('saas-slack-tenant', "Slack workspace: %s" % host,
                          "Slack workspace [%s] confirmed. No open email-domain signup detected on the sign-in page." % host,
                          RATING_INFO, ctx, host, None))
    return [(host, 'https://' + host + '/', issues)]


def _p_awssso(slug, ctx):
    for host in ('%s.awsapps.com' % slug,):
        r = _get('https://%s/start' % host, allow_redirects=True)
        if r is None or r.status_code not in (200, 302):
            continue
        b = _body(r)
        if 'awsapps.com' not in r.url and 'AWS access portal' not in b and 'aws' not in b.lower():
            continue
        issues = [_mk('saas-aws-sso-portal', "AWS IAM Identity Center (SSO) portal: %s" % host,
                      "An AWS access portal (IAM Identity Center / AWS SSO) is reachable at https://%s/start . Confirms an AWS footprint; the SAML metadata endpoint typically discloses the AWS account ID(s)." % host,
                      RATING_INFO, ctx, host,
                      "Confirm the portal is expected. Enforce MFA on all Identity Center users, and treat the disclosed AWS account IDs as semi-sensitive infrastructure metadata.")]
        return [(host, 'https://%s/start' % host, issues)]
    return []


def _p_zendesk(slug, ctx):
    host = '%s.zendesk.com' % slug
    r = _get('https://' + host + '/', allow_redirects=False)
    if r is None or r.status_code >= 400 or _redirects_offhost(r, host):
        return []      # non-existent Zendesk -> 301 to www.zendesk.com/app/help-center-closed
    hc = _get('https://' + host + '/', allow_redirects=True)
    if hc is None or 'zendesk' not in _body(hc, 20000).lower():
        return []
    issues = []
    b = _body(hc, 40000)
    if re.search(r'(?i)sign up|registration', b) and 'user_registration' not in b:
        issues.append(_mk('saas-zendesk-open-signup', "Zendesk end-user registration appears open: %s" % host,
                          "The Zendesk help center at [%s] appears to allow open end-user registration. Open registration can be abused for spam, phishing lures under your brand, and (mis)configured to expose internal-only articles." % host,
                          RATING_LOW, ctx, host,
                          "In Zendesk: Guide/Support settings > require users to be created by an agent, or restrict sign-up to approved email domains; review help-center visibility settings."))
    else:
        issues.append(_mk('saas-zendesk-tenant', "Zendesk tenant: %s" % host,
                          "Zendesk tenant [%s] confirmed." % host, RATING_INFO, ctx, host, None))
    return [(host, 'https://' + host + '/', issues)]


def _p_servicenow(slug, ctx):
    host = '%s.service-now.com' % slug
    r = _get('https://' + host + '/', allow_redirects=True)
    if r is None or r.status_code not in (200, 302) or not re.search(r'(?i)service-now|servicenow|glide', _body(r, 20000)):
        return []
    issues = []
    stats = _get('https://%s/stats.do' % host, allow_redirects=False)
    ver = None
    if stats is not None and stats.status_code == 200:
        m = re.search(r'(?i)Build name:\s*([^\r\n<]+)', stats.text or '')
        m2 = re.search(r'(?i)Build date:\s*([^\r\n<]+)', stats.text or '')
        if m:
            ver = m.group(1).strip() + (' (%s)' % m2.group(1).strip() if m2 else '')
    if ver:
        issues.append(_mk('saas-servicenow-version', "ServiceNow version disclosed: %s" % host,
                          "The ServiceNow instance [%s] discloses its build via an unauthenticated /stats.do: %s . A disclosed version enables targeted matching against ServiceNow security advisories (several unauthenticated data-exposure issues have been published)." % (host, ver),
                          RATING_LOW, ctx, host,
                          "Restrict /stats.do to authenticated administrators (glide.stats.guest property), keep the instance on a supported patch level, and review ACLs on public-facing widgets/knowledge bases."))
    else:
        issues.append(_mk('saas-servicenow-tenant', "ServiceNow instance: %s" % host,
                          "ServiceNow instance [%s] confirmed." % host, RATING_INFO, ctx, host, None))
    return [(host, 'https://' + host + '/', issues)]


def _p_auth0(slug, ctx):
    for host in ('%s.auth0.com' % slug, '%s.us.auth0.com' % slug, '%s.eu.auth0.com' % slug):
        r = _get('https://%s/.well-known/openid-configuration' % host)
        if r is None or r.status_code != 200 or 'issuer' not in _body(r):
            continue
        issues = [_mk('saas-auth0-tenant', "Auth0 tenant: %s" % host,
                      "Auth0 tenant [%s] confirmed via its public OIDC discovery document. Auth0 tenants are a customer identity boundary; review connection settings (open DB signup, permissive redirect_uri) in the dashboard." % host,
                      RATING_INFO, ctx, host,
                      "Confirm this tenant is yours. Disable database-connection self-signup on any connection used for staff/admin apps, and tighten Allowed Callback URLs.")]
        return [(host, 'https://' + host + '/', issues)]
    return []


def _p_generic(slug, ctx, name, category, hostfmt, marker, sev=RATING_INFO):
    host = hostfmt % slug
    r = _get('https://' + host + '/', allow_redirects=False)
    if r is None or r.status_code >= 400 or _redirects_offhost(r, host):
        return []
    if not r.headers.get('Location') and marker not in _body(r, 20000).lower():
        return []
    return [(host, 'https://' + host + '/', [_mk('saas-%s-tenant' % name.lower().replace(' ', '-'),
            "%s tenant: %s" % (name, host),
            "%s tenant [%s] confirmed for this organisation." % (name, host),
            sev, ctx, host,
            "Confirm the tenant is managed and enforces SSO; review any open self-registration.")])]


PROVIDERS = [
    ('Okta', 'IdP', _p_okta),
    ('Microsoft Entra ID', 'IdP', _p_entra),
    ('Google Workspace', 'IdP', _p_google),
    ('GitHub', 'Code', _p_github),
    ('Atlassian', 'Collaboration', _p_atlassian),
    ('Slack', 'Collaboration', _p_slack),
    ('AWS IAM Identity Center', 'IdP', _p_awssso),
    ('Zendesk', 'Support', _p_zendesk),
    ('ServiceNow', 'ITSM', _p_servicenow),
    ('Auth0', 'IdP', _p_auth0),
    ('Zoom', 'Collaboration', lambda s, c: _p_generic(s, c, 'Zoom', 'Collaboration', '%s.zoom.us', 'zoom')),
    ('Statuspage', 'Ops', lambda s, c: _p_generic(s, c, 'Statuspage', 'Ops', '%s.statuspage.io', 'statuspage')),
]
# Deliberately NOT probed: PagerDuty and Cloudflare Access both serve a
# wildcard sign-in page (HTTP 200 / on-host 302) for every possible subdomain,
# so there is no reliable unauthenticated tenant-existence oracle - probing
# them only produces false positives.

_CATEGORY_BY_NAME = {name: cat for name, cat, _ in PROVIDERS}


def _mk(twc_id, title, details, rating, ctx, obj, remediation):
    return _new_issue(twc_id, title, details, rating, ctx['asset_id'],
                      ISSUE_TYPE_EXPOSED_PANEL if rating not in (RATING_INFO,) else ISSUE_TYPE_WEB_APPLICATION,
                      object_id=obj, remediation=remediation, object_meta=obj)


def _mail_context(domain):
    """MX-derived passive signals: which mail platform the domain uses."""
    ctx = {'google_mx': False, 'm365_mx': False}
    if not HAVE_DNSPYTHON:
        return ctx
    ans = _resolve_record(_get_dns_resolver(), domain, 'MX')
    for rr in (ans or []):
        h = str(getattr(rr, 'exchange', rr)).lower().rstrip('.')
        if 'google.com' in h or 'googlemail.com' in h:
            ctx['google_mx'] = True
        if 'mail.protection.outlook.com' in h or 'olc.protection.outlook.com' in h:
            ctx['m365_mx'] = True
    return ctx


def check_saas_discovery(domain, asset_id, args, tags=None, extra_labels=None):
    """Discover the organisation's SaaS tenants and their misconfigurations.
    Domain-level check: attaches findings/tags to the anchor asset."""
    if getattr(args, 'no_saas_discovery', False) or not HAVE_REQUESTS:
        return []
    reg = get_registered_domain(domain) or domain
    info = org_identity.derive(reg, extra_slugs=getattr(args, 'saas_slug', None) or None,
                               ttl=getattr(args, 'saas_discovery_ttl', org_identity.DEFAULT_TTL))
    slugs = info['slugs']
    if not slugs:
        return []
    logging.info("[EASM] saas_discovery: [%s] identity '%s' (%s conf) - probing %d provider(s) x %d slug(s)",
                 reg, info['display_name'], info['confidence'], len(PROVIDERS), len(slugs))

    mail = _mail_context(reg)
    ctx = {
        'domain': reg, 'asset_id': asset_id, 'args': args,
        'google_mx': mail['google_mx'], 'm365_mx': mail['m365_mx'],
    }

    issues = [org_identity.identity_issue(info, asset_id)]
    confirmed = []          # (provider, category, host, url)
    tags = tags if tags is not None else []

    # domain-keyed providers run once; slug-keyed providers run per slug
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {}
        for name, category, fn in PROVIDERS:
            domain_keyed = name in ('Microsoft Entra ID', 'Google Workspace')
            for slug in (slugs[:1] if domain_keyed else slugs):
                futs[pool.submit(_safe_probe, fn, slug, ctx)] = (name, category)
        for fut in as_completed(futs):
            name, category = futs[fut]
            for host, url, tenant_issues in fut.result():
                confirmed.append((name, category, host, url))
                issues.extend(tenant_issues)
                _tag(tags, 'SAAS_PROVIDER:' + name)
                if category == 'IdP' and name in ('Okta', 'Microsoft Entra ID', 'Auth0', 'Google Workspace'):
                    _tag(tags, 'IDP:' + name)
                if host:
                    _tag(tags, 'SAAS_TENANT:' + host)

    if len(confirmed) <= 0:
        issues.append(_new_issue(
            'saas-tenant-none', "No SaaS tenants discovered",
            "Probed %d SaaS provider(s) using candidate slug(s) [%s] derived from the organisation's identity, and confirmed none. This is a coverage statement, not an all-clear - a heavily abbreviated tenant slug (e.g. an acronym) may be missed; re-run with --saas_slug <slug> if the organisation's SaaS namespace is known."
            % (len(PROVIDERS), ', '.join(slugs[:14])),
            RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=reg,
            remediation="No action required.")
        )
        return issues

    lines = ['%-24s %-14s %s' % ('PROVIDER', 'CATEGORY', 'TENANT')]
    for name, category, host, url in sorted(set(confirmed)):
        lines.append('%-24s %-14s %s' % (name, category, host or reg))
    issues.append(_new_issue(
        'saas-tenant-inventory', "SaaS tenant footprint (%d confirmed)" % len(set((n, h) for n, _, h, _ in confirmed)),
        "SaaS tenants owned by this organisation, discovered from its identity ('%s', %s confidence). Each is externally-facing attack surface the organisation owns but does not host; see the individual findings for any misconfiguration detected:\n%s"
        % (info['display_name'], info['confidence'], '\n'.join(lines)),
        RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=reg,
        object_meta=','.join(sorted({h for _, _, h, _ in confirmed if h})),
        remediation="Confirm each tenant is centrally managed (SSO enforced, admin inventory, offboarding). Add any tenant with its own hostname (and any federation endpoint listed) as an EASM seed so it is assessed and monitored like the rest of the estate."))
    return issues


def _safe_probe(fn, slug, ctx):
    try:
        return fn(slug, ctx) or []
    except Exception as e:
        logging.debug("[EASM] saas_discovery: probe error (%s): %s", getattr(fn, '__name__', fn), e)
        return []


def _tag(tags, t):
    if t not in tags:
        tags.append(t)
