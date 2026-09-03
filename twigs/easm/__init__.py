"""
External Attack Surface Management (EASM) discovery module.

Given one or more seeds - any mix of domains, hostnames, IP addresses, CIDR
blocks and ASNs, supplied via --fqdn, a repeatable --seed, or --seed_file
(see twigs/easm/seeds.py for how each kind is classified and expanded) -
this module performs unauthenticated, internet-facing reconnaissance.
Domain-level checks run only for domains that were themselves seeded (or are
the registered domain of a seeded hostname); everything discovered downstream
gets host-level assessment only:

  - host / service discovery (independent nmap wrapper, not twigs.fingerprint)
  - subdomain enumeration from many free passive sources unioned together
    (crt.sh, certspotter, AnubisDB, Subdomain Center, HackerTarget, AlienVault
    OTX, urlscan.io, RapidDNS, Wayback/CommonCrawl crawl indexes) plus a DNS
    brute force over a selectable wordlist (built-in ~130-label list, bundled
    ~5k / ~20k lists via --wordlist_tier, or --wordlist_file); on wildcard-DNS
    domains the brute force still runs, filtered against a wildcard fingerprint
  - incremental Certificate Transparency monitoring: a persisted per-domain
    high-water mark means each run only processes CT entries newer than the
    last, catching newly logged subdomains and lookalike-domain certificates
    between full scans; a fixed look-back window is used on the first run or
    when no persistent state is available (see ct_monitor.py)
  - host / service discovery against discovered subdomains
  - SSL/TLS certificate and protocol checks
  - SSL/TLS named-vulnerability scanning (Heartbleed, POODLE, FREAK, Logjam,
    DROWN, ROBOT, BEAST, CRIME, weak/NULL/export ciphers, etc.) against the
    primary host and every discovered subdomain, via the vendored testssl.sh
    (twigs.ssl_audit); checks the target passes are collapsed into one
    informational "named-vulnerability checks passed" finding, while each
    check the target is actually vulnerable to is reported individually and
    still fed to KEV/EPSS re-rating
  - DNS hygiene checks (zone transfer, CAA certificate-authority-authorization
    records, DNSSEC chain-of-trust status, lame delegation)
  - DNSSEC NSEC / NSEC3 zone walking: on a signed zone that uses plain NSEC,
    the next-name pointers are chained to enumerate the whole zone (recovered
    hostnames feed back into subdomain assessment); on NSEC3 zones, iteration
    count (RFC 9276) and opt-out are checked
  - dangling-CNAME / subdomain-takeover detection using the community
    can-i-take-over-xyz fingerprint set (~50 providers, auto-refreshed with a
    bundled offline fallback): each discovered subdomain's CNAME chain is
    matched by provider, then confirmed by the target returning NXDOMAIN or by
    the live HTTP response carrying that provider's "unclaimed resource"
    body/status fingerprint - "Vulnerable" providers reported HIGH, "Edge
    case" providers reported MEDIUM for manual confirmation
  - technology stack discovery (HTTP headers/HTML fingerprinting), including
    client-side JavaScript library detection by name+version (CDN URL
    conventions, self-hosted filenames, and a bounded content-banner fetch
    fallback) and WordPress core/plugin/theme detection by name+version
    (wp-content/ URL slugs plus bounded readme.txt/style.css fetches) -
    reported as products only, no vulnerability correlation of its own since
    ThreatWorx's backend maps products to known CVEs
  - best-effort version recovery for any product detected without a version,
    via a curated set of version-disclosure endpoints (CHANGELOG/RELEASE-NOTES
    files, status/health APIs, generator feeds) - folded back into the product
    list for version-accurate CVE mapping
  - per-host content discovery from the Wayback Machine CDX index: real
    historically-archived URLs, filtered to security-relevant paths/params,
    with a bounded live-reachability probe of the interesting ones
  - JavaScript bundle analysis: mines same-origin/first-party script bundles
    for credential/secret patterns, API endpoint paths, internal hostnames,
    and exposed source maps (sources[] listing)
  - cloud object-storage discovery: AWS S3 / GCS / Azure Blob names generated
    from the org label + discovered subdomains, probed for existence and
    public listability
  - SaaS tenant discovery: derives the organisation's identity (TLS cert O=,
    WHOIS registrant, homepage name, registrable-domain label) into candidate
    tenant slugs, then confirms Okta / Microsoft Entra ID / Google Workspace /
    GitHub org / Atlassian / Slack / AWS IAM Identity Center / Zendesk /
    ServiceNow / Auth0 / Zoom / Cloudflare Access / PagerDuty / Statuspage
    tenants by provider-specific response fingerprint (never bare DNS), then
    runs unauthenticated read-only enrichment for real misconfiguration
    (anonymous Confluence/Jira read, open Slack email-domain signup, exposed
    AWS SSO portal, on-prem federation/AD FS endpoints, ServiceNow version
    disclosure, internal-looking public GitHub repos, and - with
    --github_repo_scan - secret scanning of the org's public repositories)
  - HTTP security headers audit (HSTS, Content-Security-Policy,
    X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and cookie
    security flags (Secure/HttpOnly/SameSite) for every discovered host
  - MTA-STS/TLS-RPT (inbound mail transport encryption policy) and BIMI
    checks, alongside the existing SPF/DMARC/DKIM/MX checks
  - Subresource Integrity (SRI) check on cross-origin scripts/stylesheets
  - security.txt (RFC 9116) and robots.txt/sitemap.xml reconnaissance
  - open-redirect probing of common query parameters
  - email security checks (SPF/DMARC/DKIM/MX)
  - firewall / WAF discovery - known WAF/CDN header/cookie/Server signatures
    plus a probe/baseline status-code differential; each recognized WAF/CDN is
    added to the asset's product list (name only, except ModSecurity when the
    Server header carries a version)
  - web application tests via the nuclei CLI (used only if present on PATH)
  - CISA KEV + FIRST.org EPSS enrichment of every CVE referenced by a finding:
    KEV-listed / high-EPSS CVEs raise the affected finding's rating (never
    lower it), each asset's issues are re-sorted worst-first, and an
    "exploitation-prioritized" summary finding is emitted per affected asset
  - typosquatting checks: dnstwist lookalike-domain permutations, each
    checked for registration status (A/AAAA, MX, or NS/SOA delegation) - not
    just whether it resolves - so registered-but-dormant lookalikes are
    caught, and a lookalike publishing MX records (email-capable, i.e. BEC /
    phishing infrastructure) is rated HIGH; a bounded WHOIS lookup enriches
    the MX-first-ordered hits (no live-content fetch or screenshot here)
  - permutation subdomain scanning: mutates the discovered subdomain set
    (affixes, number bumps, dev/staging/uat/... env-token swaps) and resolves
    the candidates, surfacing sibling environments like api-staging off a
    known api
  - reverse-WHOIS related-domain pivot: crt.sh queried by cert organisation
    (--reverse_whois_org) and by the domain's label, to surface sibling /
    forgotten domains sharing a certificate identity
  - reverse-IP / virtual-host discovery for likely target-owned IPs
    (CLOUD:unattributed): co-hosted hostnames via HackerTarget / RapidDNS / OTX, plus
    a Host-header vhost probe that confirms apps reachable with no current DNS
  - netblock-scale discovery for CIDR/ASN seeds (and, with --asn_sweep, the
    org's own ASNs derived from its IPs): reverse-DNS (PTR) sweep of each
    announced prefix plus a masscan/naabu/python port sweep, with host assets
    created for addresses that answer
  - a vetted multi-resolver pool (liar-checked public resolvers, round-robin)
    for high-concurrency subdomain brute force
  - optional recursive discovery (--recursive_discovery): one or more extra
    passes over high-confidence related domains surfaced by the reverse-WHOIS,
    reverse-IP, and JS-analysis checks
  - WHOIS registration lookups (registrar/creation/expiry/name servers) for
    the primary domain and any registered lookalike domains found
  - LeakRadar credential-leak lookups for the primary domain and every
    discovered subdomain (optional, only if an API key is supplied - see
    --leakradar_api_key / LEAKRADAR_API_KEY)
  - ransomware.live victim-listing lookups for the primary domain (optional,
    only if a Pro API key is supplied - see --ransomware_live_api_key /
    RANSOMWARE_LIVE_API_KEY)
  - ASN/netblock discovery (Team Cymru IP-to-ASN lookup) for every discovered
    host, with a heuristic flag for third-party cloud/CDN hosting vs.
    infrastructure that appears to be directly owned by the target
  - cloud/CDN/hosting provider attribution for every discovered host's IP
    (AWS/GCP/Azure/M365/OCI/Cloudflare/Fastly/DigitalOcean/Linode/Vultr/GitHub
    published prefix files, plus a curated ASN map for Alibaba/Tencent/Hetzner/
    OVH/IBM/Akamai/Rackspace/... ) - reported as CLOUD:/CLOUD_REGION:/
    CLOUD_SERVICE: tags, with CLOUD:unattributed (matched no known provider)
    marking a likely target-owned netblock
  - exposed admin panel / dev-tool / misconfiguration probing for every
    discovered host: CI/CD and artifact tooling (Jenkins, Portainer, Nexus,
    Artifactory, SonarQube, NiFi, GitLab), database admin UIs (Elasticsearch,
    Kibana, CouchDB, Neo4j, Mongo Express, Redis Commander, pgAdmin,
    phpMyAdmin, Adminer), monitoring (Grafana, Prometheus, Zabbix), secrets
    management (HashiCorp Vault), Kubernetes Dashboard, Docker Registry API,
    Apache Tomcat Manager, Webmin, Spring Boot Actuator, and information
    disclosure (phpinfo(), mod_status, exposed .git/.svn/.env and backup
    config files)
  - API discovery/testing for every discovered host: OpenAPI/Swagger spec
    discovery (with parsing for endpoint count and unauthenticated
    endpoints), GraphQL introspection, CORS misconfiguration (arbitrary
    origin reflection), and verbose error/stack-trace disclosure
  - GraphQL deep enumeration: when introspection is on, the schema is dumped
    and summarised (mutation root fields, sensitive-looking field names);
    when it is off, field names are recovered via "Did you mean" suggestions
    and a root-field wordlist, and an exposed GraphiQL/Playground console,
    query batching and GET-based execution are flagged
  - OpenAPI active probing: the documented operations that declare no
    authentication are actually requested (GET/HEAD only, never a write
    method, parameters filled only from spec examples) to confirm which are
    truly reachable unauthenticated vs. really protected (401/403)
  - calibrated content/directory brute force: a small curated high-signal
    path list probed with soft-404 fingerprinting (random-path baseline), with
    content verification of high-value hits (VCS metadata, .env, DB dumps,
    private keys) before rating
  - mixed content (HTTP resources loaded on an HTTPS page) and favicon hash
    fingerprinting (an mmh3 hash reported as an asset tag, for infrastructure
    correlation - not a vulnerability finding on its own)
  - HTTP method enumeration (PUT/DELETE/TRACE/CONNECT advertised via Allow)
    and directory listing (autoindex) detection on common paths
  - UDP top-port exposure scan: protocol-specific probes to a curated set of
    reflection/amplification-prone UDP services (SNMP, NTP incl. monlist, DNS
    incl. open-resolver test, IKE, mDNS, NetBIOS, SSDP, memcached, CLDAP,
    chargen/echo) - response-only, so open is definitive and no root is needed
  - active TLS-stack fingerprinting: a battery of varied ClientHellos hashed
    into a stable per-server fingerprint (reported as the TLS_STACK asset tag,
    alongside the leaf-cert SHA-256) for clustering shared TLS termination
    infrastructure; also confirms any weak/legacy cipher the server will
    actually negotiate
  - wildcard DNS fingerprinting ahead of subdomain brute force: guessed
    labels that resolve only to the wildcard address(es) are subtracted out,
    so brute force still contributes on wildcard domains instead of being
    skipped
  - DNSBL/IP reputation lookups (Spamhaus ZEN) for every discovered host's
    resolved IPv4 address(es)
  - nameserver delegation consistency (lame delegation) checking
  - end-to-end IPv6 coverage: AAAA records are resolved and brute-forced
    alongside A, every host records its IP stack (dualstack / ipv6-only /
    ipv4-only) and per-address IPV6: tags, the IPv6 address is port-scanned
    (nmap -6 on the primary, a fast TCP sweep elsewhere) with IPv6 cloud
    attribution, and its open ports are diffed against IPv4 - a port open on
    IPv6 but not IPv4 is reported as a firewall gap, and an IPv6-only host is
    flagged as an IPv4-tooling blind spot

This is the package's entry point - `twigs/twigs.py` does `from . import
easm` and calls `easm.get_inventory(args)`, unchanged from when this module
was a single flat easm.py file. Each check family now lives in its own
sibling module (see the twigs/easm/ directory) instead of one large file;
this __init__.py only contains the per-host/per-domain orchestration
(build_host_asset, get_inventory) that ties them together.

Everything that is not stdlib is imported defensively (in the relevant
submodule) so a missing optional dependency only disables the check it
powers, instead of crashing the module.
"""
import logging

import urllib3
# Every check module in this package makes unauthenticated-cert HTTPS
# requests (verify=False) against arbitrary external targets by design - the
# whole point is testing what an unauthenticated internet visitor sees, cert
# trust included. Suppress the resulting per-request warning noise once,
# package-wide, on import.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .constants import RATING_INFO, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_SUBDOMAIN, ISSUE_TYPE_DNS
from .util import resolve_ips, _is_ip_address, _is_ipv6, get_registered_domain, HAVE_DNSPYTHON, _get_dns_resolver, _new_issue
from .nmap_discovery import nmap_exists, run_nmap_scan, create_port_issues
from .ssl_checks import check_ssl, check_ssl_vulnerabilities
from .tech_stack import check_tech_stack
from .version_probe import probe_product_versions
from .content_discovery import check_content_discovery
from .reverse_ip import check_reverse_ip
from .reverse_whois import check_reverse_whois
from .js_analysis import check_js_analysis
from .bucket_discovery import check_bucket_discovery
from .saas_discovery import check_saas_discovery
from .zone_walk import check_zone_walk
from .ipv6 import check_ipv6
from .graphql_enum import check_graphql_enum
from .openapi_probe import check_openapi_probe
from .dir_brute import check_dir_brute
from .tls_fingerprint import check_tls_fingerprint
from .udp_scan import check_udp_scan
from . import netblock_sweep
from . import portsweep
from .waf import check_waf
from .http_headers import check_security_headers, check_cookie_security
from .web_recon import check_security_txt, check_robots_sitemap, check_open_redirect, check_http_methods, check_directory_listing
from .exposed_panels import check_exposed_panels
from .api_discovery import check_api_discovery
from .asn_netblock import check_asn_netblock
from . import cloud_ranges
from . import kev_epss
from .dnsbl import check_dnsbl
from .nuclei_scan import nuclei_exists, run_nuclei
from .whois_lookup import check_whois
from .leakradar import get_leakradar_api_key, check_leakradar
from .ransomware_live import get_ransomware_live_api_key, check_ransomware_live
from .email_security import check_email_security
from .dns_hygiene import check_zone_transfer, check_dangling_cname, check_caa_records, check_dnssec, check_ns_consistency
from . import takeover_fingerprints
from .typosquatting import check_typosquatting
from .subdomains import enumerate_subdomains
from .ct_monitor import check_ct_monitor
from . import seeds


def _stage(hostname, label):
    """Emit a single info-level progress line naming the EASM check about to
    run against `hostname`, so a long run's log shows where it currently is."""
    logging.info("[EASM] %s: %s", hostname, label)


def _maybe_nuclei_extra(args, hostname, asset):
    """Run nuclei web-application tests against a non-primary host, but only
    when --nuclei_all_hosts is set (nuclei is slow; by default it runs on the
    primary asset only)."""
    if not getattr(args, 'nuclei_all_hosts', False):
        return
    if getattr(args, 'no_nuclei', False) or not nuclei_exists():
        return
    _stage(hostname, "nuclei web application tests")
    severity = getattr(args, 'nuclei_severity', 'info,low,medium,high,critical')
    asset['config_issues'].extend(run_nuclei(
        hostname, asset['id'], severity, getattr(args, 'nuclei_timeout', 3600)))


def build_host_asset(args, hostname, owner, is_primary, nmap_cache):
    logging.info("[EASM] building host asset for [%s] (%s)",
                 hostname, "primary" if is_primary else "secondary")
    ips = resolve_ips(hostname)
    if not ips and not _is_ip_address(hostname):
        logging.warning("Unable to resolve [%s] - skipping", hostname)
        return None

    ipv4_ips = [ip for ip in ips if not _is_ipv6(ip)]
    scan_target = (ipv4_ips[0] if ipv4_ips else ips[0]) if ips else hostname
    # The asset is keyed by hostname; every discovered subdomain becomes its
    # own separate asset and its findings are never merged into the parent
    # domain's asset. scan_target (an IP) is only the nmap scan target and
    # nmap_cache key, not the asset identity.
    asset_id = hostname
    host_result = nmap_cache.get(scan_target)
    if host_result is None:
        _stage(hostname, "host/service discovery (nmap)")
        host_result = run_nmap_scan(args, scan_target)
        nmap_cache[scan_target] = host_result
    else:
        logging.info("[EASM] %s: reusing cached nmap result for %s", hostname, scan_target)

    asset_data = {
        'id': asset_id,
        'name': hostname,
        'type': 'Domain',
        'owner': owner,
        'products': list(host_result['products']) if host_result else [],
        'config_issues': [],
        'tags': ['DISCOVERY_TYPE:Unauthenticated', 'EASM'],
    }
    if is_primary:
        asset_data['tags'].append('EASM_PRIMARY')
    else:
        asset_data['tags'].append('EASM_SUBDOMAIN')
    if ips:
        asset_data['tags'].append('IP:' + ips[0])

    if not getattr(args, 'no_cloud_attribution', False):
        lookup_ip = scan_target if _is_ip_address(scan_target) else (ips[0] if ips else None)
        if lookup_ip:
            info = cloud_ranges.lookup(lookup_ip, ttl=getattr(args, 'cloud_ranges_ttl', cloud_ranges.DEFAULT_TTL))
            for t in cloud_ranges.as_tags(info):
                asset_data['tags'].append(t)
            if info is not None:
                logging.info("[EASM] %s: %s attributed to %s (%s%s)", hostname, lookup_ip,
                             info.provider, info.kind,
                             '/' + info.region if info.region else '')

    if host_result:
        asset_data['config_issues'].extend(create_port_issues(host_result, asset_id))

    if not getattr(args, 'no_ipv6', False):
        _stage(hostname, "IPv6 coverage (stack, reachability, v4/v6 firewall delta)")
        asset_data['config_issues'].extend(check_ipv6(
            hostname, ips, host_result, asset_data['products'], asset_data['tags'],
            asset_id, args, is_primary=is_primary, nmap_cache=nmap_cache))

    if not getattr(args, 'no_ssl_checks', False):
        _stage(hostname, "SSL/TLS certificate & protocol checks")
        asset_data['config_issues'].extend(check_ssl(hostname, host_result, asset_id))

    if not getattr(args, 'no_ssl_audit', False):
        _stage(hostname, "SSL/TLS named-vulnerability scan (testssl.sh)")
        asset_data['config_issues'].extend(check_ssl_vulnerabilities(
            hostname, host_result, asset_id, getattr(args, 'ssl_audit_timeout', 120)))

    if not getattr(args, 'no_tls_fingerprint', False):
        _stage(hostname, "TLS stack fingerprinting (infrastructure correlation)")
        asset_data['config_issues'].extend(check_tls_fingerprint(
            hostname, host_result, asset_data['tags'], asset_id, args))

    if not getattr(args, 'no_tech_stack', False):
        _stage(hostname, "technology stack / JS library / WordPress detection")
        asset_data['config_issues'].extend(check_tech_stack(hostname, asset_data['products'], asset_data['tags'], asset_id))

    if not getattr(args, 'no_version_probe', False):
        _stage(hostname, "product version probing (version-disclosure endpoints)")
        asset_data['config_issues'].extend(probe_product_versions(hostname, asset_data['products'], asset_id, args))

    if not getattr(args, 'no_content_discovery', False):
        _stage(hostname, "content discovery (Wayback CDX historical URLs)")
        asset_data['config_issues'].extend(check_content_discovery(hostname, asset_id, args))

    if not getattr(args, 'no_js_analysis', False):
        _stage(hostname, "JavaScript bundle analysis (secrets / endpoints / source maps)")
        js_issues, _js_hosts = check_js_analysis(hostname, asset_id, args)
        asset_data['config_issues'].extend(js_issues)

    if not getattr(args, 'no_waf_check', False):
        _stage(hostname, "firewall / WAF discovery")
        asset_data['config_issues'].extend(check_waf(hostname, asset_id, asset_data['products']))

    if not getattr(args, 'no_security_headers_check', False):
        _stage(hostname, "HTTP security headers audit")
        asset_data['config_issues'].extend(check_security_headers(hostname, asset_id))

    if not getattr(args, 'no_cookie_check', False):
        _stage(hostname, "cookie security flags check")
        asset_data['config_issues'].extend(check_cookie_security(hostname, asset_id))

    if not getattr(args, 'no_exposed_panel_check', False):
        _stage(hostname, "exposed admin panel / dev-tool probing")
        asset_data['config_issues'].extend(check_exposed_panels(hostname, asset_id))

    if not getattr(args, 'no_api_discovery', False):
        _stage(hostname, "API discovery (OpenAPI/GraphQL/CORS/error disclosure)")
        asset_data['config_issues'].extend(check_api_discovery(hostname, asset_id))

    if not getattr(args, 'no_graphql_enum', False):
        _stage(hostname, "GraphQL deep enumeration (schema dump / field suggestion / console)")
        asset_data['config_issues'].extend(check_graphql_enum(hostname, asset_id, args))

    if not getattr(args, 'no_openapi_probe', False):
        _stage(hostname, "OpenAPI active probing (documented no-auth endpoints)")
        asset_data['config_issues'].extend(check_openapi_probe(hostname, asset_id, args))

    if not getattr(args, 'no_web_recon', False):
        _stage(hostname, "web recon (security.txt, robots.txt, sitemap.xml)")
        asset_data['config_issues'].extend(check_security_txt(hostname, asset_id))
        asset_data['config_issues'].extend(check_robots_sitemap(hostname, asset_id))

    if not getattr(args, 'no_open_redirect_check', False):
        _stage(hostname, "open-redirect probing")
        asset_data['config_issues'].extend(check_open_redirect(hostname, asset_id))

    if not getattr(args, 'no_http_methods_check', False):
        _stage(hostname, "HTTP method enumeration")
        asset_data['config_issues'].extend(check_http_methods(hostname, asset_id))

    if not getattr(args, 'no_directory_listing_check', False):
        _stage(hostname, "directory listing (autoindex) detection")
        asset_data['config_issues'].extend(check_directory_listing(hostname, asset_id))

    if not getattr(args, 'no_dir_brute', False):
        _stage(hostname, "calibrated content/dir brute force (soft-404 fingerprinted)")
        asset_data['config_issues'].extend(check_dir_brute(hostname, asset_id, args))

    if not getattr(args, 'no_asn_lookup', False):
        _stage(hostname, "ASN / netblock discovery")
        asset_data['config_issues'].extend(check_asn_netblock(hostname, ips, asset_id))

    if not getattr(args, 'no_reverse_ip', False):
        _stage(hostname, "reverse-IP / virtual-host discovery")
        asset_data['config_issues'].extend(check_reverse_ip(hostname, ips, asset_data['tags'], asset_id, args))

    if not getattr(args, 'no_dnsbl_check', False):
        _stage(hostname, "DNSBL / IP reputation lookup")
        asset_data['config_issues'].extend(check_dnsbl(hostname, ips, asset_id))

    if not getattr(args, 'no_udp_scan', False):
        _stage(hostname, "UDP top-port exposure scan (SNMP/NTP/DNS/IKE/mDNS/memcached/...)")
        asset_data['config_issues'].extend(check_udp_scan(hostname, ips, asset_id, args))

    logging.info("[EASM] %s: host asset complete - %d product(s), %d finding(s)",
                 hostname, len(asset_data['products']), len(asset_data['config_issues']))
    return asset_data


def _assess_domain(args, domain, anchor_asset, anchor_host, owner, nmap_cache, register):
    """Run every domain-level check for `domain` (WHOIS, credential-leak /
    ransomware lookups, email security, DNS hygiene, typosquatting, subdomain
    enumeration + per-subdomain host assessment). Domain-level findings attach
    to `anchor_asset` (the asset for the seed that pulled this domain in);
    each discovered subdomain becomes its own asset via `register(asset)`,
    which returns the canonical asset for that id (de-duplicating a subdomain
    that was also seeded explicitly)."""
    anchor_id = anchor_asset['id']

    if not getattr(args, 'no_whois', False):
        _stage(anchor_host, "WHOIS registration lookup for %s" % domain)
        anchor_asset['config_issues'].extend(check_whois(domain, anchor_id))

    leakradar_api_key = get_leakradar_api_key(args)
    if leakradar_api_key:
        _stage(anchor_host, "LeakRadar credential-leak lookup for %s" % domain)
        anchor_asset['config_issues'].extend(check_leakradar(domain, anchor_id, leakradar_api_key))

    ransomware_live_api_key = get_ransomware_live_api_key(args)
    if ransomware_live_api_key:
        _stage(anchor_host, "ransomware.live victim lookup for %s" % domain)
        anchor_asset['config_issues'].extend(check_ransomware_live(domain, anchor_id, ransomware_live_api_key))

    if not getattr(args, 'no_email_security', False):
        _stage(anchor_host, "email security checks (SPF/DMARC/DKIM/MX/MTA-STS/BIMI)")
        anchor_asset['config_issues'].extend(check_email_security(domain, anchor_id))

    if not getattr(args, 'no_dns_checks', False):
        _stage(anchor_host, "DNS hygiene checks (zone transfer, CAA, DNSSEC, NS consistency)")
        anchor_asset['config_issues'].extend(check_zone_transfer(domain, anchor_id))
        anchor_asset['config_issues'].extend(check_caa_records(domain, anchor_id))
        anchor_asset['config_issues'].extend(check_dnssec(domain, anchor_id))
        anchor_asset['config_issues'].extend(check_ns_consistency(domain, anchor_id))

    if not getattr(args, 'no_typosquatting', False):
        _stage(anchor_host, "typosquatting / lookalike domain checks")
        anchor_asset['config_issues'].extend(check_typosquatting(domain, anchor_id, args))

    if not getattr(args, 'no_reverse_whois', False):
        _stage(anchor_host, "reverse-WHOIS related-domain pivot (crt.sh)")
        anchor_asset['config_issues'].extend(check_reverse_whois(domain, anchor_id, args))

    if not getattr(args, 'no_saas_discovery', False):
        _stage(anchor_host, "SaaS tenant discovery (Okta / Entra ID / GitHub / Atlassian / ...)")
        anchor_asset['config_issues'].extend(
            check_saas_discovery(domain, anchor_id, args, anchor_asset['tags']))

    if getattr(args, 'no_subdomain_enum', False):
        return

    _stage(anchor_host, "subdomain enumeration (passive sources + DNS brute force)")
    discovered, wildcard_dns, wordlist_size = enumerate_subdomains(domain, args)
    discovered.discard(anchor_host)

    if not getattr(args, 'no_ct_monitor', False):
        _stage(anchor_host, "certificate transparency monitoring (incremental)")
        ct_issues, ct_new = check_ct_monitor(domain, anchor_id, args, discovered)
        anchor_asset['config_issues'].extend(ct_issues)
        discovered |= {n for n in ct_new if n != anchor_host}

    if not getattr(args, 'no_dns_checks', False) and not getattr(args, 'no_zone_walk', False):
        _stage(anchor_host, "DNSSEC NSEC/NSEC3 zone walking")
        zw_issues, zw_names = check_zone_walk(domain, anchor_id, args)
        anchor_asset['config_issues'].extend(zw_issues)
        discovered |= {n for n in zw_names if n != anchor_host}

    sorted_subs = sorted(discovered)
    anchor_asset['tags'].append('EASM_SUBDOMAIN_COUNT:%d' % len(sorted_subs))

    if wildcard_dns:
        anchor_asset['config_issues'].append(_new_issue(
            'dns-wildcard-detected', "Wildcard DNS detected",
            "Domain [%s] resolves arbitrary, non-existent subdomain labels to an address (wildcard DNS). DNS brute-force enumeration was still performed, but its results were filtered against a wildcard fingerprint - candidates that resolved only to the wildcard address(es) were discarded, and only those with a distinct address or CNAME target were kept. Some real hosts hidden behind the wildcard may still be missed, and some reported names may be false positives." % domain,
            RATING_INFO, anchor_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="No action required unless the wildcard itself is unintentional. Be aware wildcard DNS can also mask a genuinely dangling/unclaimed subdomain from external detection, since every name appears to resolve."))
        summary_detail = "Discovered [%s] candidate subdomain(s) for [%s] via passive sources and wildcard-filtered DNS brute force (wordlist of %s labels). This list may include subdomains no longer in active use." % (len(discovered), domain, wordlist_size)
    else:
        summary_detail = "Discovered [%s] candidate subdomain(s) for [%s] via passive sources (certificate transparency, passive DNS, crawl indexes) and DNS brute force (wordlist of %s labels). This list reflects hostnames with historical or current DNS/certificate presence and may include subdomains that are no longer in active use." % (len(discovered), domain, wordlist_size)

    if sorted_subs:
        summary_detail += " Complete list of the %d discovered subdomain(s):\n%s" % (
            len(sorted_subs), '\n'.join(sorted_subs))
    else:
        summary_detail += " No subdomains were discovered."

    anchor_asset['config_issues'].append(_new_issue(
        'subdomain-enum-summary', "Subdomain enumeration summary",
        summary_detail,
        RATING_INFO, anchor_id, ISSUE_TYPE_SUBDOMAIN, object_id=domain,
        object_meta=','.join(sorted_subs),
        remediation="Review the discovered subdomains to confirm each is still in active, authorized use. Decommission unused subdomains and remove their DNS records to reduce the attack surface, and ensure inactive ones are not left pointing at services that could be claimed by an attacker (see subdomain takeover findings below, if any)."))

    takeover_found = False
    tested_dangling = 0
    if HAVE_DNSPYTHON and discovered:
        _stage(anchor_host, "dangling CNAME / subdomain takeover check (%d candidate(s))" % min(len(discovered), 200))
        resolver = _get_dns_resolver()
        for sub in list(discovered)[:200]:
            tested_dangling += 1
            tf = check_dangling_cname(sub, resolver)
            if not tf:
                continue
            takeover_found = True
            if tf.confidence == 'confirmed':
                rating = RATING_HIGH
                title = "Subdomain takeover: %s (%s)" % (sub, tf.service)
                lead = ("Subdomain [%s] is vulnerable to takeover: %s." % (sub, tf.evidence))
            else:
                rating = RATING_MEDIUM
                title = "Possible subdomain takeover: %s (%s)" % (sub, tf.service)
                lead = ("Subdomain [%s] may be vulnerable to takeover: %s. This is an unconfirmed / edge-case signal (%s) - verify manually before acting."
                        % (sub, tf.evidence, tf.status))
            detail = (lead + " Its CNAME resolves to [%s]. If the referenced %s resource is unclaimed, an attacker can register it and serve arbitrary content - phishing, malware, cookie/session theft - under your trusted domain name."
                      % (tf.cname, tf.service))
            if tf.documentation:
                detail += " Reference: %s." % tf.documentation
            anchor_asset['config_issues'].append(_new_issue(
                'dns-dangling-cname-%s' % sub, title, detail,
                rating, anchor_id, ISSUE_TYPE_DNS, object_id=sub, object_meta=tf.service,
                remediation="Either remove the stale CNAME record if the third-party resource is no longer used, or (re)claim/re-provision the referenced resource under your account so it cannot be claimed by someone else. Verify by confirming the resource resolves to content you control before considering this resolved."))
        if not takeover_found and tested_dangling > 0:
            anchor_asset['config_issues'].append(_new_issue(
                'dns-dangling-cname-none-found', "No subdomain takeover risk found",
                "Checked [%s] discovered subdomain(s) against the can-i-take-over-xyz fingerprint set (%d provider signatures: CNAME target + NXDOMAIN state + HTTP response body/status), and found none pointing at an unclaimed third-party resource." % (tested_dangling, len(takeover_fingerprints.load())),
                RATING_INFO, anchor_id, ISSUE_TYPE_DNS, object_id=domain,
                remediation="No action required. Re-check periodically, especially after decommissioning any third-party integrations."))

    max_subdomains = getattr(args, 'max_subdomains', 25) or 25
    live_subdomains = []
    for sub in discovered:
        if resolve_ips(sub):
            live_subdomains.append(sub)
        if len(live_subdomains) >= max_subdomains:
            break
    logging.info("[EASM] %s: %d live subdomain(s) to assess (cap %d)",
                 anchor_host, len(live_subdomains), max_subdomains)

    for idx, sub in enumerate(live_subdomains, 1):
        logging.info("[EASM] assessing subdomain %d/%d: [%s]", idx, len(live_subdomains), sub)
        sub_asset = build_host_asset(args, sub, owner, False, nmap_cache)
        if sub_asset is None:
            continue
        sub_asset['tags'].append('EASM_ROOT_DOMAIN:' + domain)
        sub_id = sub_asset['id']  # the subdomain's own hostname
        _maybe_nuclei_extra(args, sub, sub_asset)
        if leakradar_api_key:
            _stage(sub, "LeakRadar credential-leak lookup")
            sub_asset['config_issues'].extend(check_leakradar(sub, sub_id, leakradar_api_key))
        if register(sub_asset, skip_if_empty=True) is None:
            logging.info("[EASM] nothing discovered for subdomain [%s] - not reporting it", sub)

    if not getattr(args, 'no_bucket_discovery', False):
        _stage(anchor_host, "cloud storage bucket discovery (S3 / GCS / Azure Blob)")
        extra = {s.split('.')[0] for s in sorted_subs}
        anchor_asset['config_issues'].extend(check_bucket_discovery(domain, anchor_id, args, extra))


def _harvest_related_domains(assets, exclude):
    """Registrable domains worth a recursive discovery pass, mined from
    findings already produced: reverse-WHOIS siblings (cert identity),
    co-hosted domains on target-owned IPs, and internal hostnames from JS."""
    out = {}
    for a in assets:
        owned_ip = 'CLOUD:unattributed' in a.get('tags', [])
        for iss in a.get('config_issues', []):
            tid = iss.get('twc_id', '')
            meta = (iss.get('object_meta') or '').strip()
            if not meta:
                continue
            if tid == 'easm-reverse-whois-related':
                for d in meta.split(','):
                    d = d.strip().lower()
                    if d and d not in exclude:
                        out.setdefault(d, 'reverse-whois')
            elif tid == 'easm-reverse-ip-cohosted' and owned_ip:
                for h in meta.split(','):
                    rd = get_registered_domain(h.strip().lower())
                    if rd and rd not in exclude:
                        out.setdefault(rd, 'reverse-ip')
            elif tid == 'easm-js-internal-hostname':
                for h in meta.split(','):
                    rd = get_registered_domain(h.strip().lower())
                    if rd and rd not in exclude:
                        out.setdefault(rd, 'js-analysis')
    return out


def get_inventory(args):
    if not nmap_exists():
        logging.warning("nmap CLI not found - host/service discovery will be skipped")

    seed_list, seed_errors = seeds.load(args)
    for raw, source in seed_errors:
        logging.warning("[EASM] ignoring unrecognised seed (%s): %r", source, raw)
    if not seed_list:
        logging.error("No usable EASM seed supplied - give at least one of --fqdn, --seed or --seed_file")
        return None

    owner = args.handle
    nmap_cache = {}
    max_seed_hosts = getattr(args, 'max_seed_hosts', 256) or 256

    # ---- expand seeds -------------------------------------------------
    # domain/host seeds keep their identity; ip seeds become explicit host
    # targets (always reported); cidr/asn seeds fan out to swept host targets
    # (host-level only, reported only if something is found), bounded by
    # max_seed_hosts across the whole run.
    dh_seeds = [s for s in seed_list if s.kind in (seeds.SEED_DOMAIN, seeds.SEED_HOST)]
    explicit_ips = [(s.value, s.raw) for s in seed_list if s.kind == seeds.SEED_IP]
    swept_ips = []
    budget = max_seed_hosts
    for s in seed_list:
        if budget <= 0:
            break
        if s.kind == seeds.SEED_CIDR:
            hosts = seeds.iter_cidr_hosts(s.value, budget)
            if len(hosts) >= budget:
                logging.warning("[EASM] CIDR seed [%s] truncated at the %d-host budget", s.value, max_seed_hosts)
            budget -= len(hosts)
            swept_ips.extend((ip, s.raw) for ip in hosts)
        elif s.kind == seeds.SEED_ASN:
            prefixes = seeds.asn_announced_prefixes(s.value)
            if not prefixes:
                logging.warning("[EASM] ASN seed [%s]: no announced prefixes available (RIPEstat unreachable?) - skipping", s.value)
                continue
            logging.info("[EASM] ASN seed [%s]: %d announced prefix(es)", s.value, len(prefixes))
            for pfx in prefixes:
                if budget <= 0:
                    logging.warning("[EASM] ASN seed [%s] hit the %d-host budget - remaining prefixes not materialised", s.value, max_seed_hosts)
                    break
                hosts = seeds.iter_cidr_hosts(pfx, budget)
                budget -= len(hosts)
                swept_ips.extend((ip, "%s %s" % (s.raw, pfx)) for ip in hosts)

    # ---- pick the primary asset -------------------------------------
    primary_host = None
    for s in dh_seeds:
        if s.kind == seeds.SEED_DOMAIN:
            primary_host = s.value
            break
    if primary_host is None and dh_seeds:
        primary_host = dh_seeds[0].value
    if primary_host is None and explicit_ips:
        primary_host = explicit_ips[0][0]
    if primary_host is None and swept_ips:
        primary_host = swept_ips[0][0]

    seed_by_value = {s.value: s for s in seed_list}
    logging.info("[EASM] starting external attack surface assessment - primary [%s]; %d seed(s), %d explicit + %d swept host target(s)",
                 primary_host, len(seed_list), len(explicit_ips), len(swept_ips))

    assets = []
    assets_by_id = {}

    def _register(asset, skip_if_empty=False):
        if asset is None:
            return None
        existing = assets_by_id.get(asset['id'])
        if existing is not None:
            return existing
        if skip_if_empty and not asset['products'] and not asset['config_issues']:
            return None
        assets_by_id[asset['id']] = asset
        assets.append(asset)
        return asset

    def _tag_seed_provenance(asset, seed):
        if seed is None or asset is None:
            return
        for t in ('EASM_SEED:' + seed.raw, 'EASM_SEED_TYPE:' + seed.kind):
            if t not in asset['tags']:
                asset['tags'].append(t)

    # ---- primary --------------------------------------------------------
    primary_asset = _register(build_host_asset(args, primary_host, owner, True, nmap_cache))
    if primary_asset is None:
        primary_asset = _register({
            'id': primary_host, 'name': primary_host, 'type': 'Domain', 'owner': owner,
            'products': [], 'config_issues': [],
            'tags': ['DISCOVERY_TYPE:Unauthenticated', 'EASM', 'EASM_PRIMARY'],
        })
    if args.assetname:
        primary_asset['name'] = args.assetname
    _tag_seed_provenance(primary_asset, seed_by_value.get(primary_host))

    primary_id = primary_asset['id']
    primary_domain = None if _is_ip_address(primary_host) else get_registered_domain(primary_host)
    if primary_domain:
        primary_asset['tags'].append('EASM_ROOT_DOMAIN:' + primary_domain)

    if not getattr(args, 'no_nuclei', False) and nuclei_exists():
        _stage(primary_host, "nuclei web application tests")
        severity = getattr(args, 'nuclei_severity', 'info,low,medium,high,critical')
        primary_asset['config_issues'].extend(run_nuclei(primary_host, primary_id, severity, getattr(args, 'nuclei_timeout', 3600)))
    elif not getattr(args, 'no_nuclei', False):
        logging.info("[EASM] %s: nuclei CLI not found on PATH - skipping web application tests", primary_host)

    assessed_domains = set()
    if primary_domain:
        _assess_domain(args, primary_domain, primary_asset, primary_host, owner, nmap_cache, _register)
        assessed_domains.add(primary_domain)

    # ---- additional domain / host seeds ------------------------------
    for s in dh_seeds:
        if s.value == primary_host:
            continue
        seed_asset = _register(build_host_asset(args, s.value, owner, False, nmap_cache))
        _tag_seed_provenance(seed_asset, s)
        if seed_asset is not None:
            _maybe_nuclei_extra(args, s.value, seed_asset)
        rd = get_registered_domain(s.value)
        if not rd or rd in assessed_domains:
            continue
        assessed_domains.add(rd)
        if seed_asset is not None:
            anchor, anchor_host = seed_asset, s.value
            anchor.setdefault('tags', [])
            if 'EASM_ROOT_DOMAIN:' + rd not in anchor['tags']:
                anchor['tags'].append('EASM_ROOT_DOMAIN:' + rd)
        else:
            anchor = _register({
                'id': rd, 'name': rd, 'type': 'Domain', 'owner': owner,
                'products': [], 'config_issues': [],
                'tags': ['DISCOVERY_TYPE:Unauthenticated', 'EASM',
                         'EASM_SEED:' + s.raw, 'EASM_ROOT_DOMAIN:' + rd],
            })
            anchor_host = rd
        _assess_domain(args, rd, anchor, anchor_host, owner, nmap_cache, _register)

    # ---- explicit IP seeds (always reported) -----------------------
    for ip, raw in explicit_ips:
        if ip in assets_by_id:
            _tag_seed_provenance(assets_by_id[ip], seed_by_value.get(ip))
            continue
        ip_asset = build_host_asset(args, ip, owner, False, nmap_cache)
        if ip_asset is None:
            continue
        _tag_seed_provenance(ip_asset, seed_by_value.get(ip))
        _register(ip_asset)
        _maybe_nuclei_extra(args, ip, ip_asset)

    # ---- swept IP targets from CIDR/ASN (reported only if non-empty) --
    for ip, prov in swept_ips:
        if ip in assets_by_id:
            continue
        ip_asset = build_host_asset(args, ip, owner, False, nmap_cache)
        if ip_asset is None:
            continue
        ip_asset['tags'].append('EASM_SEED:' + prov)
        if _register(ip_asset, skip_if_empty=True) is None:
            continue
        _maybe_nuclei_extra(args, ip, ip_asset)

    # ---- netblock PTR + port sweep (explicit CIDR/ASN seeds; owned ASNs with --asn_sweep) ----
    sweep_targets = []   # (prefix, label)
    for s in seed_list:
        if s.kind == seeds.SEED_CIDR:
            sweep_targets.append((s.value, 'seed CIDR ' + s.value))
        elif s.kind == seeds.SEED_ASN:
            for p in seeds.asn_announced_prefixes(s.value):
                sweep_targets.append((p, '%s %s' % (s.value, p)))
    if getattr(args, 'asn_sweep', False) and primary_domain:
        for asn, info in netblock_sweep.derive_org_asns(primary_domain, resolve_ips(primary_host)).items():
            for p in info['prefixes']:
                sweep_targets.append((p, 'AS%s %s (%s)' % (asn, p, info['name'])))

    if sweep_targets and not getattr(args, 'no_netblock_sweep', False):
        seen_pfx = set()
        budget = getattr(args, 'max_seed_hosts', 256) or 256
        for pfx, label in sweep_targets:
            if pfx in seen_pfx:
                continue
            seen_pfx.add(pfx)
            _stage(primary_host, "reverse-DNS sweep of %s" % label)
            ptr_issues, ptr_found = netblock_sweep.sweep_prefixes([pfx], primary_id, label)
            primary_asset['config_issues'].extend(ptr_issues)
            if not getattr(args, 'no_portsweep', False):
                _stage(primary_host, "port sweep of %s" % label)
                results, engine = portsweep.sweep_netblock(pfx, args)
                si = portsweep.summary_issue(pfx, results, engine, primary_id)
                if si:
                    primary_asset['config_issues'].append(si)
                for ip in sorted(results):
                    if budget <= 0 or ip in assets_by_id:
                        continue
                    a = build_host_asset(args, ip, owner, False, nmap_cache)
                    if a is None:
                        continue
                    a['tags'].append('EASM_SEED:' + label)
                    if _register(a, skip_if_empty=True) is not None:
                        budget -= 1
                        _maybe_nuclei_extra(args, ip, a)
            for ip, hn in list(ptr_found.items()):
                if budget <= 0 or ip in assets_by_id or hn in assets_by_id:
                    continue
                a = build_host_asset(args, hn, owner, False, nmap_cache)
                if a is None:
                    continue
                a['tags'].append('EASM_DISCOVERED_VIA:ptr-sweep')
                if _register(a, skip_if_empty=True) is not None:
                    budget -= 1

    # ---- recursive discovery: gated re-assessment of related domains ----
    if getattr(args, 'recursive_discovery', False):
        seed_regs = {get_registered_domain(s.value) for s in dh_seeds if not _is_ip_address(s.value)}
        max_depth = getattr(args, 'max_discovery_depth', 1) or 1
        take = getattr(args, 'max_discovered_domains', 10) or 10
        for depth in range(1, max_depth + 1):
            cand = _harvest_related_domains(assets, assessed_domains | seed_regs | {None})
            if not cand:
                break
            picked = sorted(cand)[:take]
            logging.info("[EASM] recursive discovery depth %d: %d related domain(s): %s",
                         depth, len(picked), ', '.join(picked))
            for rd in picked:
                if rd in assessed_domains:
                    continue
                assessed_domains.add(rd)
                a = _register(build_host_asset(args, rd, owner, False, nmap_cache))
                if a is None:
                    a = _register({
                        'id': rd, 'name': rd, 'type': 'Domain', 'owner': owner,
                        'products': [], 'config_issues': [],
                        'tags': ['DISCOVERY_TYPE:Unauthenticated', 'EASM', 'EASM_ROOT_DOMAIN:' + rd]})
                a['tags'].append('EASM_DISCOVERED_DEPTH:%d' % depth)
                a['tags'].append('EASM_DISCOVERED_VIA:' + cand[rd])
                _assess_domain(args, rd, a, rd, owner, nmap_cache, _register)
            take = max(2, take // 2)

    if len(assets) == 1 and not primary_asset['products'] and not primary_asset['config_issues']:
        logging.warning("Nothing to report for: %s", primary_host)
        return None

    if not getattr(args, 'no_kev_epss', False):
        _stage(primary_host, "KEV / EPSS exploitation enrichment + risk-ranking")
        kev_epss.apply(assets, ttl=getattr(args, 'kev_epss_ttl', kev_epss.DEFAULT_TTL))

    logging.info("[EASM] assessment complete for [%s] - %d asset(s) reported", primary_host, len(assets))
    return assets
