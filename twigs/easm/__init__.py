"""
External Attack Surface Management (EASM) discovery module.

Given a single fully qualified hostname or domain name, this module performs
unauthenticated, internet-facing reconnaissance:

  - host / service discovery (independent nmap wrapper, not twigs.fingerprint)
  - subdomain enumeration (certificate transparency + DNS brute force)
  - host / service discovery against discovered subdomains
  - SSL/TLS certificate and protocol checks
  - SSL/TLS named-vulnerability scanning (Heartbleed, POODLE, FREAK, Logjam,
    DROWN, ROBOT, BEAST, CRIME, weak/NULL/export ciphers, etc.) against the
    primary host and every discovered subdomain, via the vendored testssl.sh
    (twigs.ssl_audit)
  - DNS hygiene checks (zone transfer, dangling CNAME / subdomain takeover,
    CAA certificate-authority-authorization records, DNSSEC chain-of-trust
    status)
  - technology stack discovery (HTTP headers/HTML fingerprinting), including
    client-side JavaScript library detection by name+version (CDN URL
    conventions, self-hosted filenames, and a bounded content-banner fetch
    fallback) - reported as products only, no vulnerability correlation of
    its own since ThreatWorx's backend maps products to known CVEs
  - HTTP security headers audit (HSTS, Content-Security-Policy,
    X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and cookie
    security flags (Secure/HttpOnly/SameSite) for every discovered host
  - MTA-STS/TLS-RPT (inbound mail transport encryption policy) and BIMI
    checks, alongside the existing SPF/DMARC/DKIM/MX checks
  - Subresource Integrity (SRI) check on cross-origin scripts/stylesheets
  - security.txt (RFC 9116) and robots.txt/sitemap.xml reconnaissance
  - open-redirect probing of common query parameters
  - email security checks (SPF/DMARC/DKIM/MX)
  - firewall / WAF discovery
  - web application tests via the nuclei CLI (used only if present on PATH)
  - typosquatting checks (lookalike domain permutations)
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
  - mixed content (HTTP resources loaded on an HTTPS page) and favicon hash
    fingerprinting (an mmh3 hash reported as an asset tag, for infrastructure
    correlation - not a vulnerability finding on its own)
  - HTTP method enumeration (PUT/DELETE/TRACE/CONNECT advertised via Allow)
    and directory listing (autoindex) detection on common paths
  - wildcard DNS detection ahead of subdomain brute force, so guessed labels
    aren't falsely reported as existing when a domain resolves anything
  - DNSBL/IP reputation lookups (Spamhaus ZEN) for every discovered host's
    resolved IPv4 address(es)
  - nameserver delegation consistency (lame delegation) checking

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

from .constants import RATING_INFO, RATING_HIGH, ISSUE_TYPE_SUBDOMAIN, ISSUE_TYPE_DNS
from .util import resolve_ips, _is_ip_address, _is_ipv6, get_registered_domain, HAVE_DNSPYTHON, _get_dns_resolver, _new_issue
from .nmap_discovery import nmap_exists, run_nmap_scan, create_port_issues
from .ssl_checks import check_ssl, check_ssl_vulnerabilities
from .tech_stack import check_tech_stack
from .waf import check_waf
from .http_headers import check_security_headers, check_cookie_security
from .web_recon import check_security_txt, check_robots_sitemap, check_open_redirect, check_http_methods, check_directory_listing
from .exposed_panels import check_exposed_panels
from .api_discovery import check_api_discovery
from .asn_netblock import check_asn_netblock
from .dnsbl import check_dnsbl
from .nuclei_scan import nuclei_exists, run_nuclei
from .whois_lookup import check_whois
from .leakradar import get_leakradar_api_key, check_leakradar
from .ransomware_live import get_ransomware_live_api_key, check_ransomware_live
from .email_security import check_email_security
from .dns_hygiene import check_zone_transfer, check_dangling_cname, check_caa_records, check_dnssec, check_ns_consistency
from .typosquatting import check_typosquatting
from .subdomains import enumerate_subdomains, COMMON_SUBDOMAINS


def build_host_asset(args, hostname, owner, is_primary, nmap_cache):
    ips = resolve_ips(hostname)
    if not ips and not _is_ip_address(hostname):
        logging.warning("Unable to resolve [%s] - skipping", hostname)
        return None

    ipv4_ips = [ip for ip in ips if not _is_ipv6(ip)]
    scan_target = (ipv4_ips[0] if ipv4_ips else ips[0]) if ips else hostname
    host_result = nmap_cache.get(scan_target)
    if host_result is None:
        host_result = run_nmap_scan(args, scan_target)
        nmap_cache[scan_target] = host_result

    asset_data = {
        'id': hostname,
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

    if host_result:
        asset_data['config_issues'].extend(create_port_issues(host_result, hostname))

    if not getattr(args, 'no_ssl_checks', False):
        asset_data['config_issues'].extend(check_ssl(hostname, host_result, hostname))

    if not getattr(args, 'no_ssl_audit', False):
        asset_data['config_issues'].extend(check_ssl_vulnerabilities(
            hostname, host_result, hostname, getattr(args, 'ssl_audit_timeout', 120)))

    if not getattr(args, 'no_tech_stack', False):
        asset_data['config_issues'].extend(check_tech_stack(hostname, asset_data['products'], asset_data['tags'], hostname))

    if not getattr(args, 'no_waf_check', False):
        asset_data['config_issues'].extend(check_waf(hostname, hostname))

    if not getattr(args, 'no_security_headers_check', False):
        asset_data['config_issues'].extend(check_security_headers(hostname, hostname))

    if not getattr(args, 'no_cookie_check', False):
        asset_data['config_issues'].extend(check_cookie_security(hostname, hostname))

    if not getattr(args, 'no_exposed_panel_check', False):
        asset_data['config_issues'].extend(check_exposed_panels(hostname, hostname))

    if not getattr(args, 'no_api_discovery', False):
        asset_data['config_issues'].extend(check_api_discovery(hostname, hostname))

    if not getattr(args, 'no_web_recon', False):
        asset_data['config_issues'].extend(check_security_txt(hostname, hostname))
        asset_data['config_issues'].extend(check_robots_sitemap(hostname, hostname))

    if not getattr(args, 'no_open_redirect_check', False):
        asset_data['config_issues'].extend(check_open_redirect(hostname, hostname))

    if not getattr(args, 'no_http_methods_check', False):
        asset_data['config_issues'].extend(check_http_methods(hostname, hostname))

    if not getattr(args, 'no_directory_listing_check', False):
        asset_data['config_issues'].extend(check_directory_listing(hostname, hostname))

    if not getattr(args, 'no_asn_lookup', False):
        asset_data['config_issues'].extend(check_asn_netblock(hostname, ips, hostname))

    if not getattr(args, 'no_dnsbl_check', False):
        asset_data['config_issues'].extend(check_dnsbl(hostname, ips, hostname))

    return asset_data


def get_inventory(args):
    if not nmap_exists():
        logging.warning("nmap CLI not found - host/service discovery will be skipped")

    host = (args.fqdn or '').strip().lower()
    if not host:
        logging.error("[--fqdn] cannot be empty")
        return None

    owner = args.handle
    nmap_cache = {}

    primary_asset = build_host_asset(args, host, owner, True, nmap_cache)
    if primary_asset is None:
        primary_asset = {
            'id': host, 'name': host, 'type': 'Domain', 'owner': owner,
            'products': [], 'config_issues': [], 'tags': ['DISCOVERY_TYPE:Unauthenticated', 'EASM', 'EASM_PRIMARY'],
        }
    if args.assetname:
        primary_asset['name'] = args.assetname

    assets = [primary_asset]

    is_ip_target = _is_ip_address(host)
    domain = None if is_ip_target else get_registered_domain(host)
    if domain:
        primary_asset['tags'].append('EASM_ROOT_DOMAIN:' + domain)

    if not getattr(args, 'no_nuclei', False) and nuclei_exists():
        severity = getattr(args, 'nuclei_severity', 'critical,high,medium')
        primary_asset['config_issues'].extend(run_nuclei(host, host, severity, getattr(args, 'nuclei_timeout', 600)))
    elif not getattr(args, 'no_nuclei', False):
        logging.debug("nuclei CLI not found on PATH - skipping web application tests")

    if domain:
        if not getattr(args, 'no_whois', False):
            primary_asset['config_issues'].extend(check_whois(domain, host))

        leakradar_api_key = get_leakradar_api_key(args)
        if leakradar_api_key:
            primary_asset['config_issues'].extend(check_leakradar(domain, host, leakradar_api_key))

        ransomware_live_api_key = get_ransomware_live_api_key(args)
        if ransomware_live_api_key:
            primary_asset['config_issues'].extend(check_ransomware_live(domain, host, ransomware_live_api_key))

        if not getattr(args, 'no_email_security', False):
            primary_asset['config_issues'].extend(check_email_security(domain, host))

        if not getattr(args, 'no_dns_checks', False):
            primary_asset['config_issues'].extend(check_zone_transfer(domain, host))
            primary_asset['config_issues'].extend(check_caa_records(domain, host))
            primary_asset['config_issues'].extend(check_dnssec(domain, host))
            primary_asset['config_issues'].extend(check_ns_consistency(domain, host))

        if not getattr(args, 'no_typosquatting', False):
            primary_asset['config_issues'].extend(check_typosquatting(domain, host, args))

        if not getattr(args, 'no_subdomain_enum', False):
            discovered, wildcard_dns = enumerate_subdomains(domain, args)
            discovered.discard(host)

            if wildcard_dns:
                primary_asset['config_issues'].append(_new_issue(
                    'dns-wildcard-detected', "Wildcard DNS detected - brute-force subdomain enumeration skipped",
                    "Domain [%s] resolves arbitrary, non-existent subdomain labels to an IP address (wildcard DNS). This makes DNS brute-force guessing unreliable - every guessed label would falsely appear to \"exist\" - so it was skipped for this domain; only subdomains found via certificate transparency (which reflect a real certificate actually issued for that name) are reported." % domain,
                    RATING_INFO, host, ISSUE_TYPE_DNS, object_id=domain,
                    remediation="No action required unless the wildcard itself is unintentional. Be aware wildcard DNS can also mask a genuinely dangling/unclaimed subdomain from external detection, since every name appears to resolve."))
                summary_detail = "Discovered [%s] candidate subdomain(s) for [%s] via certificate transparency logs (DNS brute force was skipped - see the wildcard DNS finding above). This list reflects hostnames a certificate was actually issued for and may include subdomains no longer in active use." % (len(discovered), domain)
            else:
                summary_detail = "Discovered [%s] candidate subdomain(s) for [%s] via certificate transparency logs and DNS brute force (a curated wordlist of %s common labels). This list reflects hostnames with historical or current DNS/certificate presence and may include subdomains that are no longer in active use." % (len(discovered), domain, len(COMMON_SUBDOMAINS))

            primary_asset['config_issues'].append(_new_issue(
                'subdomain-enum-summary', "Subdomain enumeration summary",
                summary_detail,
                RATING_INFO, host, ISSUE_TYPE_SUBDOMAIN, object_id=domain,
                remediation="Review the discovered subdomains to confirm each is still in active, authorized use. Decommission unused subdomains and remove their DNS records to reduce the attack surface, and ensure inactive ones are not left pointing at services that could be claimed by an attacker (see subdomain takeover findings below, if any)."))

            takeover_found = False
            tested_dangling = 0
            if HAVE_DNSPYTHON and discovered:
                resolver = _get_dns_resolver()
                for sub in list(discovered)[:200]:
                    tested_dangling += 1
                    takeover_target = check_dangling_cname(sub, resolver)
                    if takeover_target:
                        takeover_found = True
                        primary_asset['config_issues'].append(_new_issue(
                            'dns-dangling-cname-%s' % sub, "Possible subdomain takeover: %s" % sub,
                            "Subdomain [%s] has a CNAME record pointing to [%s], a third-party/cloud-hosted resource that does not currently resolve to any content. If that resource name is available to be claimed by anyone (e.g. an unclaimed S3 bucket, GitHub Pages site, Azure/Heroku app name), an attacker could register it and serve arbitrary content - including phishing pages or malware - under your trusted domain name." % (sub, takeover_target),
                            RATING_HIGH, host, ISSUE_TYPE_DNS, object_id=sub,
                            remediation="Either remove the stale CNAME record if the third-party resource is no longer used, or (re)claim/re-provision the referenced resource under your account so it cannot be claimed by someone else. Verify by confirming the resource resolves to content you control before considering this resolved."))
                if not takeover_found and tested_dangling > 0:
                    primary_asset['config_issues'].append(_new_issue(
                        'dns-dangling-cname-none-found', "No subdomain takeover risk found",
                        "Checked [%s] discovered subdomain(s) for CNAME records pointing at known-takeover-able third-party services (e.g. GitHub Pages, S3, Azure, Heroku) with a non-resolving target, and found none." % tested_dangling,
                        RATING_INFO, host, ISSUE_TYPE_DNS, object_id=domain,
                        remediation="No action required. Re-check periodically, especially after decommissioning any third-party integrations."))

            max_subdomains = getattr(args, 'max_subdomains', 25) or 25
            live_subdomains = []
            for sub in discovered:
                ips = resolve_ips(sub)
                if ips:
                    live_subdomains.append(sub)
                if len(live_subdomains) >= max_subdomains:
                    break

            scan_subdomain_web = getattr(args, 'nuclei_all_hosts', False)
            for sub in live_subdomains:
                sub_asset = build_host_asset(args, sub, owner, False, nmap_cache)
                if sub_asset is None:
                    continue
                sub_asset['tags'].append('EASM_ROOT_DOMAIN:' + domain)
                if scan_subdomain_web and not getattr(args, 'no_nuclei', False) and nuclei_exists():
                    severity = getattr(args, 'nuclei_severity', 'critical,high,medium')
                    sub_asset['config_issues'].extend(run_nuclei(sub, sub, severity, getattr(args, 'nuclei_timeout', 600)))
                if leakradar_api_key:
                    sub_asset['config_issues'].extend(check_leakradar(sub, sub, leakradar_api_key))
                if len(sub_asset['products']) == 0 and len(sub_asset['config_issues']) == 0:
                    logging.debug("Nothing discovered for subdomain [%s] - skipping", sub)
                    continue
                assets.append(sub_asset)

    if len(assets) == 1 and len(primary_asset['products']) == 0 and len(primary_asset['config_issues']) == 0:
        logging.warning("Nothing to report for: %s", host)
        return None

    return assets
