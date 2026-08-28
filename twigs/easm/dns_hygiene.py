"""DNS hygiene checks: zone transfer (AXFR), dangling CNAME / subdomain
takeover, CAA (Certificate Authority Authorization) records, DNSSEC
chain-of-trust status, and nameserver delegation consistency (lame
delegation)."""
try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.message
    import dns.flags
    import dns.rcode
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_DNS, DNS_TIMEOUT
from .util import resolve_ips, _get_dns_resolver, _resolve_record, _new_issue

# CNAME target suffixes with a documented history of being takeover-able
# when the referenced third-party resource is not claimed.
DANGLING_CNAME_SERVICES = [
    '.github.io', '.herokuapp.com', '.herokudns.com', '.s3.amazonaws.com',
    '.s3-website', '.azurewebsites.net', '.cloudapp.net', '.cloudapp.azure.com',
    '.trafficmanager.net', '.blob.core.windows.net', '.wordpress.com',
    '.myshopify.com', '.fastly.net', '.pantheonsite.io', '.surge.sh',
    '.readthedocs.io', '.zendesk.com', '.statuspage.io', '.helpscoutdocs.com',
    '.wpengine.com', '.netlify.app', '.vercel.app', '.firebaseapp.com',
    '.bitbucket.io', '.ghost.io', '.desk.com', '.uservoice.com',
    '.tumblr.com', '.unbouncepages.com', '.webflow.io', '.cargocollective.com',
]


def check_zone_transfer(domain, asset_id):
    issues = []
    if not HAVE_DNSPYTHON:
        return issues
    resolver = _get_dns_resolver()
    ns_answers = _resolve_record(resolver, domain, 'NS')
    if not ns_answers:
        return issues
    tested = 0
    for ns in ns_answers:
        ns_name = str(ns.target).rstrip('.')
        ns_ips = resolve_ips(ns_name)
        for ns_ip in ns_ips:
            tested += 1
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=6, lifetime=8))
                record_count = len(list(zone.nodes.keys()))
                issues.append(_new_issue('dns-zone-transfer', "DNS zone transfer (AXFR) allowed",
                                          "Nameserver [%s] (%s) allows unauthenticated DNS zone transfer (AXFR) for domain [%s], exposing [%s] DNS record(s) - potentially including internal/staging hostnames, infrastructure naming conventions, and other reconnaissance data that is not meant to be public." % (ns_name, ns_ip, domain, record_count),
                                          RATING_CRITICAL, asset_id, ISSUE_TYPE_DNS, object_id=ns_name,
                                          remediation="Disable zone transfers to unauthorized/untrusted hosts on this nameserver (e.g. 'allow-transfer' ACLs in BIND, or the equivalent secondary-DNS restriction in your DNS provider/registrar), allowing AXFR only to designated secondary nameservers."))
            except Exception:
                continue
    if not issues and tested > 0:
        issues.append(_new_issue('dns-zone-transfer-not-allowed', "DNS zone transfer (AXFR) not allowed",
                                  "Tested [%s] authoritative nameserver IP(s) for domain [%s] and none permitted an unauthenticated DNS zone transfer (AXFR)." % (tested, domain),
                                  RATING_INFO, asset_id, ISSUE_TYPE_DNS, object_id=domain,
                                  remediation="No action required."))
    return issues


def check_caa_records(domain, asset_id):
    """CAA (RFC 8659) restricts which Certificate Authorities may issue TLS
    certificates for a domain. This is domain-level (like WHOIS/email
    security), not per-host: CAA lookups climb from the queried name up to
    the apex, so a record at the apex already governs subdomains unless a
    subdomain publishes its own override, a rare case not worth a per-host
    re-check here."""
    issues = []
    if not HAVE_DNSPYTHON:
        return issues
    resolver = _get_dns_resolver()
    answers = _resolve_record(resolver, domain, 'CAA')

    if not answers:
        issues.append(_new_issue(
            'caa-not-configured', "No CAA record configured",
            "Domain [%s] does not publish a CAA (Certificate Authority Authorization) DNS record. Without one, any publicly trusted Certificate Authority is permitted to issue TLS certificates for this domain, which slightly widens the set of parties that could mis-issue a certificate for it (through compromise, social engineering, or CA error)." % domain,
            RATING_LOW, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="Consider publishing a CAA record restricting issuance to your actual CA(s), e.g. '%s. CAA 0 issue \"letsencrypt.org\"', and optionally an iodef tag for violation reporting. This is defense-in-depth, not urgent - CAA only constrains CAs that honor it and does not prevent every mis-issuance scenario." % domain))
        return issues

    issuers = []
    wild_issuers = []
    iodef = []
    no_issuance = False
    for rr in answers:
        tag = rr.tag if isinstance(rr.tag, str) else rr.tag.decode('utf-8', errors='replace')
        value = (rr.value if isinstance(rr.value, str) else rr.value.decode('utf-8', errors='replace')).strip()
        if tag == 'issue':
            if value == ';':
                no_issuance = True
            else:
                issuers.append(value)
        elif tag == 'issuewild':
            if value != ';':
                wild_issuers.append(value)
        elif tag == 'iodef':
            iodef.append(value)

    detail_bits = ["Domain [%s] publishes a CAA record." % domain]
    if no_issuance:
        detail_bits.append("Certificate issuance is explicitly disallowed for all CAs (issue \";\").")
    elif issuers:
        detail_bits.append("Authorized issuing CA(s): %s." % ', '.join(sorted(set(issuers))))
    else:
        detail_bits.append("No 'issue' tag is present, so standard certificate issuance is unrestricted (only wildcard issuance is constrained below, if at all).")
    if wild_issuers:
        detail_bits.append("Additionally authorized wildcard-issuing CA(s): %s." % ', '.join(sorted(set(wild_issuers))))
    detail_bits.append(
        "CAA violation reports configured to: %s." % ', '.join(iodef) if iodef
        else "No iodef reporting contact is configured for CAA violations.")

    issues.append(_new_issue(
        'caa-configured', "CAA record configured",
        ' '.join(detail_bits),
        RATING_INFO, asset_id, ISSUE_TYPE_DNS, object_id=domain,
        remediation="No action required. Periodically confirm the authorized CA list still matches your actual certificate provider(s), especially after switching CAs, and consider adding an iodef contact if not already present."))
    return issues


def check_dangling_cname(hostname, resolver):
    try:
        answers = resolver.resolve(hostname, 'CNAME')
    except Exception:
        return None
    for rr in answers:
        target = str(rr.target).rstrip('.')
        for suffix in DANGLING_CNAME_SERVICES:
            if target.endswith(suffix.lstrip('.')):
                if not resolve_ips(target):
                    return target
    return None


def check_dnssec(domain, asset_id):
    """Checks whether DNSSEC is enabled and whether its chain of trust
    (DNSKEY at the domain, linked via a DS record at the parent zone) is
    complete. Does not itself cryptographically validate signatures - it
    only confirms the records needed for validation are present and linked.

    Uses well-known public resolvers (1.1.1.1, 8.8.8.8) rather than the
    host's configured resolver (used everywhere else in this module):
    verified empirically that systemd-resolved's local stub resolver - a
    very common setup on modern Linux - SERVFAILs on DNSKEY/DS queries even
    for correctly-signed domains, which would make this check unreliable for
    a meaningful fraction of real users if it relied on the system default."""
    issues = []
    if not HAVE_DNSPYTHON:
        return issues
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT * 2

    dnskey = _resolve_record(resolver, domain, 'DNSKEY')
    ds = _resolve_record(resolver, domain, 'DS')

    if not dnskey and not ds:
        issues.append(_new_issue(
            'dnssec-not-enabled', "DNSSEC not enabled",
            "Domain [%s] does not publish DNSKEY or DS records, meaning DNSSEC is not enabled. Without DNSSEC, DNS responses for this domain cannot be cryptographically validated, leaving clients unable to detect DNS spoofing/cache-poisoning attacks that redirect traffic to an attacker-controlled server." % domain,
            RATING_LOW, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="Consider enabling DNSSEC signing at your DNS provider/registrar. This is defense-in-depth against DNS spoofing, not urgent - DNSSEC adoption is still a minority practice, and enabling it incorrectly (e.g. a mismatched DS record) can cause total resolution failure for the domain, so follow your provider's guided setup carefully."))
    elif dnskey and not ds:
        issues.append(_new_issue(
            'dnssec-broken-chain', "DNSSEC signing keys published but not linked from the parent zone",
            "Domain [%s] publishes DNSKEY record(s) (DNSSEC signing keys) but no DS record exists at the parent zone/registrar to link them into the chain of trust. DNSSEC-enforcing resolvers cannot actually validate this domain's signatures despite it appearing to have DNSSEC configured." % domain,
            RATING_MEDIUM, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="Publish a DS record at the domain's registrar/parent zone matching the current DNSKEY, completing the chain of trust. Most registrars have a dedicated DNSSEC/DS-record configuration step separate from DNS hosting."))
    elif ds and not dnskey:
        issues.append(_new_issue(
            'dnssec-ds-without-dnskey', "DS record published without a matching DNSKEY",
            "Domain [%s] has a DS record at the parent zone but does not publish a DNSKEY record itself, meaning the chain of trust points to signing keys that do not exist. DNSSEC-enforcing resolvers will treat all responses for this domain as invalid (bogus), which can cause the domain to fail to resolve entirely for those clients." % domain,
            RATING_HIGH, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="This looks like an active misconfiguration, not just an absence of hardening - either remove the stale DS record from the registrar if DNSSEC is not intended, or publish the correct DNSKEY record to complete the chain. Left as-is, DNSSEC-enforcing resolvers may be unable to resolve this domain at all."))
    else:
        issues.append(_new_issue(
            'dnssec-configured', "DNSSEC appears to be configured",
            "Domain [%s] publishes both DNSKEY and DS records, indicating DNSSEC signing is enabled with a chain of trust linked from the parent zone. This check confirms the records are present and linked; it does not independently verify the cryptographic signatures themselves." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="No action required. Most DNS providers automate DNSSEC key rotation - confirm yours does, to avoid an expired-signature outage."))
    return issues


def check_ns_consistency(domain, asset_id):
    """Confirms every authoritative nameserver listed in the domain's NS
    records actually resolves and answers authoritatively for it (a "lame
    delegation" check). A lame nameserver doesn't usually cause a full
    outage by itself - resolvers fall back to the other listed nameservers -
    but it silently reduces redundancy and often indicates a decommissioned
    or misconfigured server that's still listed as authoritative."""
    issues = []
    if not HAVE_DNSPYTHON:
        return issues
    resolver = _get_dns_resolver()
    ns_answers = _resolve_record(resolver, domain, 'NS')
    if not ns_answers:
        return issues

    problems = []
    tested = 0
    for ns in ns_answers:
        ns_name = str(ns.target).rstrip('.')
        ns_ips = resolve_ips(ns_name)
        if not ns_ips:
            tested += 1
            problems.append("%s does not resolve to any IP address" % ns_name)
            continue
        tested += 1
        ns_ip = ns_ips[0]
        try:
            query = dns.message.make_query(domain, 'SOA')
            response = dns.query.udp(query, ns_ip, timeout=DNS_TIMEOUT)
            if response.rcode() != 0:
                problems.append("%s (%s) responded with an error (rcode %s) instead of an authoritative answer" % (ns_name, ns_ip, dns.rcode.to_text(response.rcode())))
            elif not (response.flags & dns.flags.AA):
                problems.append("%s (%s) responded without the Authoritative Answer flag set" % (ns_name, ns_ip))
        except Exception as e:
            problems.append("%s (%s) did not respond to a direct query: %s" % (ns_name, ns_ip, str(e)))

    if problems:
        issues.append(_new_issue(
            'dns-lame-delegation', "Lame or unresponsive nameserver delegation",
            "Domain [%s] lists [%s] authoritative nameserver(s) in its NS records, but querying them directly found [%s] issue(s): %s." % (domain, len(ns_answers), len(problems), '; '.join(problems)),
            RATING_MEDIUM, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="Remove or fix any nameserver listed in NS records that does not actually serve the zone (e.g. a decommissioned secondary, or a stale/typo'd NS record). Verify with 'dig NS %s' and by querying each listed nameserver directly for the zone." % domain))
    elif tested > 0:
        issues.append(_new_issue(
            'dns-lame-delegation-none-found', "All nameservers respond authoritatively",
            "Queried all [%s] authoritative nameserver(s) listed for domain [%s] directly and each responded authoritatively." % (tested, domain),
            RATING_INFO, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="No action required."))
    return issues

