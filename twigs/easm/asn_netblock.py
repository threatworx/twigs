"""ASN / netblock discovery, via Team Cymru's IP-to-ASN DNS lookup service
(no API key, no new dependency - reuses dnspython, already required)."""
import ipaddress

from .constants import RATING_INFO, ISSUE_TYPE_ASN
from .util import _is_ipv6, HAVE_DNSPYTHON, _get_dns_resolver, _resolve_record, _new_issue

# Substrings matched (case-insensitive) against an AS org name to flag
# well-known cloud/CDN/hosting providers vs. infrastructure that appears to
# be owned/operated directly by the target organization. This is only a
# triage heuristic, not authoritative - always confirm via WHOIS/RDAP.
KNOWN_HOSTING_PROVIDER_TOKENS = [
    'amazon', 'aws', 'google', 'microsoft', 'azure', 'cloudflare', 'fastly',
    'akamai', 'digitalocean', 'ovh', 'hetzner', 'linode', 'godaddy',
    'namecheap', 'squarespace', 'wix.com', 'shopify', 'oracle corp', 'alibaba',
    'tencent', 'ibm cloud', 'rackspace', 'vultr', 'contabo', 'leaseweb',
    'choopa', 'incapsula', 'imperva', 'stackpath', 'edgecast', 'limelight',
    'cachefly', 'fly.io', 'render', 'heroku', 'vercel', 'netlify',
]


def _cymru_asn_lookup(ip, resolver):
    if _is_ipv6(ip):
        try:
            expanded = ipaddress.IPv6Address(ip).exploded.replace(':', '')
        except ValueError:
            return None
        query = '.'.join(reversed(list(expanded))) + '.origin6.asn.cymru.com'
    else:
        octets = ip.split('.')
        if len(octets) != 4:
            return None
        query = '.'.join(reversed(octets)) + '.origin.asn.cymru.com'

    answers = _resolve_record(resolver, query, 'TXT')
    if not answers:
        return None
    txt = b''.join(answers[0].strings).decode('utf-8', errors='replace')
    parts = [p.strip() for p in txt.split('|')]
    if len(parts) < 4:
        return None
    # A prefix can be announced by multiple ASNs (multi-homing); use the first.
    asn = parts[0].split(',')[0].strip()
    result = {'asn': asn, 'prefix': parts[1], 'country': parts[2], 'registry': parts[3], 'as_name': None}

    asn_answers = _resolve_record(resolver, 'AS%s.asn.cymru.com' % asn, 'TXT')
    if asn_answers:
        asn_parts = [p.strip() for p in b''.join(asn_answers[0].strings).decode('utf-8', errors='replace').split('|')]
        if len(asn_parts) >= 5:
            result['as_name'] = asn_parts[4]
    return result


def check_asn_netblock(hostname, ips, asset_id):
    issues = []
    if not HAVE_DNSPYTHON or not ips:
        return issues
    resolver = _get_dns_resolver()
    seen = set()
    for ip in ips:
        info = _cymru_asn_lookup(ip, resolver)
        if not info:
            continue
        key = (info['asn'], info['prefix'])
        if key in seen:
            continue
        seen.add(key)

        as_name = info['as_name'] or 'unknown organization'
        is_known_provider = any(tok in as_name.lower() for tok in KNOWN_HOSTING_PROVIDER_TOKENS)
        hosting_note = (
            "This ASN/netblock is registered to a well-known cloud/CDN/hosting provider, consistent with third-party-hosted infrastructure."
            if is_known_provider else
            "This ASN/netblock does not match a well-known cloud/CDN/hosting provider name pattern, which may indicate infrastructure directly owned/operated by the target organization (worth manually confirming via the registry's WHOIS/RDAP record)."
        )

        issues.append(_new_issue(
            'asn-netblock-%s-%s' % (info['asn'], info['prefix'].replace('/', '_').replace(':', '_')),
            "Hosting network: AS%s (%s) - %s" % (info['asn'], as_name, info['prefix']),
            "[%s] (%s) is announced by AS%s (%s), registered with %s, netblock [%s], country [%s]. %s" % (
                hostname, ip, info['asn'], as_name, info['registry'].upper(), info['prefix'], info['country'], hosting_note),
            RATING_INFO, asset_id, ISSUE_TYPE_ASN, object_id=info['prefix'],
            remediation="No action required. Useful for attack-surface mapping: if this netblock is directly owned by your organization, consider whether other hosts in the same range should also be inventoried (out of scope for this automatic scan, which only probes the discovered hostname/IP); if it belongs to a third-party host/CDN, note the shared-infrastructure dependency for risk assessment."))
    return issues
