"""DNSBL / IP reputation check: looks up each resolved public IPv4 address
against the free Spamhaus ZEN DNSBL - a plain DNS A-record query against
their public mirror, no API key or account needed. A listing means Spamhaus
already considers the IP a spam source, an exploited/compromised host, or
subject to a sending-policy restriction - useful signal that infrastructure
may already be abused or compromised, independent of anything else this
module finds.

Deliberately IPv4-only and one lookup per resolved IP per host (not a bulk
scan) - well within Spamhaus's public-mirror usage guidelines for ad hoc,
low-volume queries; a mail server checking every inbound connection at scale
is expected to use their data-feed product instead."""
import ipaddress

from .constants import RATING_INFO, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_DNS
from .util import _get_dns_resolver, _resolve_record, _new_issue, _is_ip_address

# Spamhaus ZEN return-code meanings (last octet of the 127.0.0.x response).
# https://www.spamhaus.org/zen/ - reproduced only for the documented/stable
# codes; anything else is reported generically rather than guessed at.
ZEN_CODES = {
    '2': ('SBL', "a static Spamhaus Block List entry (known spam source or spam-support infrastructure)"),
    '3': ('SBL CSS', "a Spamhaus CSS snowshoe-spam listing"),
    '4': ('XBL', "the Exploits Block List - shows signs of infection (open proxy, worm, trojan/bot)"),
    '5': ('XBL', "the Exploits Block List - shows signs of infection (open proxy, worm, trojan/bot)"),
    '6': ('XBL', "the Exploits Block List - shows signs of infection (open proxy, worm, trojan/bot)"),
    '7': ('XBL', "the Exploits Block List - shows signs of infection (open proxy, worm, trojan/bot)"),
    '9': ('PBL', "the Policy Block List - the network operator has stated this IP should not be sending mail directly (a policy signal, not itself evidence of compromise)"),
    '10': ('PBL', "the Policy Block List - the network operator has stated this IP should not be sending mail directly (a policy signal, not itself evidence of compromise)"),
}


def check_dnsbl(host, ips, asset_id):
    issues = []
    resolver = _get_dns_resolver()
    tested = 0
    for ip in ips:
        if not _is_ip_address(ip):
            continue
        addr = ipaddress.ip_address(ip)
        if addr.version != 4 or addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            continue
        tested += 1
        reversed_ip = '.'.join(reversed(ip.split('.')))
        answers = _resolve_record(resolver, reversed_ip + '.zen.spamhaus.org', 'A')
        if not answers:
            continue

        labels, descs = [], []
        for rr in answers:
            addr_str = getattr(rr, 'address', None) or str(rr)
            last_octet = addr_str.rsplit('.', 1)[-1]
            label, desc = ZEN_CODES.get(last_octet, (last_octet, "an undocumented/newer Spamhaus ZEN listing code"))
            labels.append(label)
            descs.append(desc)
        unique_labels = sorted(set(labels))
        rating = RATING_MEDIUM if unique_labels == ['PBL'] else RATING_HIGH
        issues.append(_new_issue(
            'dnsbl-listed-%s' % ip.replace('.', '-'),
            "IP address listed on Spamhaus ZEN (%s)" % ', '.join(unique_labels),
            "[%s] (%s) is currently listed on the Spamhaus ZEN DNSBL: %s. %s" % (host, ip, ', '.join(unique_labels), '; '.join(sorted(set(descs)))),
            rating, asset_id, ISSUE_TYPE_DNS, object_id=ip,
            remediation="If this IP sends mail or interacts with anti-abuse-conscious services, investigate why it's listed (compromised host, misconfigured relay, or a shared-hosting/cloud IP carrying a previous tenant's bad reputation) and request delisting at https://www.spamhaus.org/lookup/ once the underlying cause is fixed."))

    if tested and not issues:
        issues.append(_new_issue(
            'dnsbl-not-listed', "No DNSBL listings found",
            "Checked [%s] public IPv4 address(es) resolved for [%s] against the Spamhaus ZEN DNSBL and found no listings." % (tested, host),
            RATING_INFO, asset_id, ISSUE_TYPE_DNS, object_id=host,
            remediation="No action required."))
    return issues
