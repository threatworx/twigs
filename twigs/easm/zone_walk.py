"""DNSSEC NSEC / NSEC3 zone walking.

On a DNSSEC-signed zone that uses plain NSEC, the signed proof-of-non-existence
returned for any bogus name points at the *next* existing name in canonical
order. Chaining those pointers walks the entire zone contents out - every
hostname, plus (from the NSEC type bitmap) which record types each name
carries - with no brute-force guessing at all.

NSEC3 hashes the owner names, so the same walk only yields salted hashes
(still crackable offline, but the cost is bounded by the iteration count),
and the NSEC3 opt-out flag additionally lets unsigned delegations be spliced
into the zone.

This module walks NSEC zones (feeding the recovered hostnames back into
subdomain assessment) and, for NSEC3 zones, reports parameter choices that
weaken the zone (excessive iterations per RFC 9276, opt-out enabled). It is
deliberately quiet when the zone is not DNSSEC-signed - dns_hygiene's
check_dnssec already reports that.
"""
import time
import logging
import secrets

try:
    import dns.message
    import dns.query
    import dns.name
    import dns.rdatatype
    import dns.rdataclass
    import dns.flags
    import dns.exception
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, ISSUE_TYPE_DNS, DNS_TIMEOUT
from .util import _new_issue, resolve_ips, _get_dns_resolver, _resolve_record

MAX_NAMES = 5000        # hard cap on NSEC chain length walked
MAX_LISTED = 300        # names written into the finding detail
WALK_BUDGET_SECS = 60   # wall-clock ceiling for the whole walk


def _auth_ns_ips(domain):
    ips = []
    resolver = _get_dns_resolver()
    ns = _resolve_record(resolver, domain, 'NS')
    if not ns:
        return ips
    for rr in ns:
        for ip in resolve_ips(str(rr.target).rstrip('.')):
            if ':' not in ip and ip not in ips:   # UDP walk over IPv4 only
                ips.append(ip)
    return ips


def _query(ns_ip, qname, qtype):
    try:
        q = dns.message.make_query(qname, qtype, want_dnssec=True)
    except dns.exception.DNSException:
        return None
    try:
        r = dns.query.udp(q, ns_ip, timeout=DNS_TIMEOUT)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, ns_ip, timeout=DNS_TIMEOUT)
        return r
    except Exception:
        try:
            return dns.query.tcp(q, ns_ip, timeout=DNS_TIMEOUT)
        except Exception:
            return None


def _rrsets(msg, rdtype):
    out = []
    if not msg:
        return out
    for section in (msg.answer, msg.authority):
        for rrset in section:
            if rrset.rdtype == rdtype:
                out.append(rrset)
    return out


def _is_signed(ns_ips, domain):
    for ip in ns_ips:
        r = _query(ip, domain, dns.rdatatype.DNSKEY)
        if r and _rrsets(r, dns.rdatatype.DNSKEY):
            return True
    return False


def _probe_nonexistent(ns_ips, domain):
    """Returns (mode, msg, ns_ip): mode is 'nsec' | 'nsec3' | None."""
    qname = 'zw-' + secrets.token_hex(8) + '.' + domain
    for ip in ns_ips:
        r = _query(ip, qname, dns.rdatatype.A)
        if not r:
            continue
        if _rrsets(r, dns.rdatatype.NSEC3):
            return 'nsec3', r, ip
        if _rrsets(r, dns.rdatatype.NSEC):
            return 'nsec', r, ip
    return None, None, None


def _walk_nsec(ns_ip, domain):
    """Follow the NSEC next-name chain from the apex all the way round.
    Returns (sorted recovered subdomain names, synthetic) where `synthetic`
    is True when the nameserver was generating minimally-covering NSEC
    records on the fly ('black lies' / white lies), which defeats walking."""
    origin = dns.name.from_text(domain)
    found = set()
    current = origin
    seen = {origin}
    synthetic = False
    deadline = time.time() + WALK_BUDGET_SECS

    for _ in range(MAX_NAMES):
        if time.time() > deadline:
            logging.debug("[EASM] zone_walk: time budget hit after %d name(s)", len(found))
            break

        # Canonically smallest name strictly greater than `current`.
        try:
            probe = dns.name.Name((b'\x00',) + current.labels)
        except dns.exception.DNSException:
            break
        r = _query(ns_ip, probe.to_text(), dns.rdatatype.A)
        nsec_sets = _rrsets(r, dns.rdatatype.NSEC)
        if not nsec_sets:
            # Some servers only return NSEC for the exact owner name.
            r = _query(ns_ip, current.to_text(), dns.rdatatype.NSEC)
            nsec_sets = _rrsets(r, dns.rdatatype.NSEC)
            if not nsec_sets:
                break

        chosen = None
        for s in nsec_sets:
            if s.name == current:
                chosen = s
                break
            if chosen is None:
                chosen = s
        rd = chosen[0]

        try:
            nxt = rd.next if isinstance(rd.next, dns.name.Name) else dns.name.from_text(str(rd.next))
        except Exception:
            break

        # On-the-fly / 'black lies' NSEC: the record covers exactly the queried
        # bogus name and its `next` is that name with a synthetic \000 label
        # bolted on, so the chain never reaches a real name. Both the owner and
        # the next of such a record carry a literal \000 first label, which a
        # real zone name never does.
        owner_synthetic = bool(chosen.name.labels) and chosen.name.labels[0] == b'\x00'
        next_synthetic = bool(nxt.labels) and nxt.labels[0] == b'\x00'
        if owner_synthetic and next_synthetic:
            synthetic = True
            break

        owner = chosen.name.to_text().rstrip('.').lower()
        if (owner and owner != domain and '*' not in owner and '\\000' not in owner
                and owner.endswith(domain) and not owner_synthetic):
            found.add(owner)

        if nxt == current or nxt == origin or nxt in seen or not nxt.is_subdomain(origin):
            break
        if len(nxt.to_text()) > 250:
            break
        seen.add(nxt)
        current = nxt

    return sorted(found), synthetic


def _nsec3_params(ns_ip, domain, fallback_msg):
    r = _query(ns_ip, domain, dns.rdatatype.NSEC3PARAM)
    for s in _rrsets(r, dns.rdatatype.NSEC3PARAM):
        rd = s[0]
        return {'iterations': rd.iterations, 'flags': getattr(rd, 'flags', 0),
                'salt': rd.salt.hex() if rd.salt else '-'}
    for s in _rrsets(fallback_msg, dns.rdatatype.NSEC3):
        rd = s[0]
        return {'iterations': rd.iterations, 'flags': getattr(rd, 'flags', 0),
                'salt': rd.salt.hex() if rd.salt else '-'}
    return None


def check_zone_walk(domain, asset_id, args):
    """Returns (issues, recovered_subdomain_names)."""
    if not HAVE_DNSPYTHON:
        return [], []
    ns_ips = _auth_ns_ips(domain)
    if not ns_ips:
        return [], []
    if not _is_signed(ns_ips, domain):
        return [], []

    mode, msg, ns_ip = _probe_nonexistent(ns_ips, domain)

    if mode == 'nsec':
        names, synthetic = _walk_nsec(ns_ip, domain)
        if not names and synthetic:
            return [_new_issue(
                'dnssec-nsec-blacklies', "DNSSEC NSEC generated on the fly (zone walking mitigated)",
                "Domain [%s] is DNSSEC-signed and its nameserver answers non-existent names with minimally-covering NSEC records synthesised on demand ('white lies' / 'black lies', e.g. Cloudflare, Knot, PowerDNS nsec3-narrow). Chain walking cannot enumerate the zone in this configuration." % domain,
                RATING_INFO, asset_id, ISSUE_TYPE_DNS, object_id=domain,
                remediation="No action required - this is the recommended configuration for defeating zone enumeration."),
            ], []
        if names:
            listed = names[:MAX_LISTED]
            more = '' if len(names) <= MAX_LISTED else ' (and %d more)' % (len(names) - MAX_LISTED)
            logging.info("[EASM] zone_walk: NSEC walk of [%s] recovered %d name(s)", domain, len(names))
            return [_new_issue(
                'dnssec-nsec-zone-walk', "DNSSEC zone contents enumerable via NSEC walking",
                "Domain [%s] is DNSSEC-signed using plain NSEC records. NSEC proves a name does not exist by naming the next name that does, so the whole zone can be walked out with no brute forcing. Walking the NSEC chain recovered %d name(s)%s:\n%s"
                % (domain, len(names), more, '\n'.join(listed)),
                RATING_MEDIUM, asset_id, ISSUE_TYPE_DNS, object_id=domain,
                object_meta=','.join(names[:60]),
                remediation="Switch the zone from NSEC to NSEC3 (RFC 5155) so names are only published as salted hashes, or use a signer/DNS platform that synthesises minimally-covering NSEC/NSEC3 records on the fly ('white lies' / 'black lies', e.g. Cloudflare, PowerDNS nsec3-narrow, Knot). With NSEC3 follow RFC 9276: SHA-1, 0 extra iterations, empty salt. Names that genuinely must not be publicly known should not live in a publicly DNSSEC-signed zone at all - use a split-horizon or internal-only zone."),
            ], names
        return [_new_issue(
            'dnssec-nsec-present', "DNSSEC NSEC in use (zone walking possible)",
            "Domain [%s] is DNSSEC-signed using plain NSEC rather than NSEC3. NSEC lets the full zone contents be enumerated by walking its chain of next-name pointers; this scan did not recover names (the nameserver may rate-limit, reorder, or only answer NSEC for exact owners), but the exposure stands." % domain,
            RATING_LOW, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation="Move to NSEC3 (RFC 5155) with RFC 9276 parameters (SHA-1, 0 additional iterations, empty salt), or to a signer that synthesises minimally-covering NSEC/NSEC3 records on demand."),
        ], []

    if mode == 'nsec3':
        params = _nsec3_params(ns_ip, domain, msg)
        it = params['iterations'] if params else 0
        optout = bool(params['flags'] & 0x01) if params else False
        salt = params['salt'] if params else '?'
        rating = RATING_INFO
        weaknesses = []
        if it > 0:
            weaknesses.append("%d additional hash iteration(s) are configured (RFC 9276 recommends 0; values above ~100 cause some validating resolvers to treat the zone as insecure or to SERVFAIL, and add a CPU-amplification vector)" % it)
            if it > 100:
                rating = RATING_LOW
        if optout:
            weaknesses.append("the opt-out flag is set, which lets unsigned delegations be inserted under this zone without breaking the NSEC3 chain")
            if rating == RATING_INFO:
                rating = RATING_LOW
        detail = ("Domain [%s] is DNSSEC-signed using NSEC3 (salt %s, %d iteration(s)). NSEC3 publishes only salted hashes of the zone's names, so chain walking yields hashes rather than plaintext - still enumerable offline with a wordlist (nsec3walker / nsec3map), but bounded by the per-guess iteration cost." % (domain, salt, it))
        if weaknesses:
            detail += " Weaknesses in the current parameters: " + '; '.join(weaknesses) + "."
        return [_new_issue(
            'dnssec-nsec3', "DNSSEC NSEC3 parameters",
            detail, rating, asset_id, ISSUE_TYPE_DNS, object_id=domain,
            remediation=("Adopt RFC 9276 parameters: hash algorithm SHA-1, 0 additional iterations, and an empty salt. "
                         + ("Disable NSEC3 opt-out unless this zone delegates to many unsigned children and that trade-off is understood. " if optout else "")
                         + "To defeat offline hash enumeration entirely, use a signer that generates minimally-covering NSEC3 records on the fly.")),
        ], []

    return [], []
