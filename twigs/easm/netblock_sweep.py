"""Netblock-scale discovery of assets that were never seeded:

  * derive_org_asns(domain, ips)  - from a seeded domain's resolved IPs,
    look up the origin ASN(s) (Team Cymru) and keep the ones that look
    target-owned (AS name is not a known hoster, and the AS announces only a
    modest number of prefixes) together with their announced prefixes.

  * ptr_sweep(cidr, ...)          - reverse-DNS every address in a prefix and
    return {ip: hostname} for those that have a PTR record. A cheap way to
    enumerate live, named hosts across a range before spending a full
    host-assessment budget on it.
"""
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import RATING_INFO, ISSUE_TYPE_ASN, ISSUE_TYPE_SUBDOMAIN
from .util import HAVE_DNSPYTHON, _get_dns_resolver, _resolve_record, _is_ipv6, _new_issue
from .asn_netblock import _cymru_asn_lookup, KNOWN_HOSTING_PROVIDER_TOKENS
from .seeds import asn_announced_prefixes

# An AS that announces more prefixes than this is treated as a
# provider/hoster, not an enterprise's own space - too broad to PTR-sweep.
MAX_OWNED_ASN_PREFIXES = 40
PTR_SWEEP_MAX_ADDRS = 8192      # hard cap on addresses reverse-resolved per call
PTR_SWEEP_WORKERS = 40


def derive_org_asns(domain, ips):
    """{asn: {'name':.., 'prefixes':[..]}} for ASNs that look target-owned."""
    if not HAVE_DNSPYTHON or not ips:
        return {}
    resolver = _get_dns_resolver()
    out = {}
    for ip in ips:
        info = _cymru_asn_lookup(ip, resolver)
        if not info or not info.get('asn'):
            continue
        asn = info['asn']
        if asn in out:
            continue
        name = (info.get('as_name') or '').lower()
        if any(tok in name for tok in KNOWN_HOSTING_PROVIDER_TOKENS):
            logging.info("[EASM] netblock_sweep: AS%s (%s) looks like a hoster - not treating as target-owned", asn, name or '?')
            continue
        prefixes = asn_announced_prefixes('AS' + asn)
        if not prefixes or len(prefixes) > MAX_OWNED_ASN_PREFIXES:
            logging.info("[EASM] netblock_sweep: AS%s announces %d prefix(es) - too broad, skipping", asn, len(prefixes))
            continue
        out[asn] = {'name': info.get('as_name') or 'unknown', 'prefixes': prefixes}
        logging.info("[EASM] netblock_sweep: AS%s (%s) - %d prefix(es), treating as target-owned",
                     asn, out[asn]['name'], len(prefixes))
    return out


def _ptr(resolver, ip):
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None
    ans = _resolve_record(resolver, rev, 'PTR')
    if not ans:
        return None
    for rr in ans:
        return str(getattr(rr, 'target', rr)).rstrip('.').lower()
    return None


def ptr_sweep(cidr, limit=PTR_SWEEP_MAX_ADDRS, workers=PTR_SWEEP_WORKERS):
    """{ip: ptr_hostname} for addresses in `cidr` that have a PTR record."""
    if not HAVE_DNSPYTHON:
        return {}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {}
    if _is_ipv6(str(net.network_address)) and net.num_addresses > limit:
        logging.info("[EASM] netblock_sweep: %s is a large IPv6 range - PTR sweep skipped", cidr)
        return {}
    addrs = []
    for a in (net.hosts() if net.num_addresses > 2 else net):
        addrs.append(str(a))
        if len(addrs) >= limit:
            logging.warning("[EASM] netblock_sweep: %s truncated to %d addresses for PTR sweep", cidr, limit)
            break
    resolver = _get_dns_resolver()
    found = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_ptr, resolver, ip): ip for ip in addrs}
        for fut in as_completed(futs):
            name = fut.result()
            if name:
                found[futs[fut]] = name
    return found


def sweep_prefixes(prefixes, asset_id, source_label, limit_total=PTR_SWEEP_MAX_ADDRS):
    """PTR-sweep a list of prefixes; return (issues, {ip: hostname})."""
    all_found = {}
    budget = limit_total
    for pfx in prefixes:
        if budget <= 0:
            break
        got = ptr_sweep(pfx, limit=budget)
        all_found.update(got)
        try:
            budget -= ipaddress.ip_network(pfx, strict=False).num_addresses
        except ValueError:
            pass
    if not all_found:
        return [], {}
    lines = ["%s  %s" % (ip, hn) for ip, hn in sorted(all_found.items())][:400]
    issue = _new_issue(
        'netblock-ptr-sweep', "Hosts discovered by reverse-DNS sweep of %s" % source_label,
        "A reverse-DNS (PTR) sweep of %s found %d address(es) with a hostname - live, named infrastructure in space attributed to the target that was not explicitly seeded:\n%s"
        % (source_label, len(all_found), '\n'.join(lines)),
        RATING_INFO, asset_id, ISSUE_TYPE_SUBDOMAIN, object_id=source_label,
        object_meta=','.join(sorted({hn for hn in all_found.values()}))[:4000],
        remediation="Confirm which of these hosts belong to your organisation and fold them into the monitored inventory. Reverse-DNS names often reveal internal naming conventions and forgotten hosts.")
    return [issue], all_found
