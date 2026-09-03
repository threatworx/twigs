"""End-to-end IPv6 coverage.

The rest of the EASM pipeline already resolves AAAA records (resolve_ips),
lets nmap target an IPv6 literal (-6), matches published IPv6 cloud prefixes,
and makes HTTP/TLS connections over whichever address family the OS selects.
This module closes the remaining gaps so a dual-stack or IPv6-only host is
actually assessed as one:

  * every resolved address (v4 and v6) is tagged, and the host's IP stack
    (dualstack / ipv6-only / ipv4-only) is recorded as an IP_STACK: tag
  * the host's IPv6 address is port-scanned and its open-port set is compared
    to IPv4 - a port reachable over IPv6 but not IPv4 is flagged as a
    firewall gap (v6 packet-filter rules lagging v4 is a well-known blind
    spot)
  * an IPv6-only host is called out (IPv4-only scanners / monitoring / RBLs
    do not see it at all)
  * IPv6 cloud / CDN attribution is merged in

Subdomain brute force is made AAAA-aware separately (subdomains.py) so
IPv6-only hostnames are discovered too, not just IPv4 ones.
"""
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, ISSUE_TYPE_PORTS
from .util import _new_issue, _is_ipv6
from .nmap_discovery import nmap_exists, run_nmap_scan
from . import cloud_ranges

# Compact top-port set for the fast IPv6 TCP sweep (non-primary hosts, or when
# nmap is unavailable).
V6_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 5985,
    6379, 8000, 8080, 8443, 9200, 9300, 11211, 27017,
]
_PROBE_TIMEOUT = 2.5
_MAX_TAGGED = 6


def _split(ips):
    v4 = [ip for ip in ips if not _is_ipv6(ip)]
    v6 = [ip for ip in ips if _is_ipv6(ip)]
    return v4, v6


def _tag(tags, t):
    if tags is not None and t not in tags:
        tags.append(t)


def _tcp_open_v6(addr, ports, workers=40, timeout=_PROBE_TIMEOUT):
    def _probe(p):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return p if s.connect_ex((addr, p, 0, 0)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    open_ports = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for f in as_completed([pool.submit(_probe, p) for p in ports]):
            try:
                r = f.result()
            except Exception:
                r = None
            if r:
                open_ports.add(r)
    return open_ports


def _tcp_ports(nmap_result):
    if not nmap_result:
        return None                      # unknown - cannot diff
    return {p['port'] for p in nmap_result.get('ports', [])
            if (p.get('protocol') or 'tcp') == 'tcp'}


def check_ipv6(hostname, ips, host_result, products, tags, asset_id, args,
               is_primary=False, nmap_cache=None):
    if getattr(args, 'no_ipv6', False):
        return []

    v4, v6 = _split(ips or [])
    stack = ('dualstack' if v4 and v6 else
             'ipv6-only' if v6 else
             'ipv4-only' if v4 else 'unknown')
    _tag(tags, 'IP_STACK:' + stack)
    for a in v6[:_MAX_TAGGED]:
        _tag(tags, 'IPV6:' + a)
        _tag(tags, 'IP:' + a)

    if not v6:
        return []

    v6addr = v6[0]
    issues = []

    if not getattr(args, 'no_cloud_attribution', False):
        info = cloud_ranges.lookup(v6addr, ttl=getattr(args, 'cloud_ranges_ttl', cloud_ranges.DEFAULT_TTL))
        for t in cloud_ranges.as_tags(info):
            _tag(tags, t)
        if info is not None:
            logging.info("[EASM] %s: IPv6 %s attributed to %s (%s)", hostname, v6addr, info.provider, info.kind)

    # Full nmap -6 service scan on the primary host (or when explicitly asked
    # for every host); a fast TCP sweep everywhere else.
    v6_ports = set()
    v6_result = None
    if nmap_exists() and (is_primary or getattr(args, 'ipv6_scan_all_hosts', False)):
        if nmap_cache is not None and v6addr in nmap_cache:
            v6_result = nmap_cache[v6addr]
        else:
            _log = "[EASM] %s: nmap -6 service scan of %s" % (hostname, v6addr)
            logging.info(_log)
            v6_result = run_nmap_scan(args, v6addr)
            if nmap_cache is not None:
                nmap_cache[v6addr] = v6_result
        if v6_result:
            v6_ports = _tcp_ports(v6_result) or set()
            for prod in v6_result.get('products', []):
                if prod and prod not in products:
                    products.append(prod)
    if not v6_ports:
        v6_ports = _tcp_open_v6(v6addr, V6_TOP_PORTS)

    if not v6_ports:
        issues.append(_new_issue(
            'ipv6-no-open-ports', "IPv6 address published but no common port reachable",
            "Host [%s] publishes an AAAA record (%s) but none of the %d common TCP ports probed over IPv6 accepted a connection. The AAAA record may be stale, or every service may be firewalled on IPv6." % (hostname, v6addr, len(V6_TOP_PORTS)),
            RATING_LOW, asset_id, ISSUE_TYPE_PORTS, object_id=v6addr,
            remediation="If IPv6 is not meant to be served, remove the AAAA record so clients do not attempt (and time out on) IPv6 first. If it is meant to be served, confirm the service is actually listening on IPv6 and that its firewall rules are in place."))
        return issues

    listed = ', '.join(str(p) for p in sorted(v6_ports))
    issues.append(_new_issue(
        'ipv6-reachable', "Host reachable over IPv6",
        "Host [%s] is reachable over IPv6 at [%s]; open TCP port(s): %s.%s" % (
            hostname, v6addr, listed,
            " Service/version detail from an nmap -6 scan has been folded into this asset's product list." if v6_result else ""),
        RATING_INFO, asset_id, ISSUE_TYPE_PORTS, object_id=v6addr, object_meta=listed,
        remediation="No action required. Ensure this host's IPv6 services are patched, logged, and monitored to the same standard as its IPv4 services, and that IPv6 exposure is intentional."))

    v4_ports = _tcp_ports(host_result)
    if v4_ports is not None:
        only_v6 = sorted(v6_ports - v4_ports)
        if only_v6:
            issues.append(_new_issue(
                'ipv6-firewall-gap', "Service(s) exposed over IPv6 but not IPv4 (firewall gap)",
                "On host [%s], TCP port(s) %s accept connections over IPv6 (%s) but not over IPv4 (%s). IPv6 packet-filter / security-group rules that are not kept in sync with IPv4 are a common, often-missed exposure: a service the operator believes is firewalled is in fact reachable from the internet over IPv6." % (
                    hostname, ', '.join(str(p) for p in only_v6), v6addr, v4[0] if v4 else 'no A record'),
                RATING_MEDIUM, asset_id, ISSUE_TYPE_PORTS, object_id=v6addr,
                object_meta=','.join(str(p) for p in only_v6),
                remediation="Bring the IPv6 firewall ruleset to parity with IPv4 - every restriction enforced on IPv4 needs an equivalent IPv6 rule (ip6tables, nftables 'inet' family, or the IPv6 rules of the cloud security group), and default-deny must apply to both families."))

    if stack == 'ipv6-only':
        issues.append(_new_issue(
            'ipv6-only-host', "Host is reachable only over IPv6",
            "Host [%s] resolves to an IPv6 address (%s) and has no A record. IPv4-only vulnerability scanners, uptime/security monitoring, and IP reputation/block-lists do not see this host at all, so it can drift out of an organisation's visibility while remaining fully internet-exposed." % (hostname, v6addr),
            RATING_LOW, asset_id, ISSUE_TYPE_PORTS, object_id=v6addr,
            remediation="Make sure this host is covered by the same vulnerability scanning, logging, and monitoring as dual-stack hosts, using tooling that supports IPv6. If the IPv6-only exposure is unintentional, restrict it or add the corresponding IPv4 service behind the same controls."))

    return issues
