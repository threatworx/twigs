"""Quick domain scan (--quick): a short, passive / light-touch subset of the
full EASM assessment for a single domain.

Runs the fast, high-signal checks (passive subdomain discovery, email / DNS
hygiene, dangling-CNAME takeover, TLS certificate health and a time-boxed
named-vulnerability TLS audit, HTTP security headers, technology fingerprint, WAF, WHOIS, lookalike domains, exposed risky
services) and turns off everything slow or intrusive (nmap service/version
probing and scripts, nuclei, content / directory / API discovery, DNS brute
force, netblock sweeps, ...).

Port exposure uses a plain TCP connect on a short list of risky ports - no
banner grabbing, version detection or scripts.

Safety: domain seeds only, and any target resolving to a non-public address
(loopback, RFC1918, link-local, cloud metadata, ...) is refused so a hostile
domain cannot be used to probe the scanning machine's internal network.
"""
import socket
import signal
import logging
import ipaddress
import contextlib
from concurrent.futures import ThreadPoolExecutor

from .constants import RISKY_PORTS
from .util import _is_ipv6
from . import seeds

QUICK_TAG = 'EASM_QUICK'

# Checks that are slow, intrusive or reserved for the full scan.
QUICK_DISABLED = [
    'nuclei', 'content_discovery', 'dir_brute', 'js_analysis', 'api_discovery',
    'graphql_enum', 'openapi_probe', 'exposed_panel_check', 'web_recon',
    'open_redirect_check', 'http_methods_check', 'directory_listing_check',
    'version_probe', 'udp_scan', 'reverse_ip', 'reverse_whois', 'saas_discovery',
    'bucket_discovery', 'zone_walk', 'netblock_sweep', 'portsweep',
    'tls_fingerprint', 'dnsbl_check', 'ipv6', 'subdomain_permutations',
    'subdomain_bruteforce', 'kev_epss',
]

# Off-by-default features that must stay off even if given on the command line.
QUICK_FORCED_OFF = ['full_port_scan', 'asn_sweep', 'recursive_discovery', 'github_repo_scan']

# Upper bounds (0 means "unlimited" for typosquat_limit, so it is bumped to the cap).
QUICK_CAPS = {
    'max_subdomains': 10,
    'ssl_audit_timeout': 45,
    'max_seed_hosts': 1,
    'typosquat_limit': 50,
    'typosquat_whois_limit': 5,
    'typosquat_dns_limit': 100,
}

QUICK_DEFAULT_TIMEOUT = 300
QUICK_MAX_IPS_PER_HOST = 4

CONNECT_PORTS = sorted(set(RISKY_PORTS) | {80, 443})
CONNECT_TIMEOUT = 2.0
CONNECT_WORKERS = 32
_PORT_SERVICE = {80: 'http', 443: 'https'}


class QuickTimeout(BaseException):
    """Raised (from SIGALRM) when the quick scan exceeds its time budget.
    BaseException so the many `except Exception` blocks in the checks don't
    swallow it."""


def apply_profile(args):
    for name in QUICK_DISABLED:
        setattr(args, 'no_' + name, True)
    for name in QUICK_FORCED_OFF:
        setattr(args, name, False)
    args.extra_ports = None
    for name, cap in QUICK_CAPS.items():
        cur = getattr(args, name, 0) or 0
        setattr(args, name, min(cur, cap) if cur > 0 else cap)
    logging.info("[EASM] quick scan mode - passive / light-touch checks only")


def validate_seeds(seed_list):
    """Returns an error string if the seeds aren't a single domain/hostname."""
    if len(seed_list) != 1 or seed_list[0].kind not in (seeds.SEED_DOMAIN, seeds.SEED_HOST):
        return "--quick supports a single domain or hostname (IP, CIDR and ASN seeds and multiple seeds require the full scan)"
    return None


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def non_public(ips):
    return [ip for ip in ips if not is_public_ip(ip)]


def connect_scan(ips):
    """TCP connect check of CONNECT_PORTS against the first few resolved
    addresses. Returns a host_result dict shaped like nmap_discovery's."""
    ips = ips[:QUICK_MAX_IPS_PER_HOST]
    if not ips:
        return None

    def _probe(ip, port):
        s = socket.socket(socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        try:
            return port if s.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    open_ports = set()
    with ThreadPoolExecutor(max_workers=CONNECT_WORKERS) as pool:
        futs = [pool.submit(_probe, ip, po) for ip in ips for po in CONNECT_PORTS]
        for f in futs:
            r = f.result()
            if r:
                open_ports.add(r)
    return {
        'ip': ips[0], 'hostname': ips[0], 'ostype': 'Other', 'products': [],
        'ports': [{'port': p, 'protocol': 'tcp', 'service': _PORT_SERVICE.get(p),
                   'product': None, 'version': None, 'extrainfo': None,
                   'title': None, 'banner': None} for p in sorted(open_ports)],
    }


@contextlib.contextmanager
def deadline(seconds):
    """Raise QuickTimeout in the main thread after `seconds` (no-op where
    SIGALRM/setitimer is unavailable, e.g. Windows or non-main threads)."""
    if not seconds or not hasattr(signal, 'setitimer'):
        yield
        return

    def _fire(signum, frame):
        raise QuickTimeout()

    try:
        old = signal.signal(signal.SIGALRM, _fire)
    except ValueError:      # not the main thread
        yield
        return
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
