"""Small, widely-shared helpers used by most twigs.easm check modules:
building a config-issue dict, IP/hostname helpers, bounded DNS resolution,
and a generic bounded-HTTP-GET wrapper."""
import os
import re
import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

import requests

try:
    import dns.resolver
    import dns.exception
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

try:
    import tldextract
    HAVE_TLDEXTRACT = True
except ImportError:
    HAVE_TLDEXTRACT = False

from .constants import DNS_TIMEOUT, HTTP_TIMEOUT, USER_AGENT


def _new_issue(twc_id, twc_title, details, rating, asset_id, itype, object_id='', remediation=None, object_meta='', cve=None):
    if remediation:
        details = details.rstrip() + ' Remediation: ' + remediation
    return {
        'twc_id': 'easm-' + twc_id,
        'twc_title': twc_title,
        'details': details,
        'rating': rating,
        'object_id': object_id,
        'asset_id': asset_id,
        'object_meta': object_meta,
        'type': itype,
        # CVE id(s) this finding is about, if any - consumed by kev_epss for
        # KEV/EPSS risk-ranking. Always a list (possibly empty).
        'cve': [c.upper() for c in cve] if isinstance(cve, (list, tuple, set)) else ([cve.upper()] if cve else []),
    }


def _add_product(products, product):
    product = product.strip()
    if product and product not in products:
        products.append(product)


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_ipv6(value):
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def get_registered_domain(hostname):
    if HAVE_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return ext.domain + '.' + ext.suffix
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname


def _call_with_timeout(func, timeout, *args, **kwargs):
    """Runs func in a worker thread and enforces a hard wall-clock timeout.
    Used to bound third-party/stdlib calls (e.g. socket.getaddrinfo, dnstwist's
    WHOIS client) that accept no timeout of their own and could otherwise hang
    the whole scan. On timeout the worker thread is abandoned - not killed,
    Python cannot forcibly kill a thread - rather than waited on, so the caller
    is never blocked beyond `timeout`."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(func, *args, **kwargs).result(timeout=timeout)
    finally:
        pool.shutdown(wait=False)


def resolve_ips(hostname):
    if _is_ip_address(hostname):
        return [hostname]
    ips = []
    if HAVE_DNSPYTHON:
        # dns.resolver enforces a real timeout/lifetime (see _get_dns_resolver),
        # unlike socket.getaddrinfo() below which has no timeout of its own and
        # can hang indefinitely against a broken/unresponsive resolver.
        resolver = _get_dns_resolver()
        for rtype in ('A', 'AAAA'):
            answers = _resolve_record(resolver, hostname, rtype)
            if not answers:
                continue
            for rr in answers:
                addr = getattr(rr, 'address', None) or str(rr)
                if addr not in ips:
                    ips.append(addr)
        return ips
    try:
        infos = _call_with_timeout(socket.getaddrinfo, DNS_TIMEOUT * 2, hostname, None)
        for info in infos:
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
    except FuturesTimeoutError:
        logging.debug("DNS resolution for [%s] timed out", hostname)
    except socket.gaierror as e:
        logging.debug("Unable to resolve [%s]: %s", hostname, str(e))
    return ips


def _get_dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def _resolve_record(resolver, name, rtype):
    try:
        answers = resolver.resolve(name, rtype)
        return answers
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception as e:
        logging.debug("DNS lookup error for [%s/%s]: %s", name, rtype, str(e))
        return None



def _http_get(url):
    try:
        return requests.get(url, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True,
                             headers={'User-Agent': USER_AGENT})
    except requests.exceptions.RequestException as e:
        logging.debug("HTTP GET failed for [%s]: %s", url, str(e))
        return None
