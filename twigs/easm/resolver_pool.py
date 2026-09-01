"""A vetted pool of public recursive resolvers for high-concurrency DNS
brute force.

Using one system resolver for a 20k-label wordlist plus a permutation round
is slow and rude. This module keeps several public resolvers, drops any that
"lie" (NXDOMAIN hijacking / captive-portal wildcards / a broken control
answer), and hands out resolver objects round-robin so brute-force workers
spread load and tolerate a single resolver rate-limiting or going dark.

Thread-based (the rest of the package is threads); "async" here means high
worker concurrency, not asyncio.
"""
import random
import logging
import threading
from itertools import cycle

try:
    import dns.resolver
    import dns.exception
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

from .constants import DNS_TIMEOUT

# Well-known open recursive resolvers (v4). Order is not significance.
DEFAULT_RESOLVERS = [
    '1.1.1.1', '1.0.0.1',          # Cloudflare
    '8.8.8.8', '8.8.4.4',          # Google
    '9.9.9.9', '149.112.112.112',  # Quad9
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '94.140.14.140', '94.140.14.141',    # AdGuard (non-filtering)
    '64.6.64.6',                   # Verisign
]

# Control queries used to vet a resolver.
_CONTROL_GOOD = ('one.one.one.one', 'dns.google', 'www.iana.org')
_CONTROL_NX = 'nxdomain-vet-%s.example'   # %s filled with a random token

_lock = threading.Lock()
_POOL = None


def _mk_resolver(ip):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [ip]
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def _is_honest(ip):
    """True if `ip` answers a known-good name and correctly NXDOMAINs a
    random name (no hijack/redirect)."""
    r = _mk_resolver(ip)
    ok = False
    for good in _CONTROL_GOOD:
        try:
            if r.resolve(good, 'A'):
                ok = True
                break
        except Exception:
            continue
    if not ok:
        return False
    token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=18))
    try:
        r.resolve(_CONTROL_NX % token, 'A')
        return False          # a resolver that answers this is lying
    except dns.resolver.NXDOMAIN:
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return True
    except Exception:
        return False


class ResolverPool:
    def __init__(self, resolvers):
        self._resolvers = list(resolvers)
        self._cycle = cycle(self._resolvers) if self._resolvers else None
        self._n = len(self._resolvers)

    def __bool__(self):
        return self._n > 0

    def __len__(self):
        return self._n

    def pick(self):
        with _lock:
            return next(self._cycle) if self._cycle else None

    def resolve_record(self, name, rtype, attempts=2):
        """_resolve_record semantics (answers or None), retried across
        different pool members on transient failure."""
        last = None
        for _ in range(max(1, attempts)):
            r = self.pick()
            if r is None:
                return None
            try:
                return r.resolve(name, rtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                last = e
                continue
            except Exception as e:
                last = e
                continue
        if last:
            logging.debug("resolver pool: %s/%s failed after retries: %s", name, rtype, last)
        return None


def get_pool(overrides=None, force=False):
    """Memoised vetted pool. `overrides` is an optional list/CSV of resolver
    IPs to use instead of DEFAULT_RESOLVERS."""
    global _POOL
    if _POOL is not None and not force:
        return _POOL
    if not HAVE_DNSPYTHON:
        _POOL = ResolverPool([])
        return _POOL

    if isinstance(overrides, str):
        cand = [x.strip() for x in overrides.split(',') if x.strip()]
    else:
        cand = list(overrides) if overrides else list(DEFAULT_RESOLVERS)

    honest = []
    for ip in cand:
        try:
            if _is_honest(ip):
                honest.append(_mk_resolver(ip))
        except Exception:
            continue
    logging.info("[EASM] resolver pool: %d/%d public resolver(s) vetted honest", len(honest), len(cand))
    _POOL = ResolverPool(honest)
    return _POOL
