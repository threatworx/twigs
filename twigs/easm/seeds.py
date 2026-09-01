"""Seed input parsing for EASM.

An EASM run starts from one or more *seeds*. A seed is a single operator-
supplied string (via ``--fqdn``, a repeatable ``--seed``, or ``--seed_file``)
classified here into one of:

  domain  a registrable domain - its own registered domain is itself
          (example.com). Full assessment: domain-level checks (WHOIS, email
          security, DNS hygiene, typosquatting, subdomain enumeration) plus
          host-level checks on every resolved IP.
  host    a hostname below a registrable domain (api.example.com). Host-level
          checks on the host; domain-level checks also run once against its
          registered domain.
  ip      a single IPv4/IPv6 address. Host-level checks only.
  cidr    an IPv4/IPv6 network in prefix notation (198.51.100.0/24). Expanded
          to its host addresses - bounded by ``--max_seed_hosts`` across the
          whole run - each assessed host-level only.
  asn     an autonomous system number ("AS14618" or a bare "14618"). Announced
          prefixes are fetched from RIPEstat (free, no key) and each is
          treated as a cidr seed.

Hostnames discovered later (subdomain enumeration, reverse DNS, ...) are not
seeds: they only ever get host-level assessment. Domain-level checks run only
for domains that were themselves seeded.
"""
import re
import json
import logging
import ipaddress
from collections import namedtuple

from . import _cache
from .util import _is_ip_address, get_registered_domain

SEED_DOMAIN = 'domain'
SEED_HOST = 'host'
SEED_IP = 'ip'
SEED_CIDR = 'cidr'
SEED_ASN = 'asn'

# (kind, value, raw, source). value is the normalised form (lowercased
# host/domain, str(ip_address), str(ip_network), "AS<n>"); raw is exactly what
# the operator supplied; source is "--fqdn" / "--seed" / "--seed_file:<path>".
Seed = namedtuple('Seed', 'kind value raw source')

_ASN_RE = re.compile(r'^as(\d{1,10})$', re.I)
_HOSTNAME_RE = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')

RIPESTAT_ANNOUNCED_PREFIXES = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s'


def _looks_like_hostname(s):
    if '.' not in s or not _HOSTNAME_RE.match(s):
        return False
    labels = s.split('.')
    if any(not (1 <= len(l) <= 63) for l in labels):
        return False
    return bool(re.match(r'^[a-z]{2,}$', labels[-1]))


def classify(raw):
    """(kind, value) for a single seed string, or None if unrecognisable."""
    s = (raw or '').strip().strip('[]').rstrip('.').lower()
    if not s:
        return None

    m = _ASN_RE.match(s)
    if m:
        return SEED_ASN, 'AS' + str(int(m.group(1)))
    if s.isdigit() and len(s) <= 10:
        return SEED_ASN, 'AS' + str(int(s))

    try:
        net = ipaddress.ip_network(s, strict=False)
        if net.num_addresses == 1:
            return SEED_IP, str(net.network_address)
        return SEED_CIDR, str(net)
    except ValueError:
        pass
    if _is_ip_address(s):
        return SEED_IP, s

    if not _looks_like_hostname(s):
        return None
    rd = get_registered_domain(s)
    if rd and rd == s:
        return SEED_DOMAIN, s
    return SEED_HOST, s


def load(args):
    """Return (seeds, errors). seeds is a de-duplicated list of Seed; errors
    is a list of (raw, source) that could not be classified."""
    raw_inputs = []
    if getattr(args, 'fqdn', None):
        raw_inputs.append((args.fqdn, '--fqdn'))
    for val in (getattr(args, 'seed', None) or []):
        raw_inputs.append((val, '--seed'))
    seed_file = getattr(args, 'seed_file', None)
    if seed_file:
        try:
            with open(seed_file, 'r') as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        raw_inputs.append((line, '--seed_file:' + seed_file))
        except OSError as e:
            logging.error("[EASM] could not read --seed_file [%s]: %s", seed_file, e)

    seeds, errors, seen = [], [], set()
    for raw, source in raw_inputs:
        c = classify(raw)
        if c is None:
            errors.append((raw, source))
            continue
        kind, value = c
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        seeds.append(Seed(kind, value, raw.strip(), source))
    return seeds, errors


def asn_announced_prefixes(asn, ttl=86400):
    """Announced prefixes for an ASN via RIPEstat (cached). [] on failure."""
    num = asn[2:] if asn.lower().startswith('as') else asn
    raw = _cache.cached_get(RIPESTAT_ANNOUNCED_PREFIXES % num,
                            'ripestat_as%s.json' % num, ttl, sub='seeds')
    if not raw:
        return []
    try:
        data = json.loads(raw)
        out = []
        for p in data.get('data', {}).get('prefixes', []):
            pfx = p.get('prefix')
            if not pfx:
                continue
            try:
                ipaddress.ip_network(pfx, strict=False)
            except ValueError:
                continue
            out.append(pfx)
        return out
    except (ValueError, TypeError) as e:
        logging.warning("[EASM] RIPEstat announced-prefixes parse failed for %s: %s", asn, e)
        return []


def iter_cidr_hosts(cidr, limit):
    """Up to `limit` usable host-address strings from a CIDR (list, not
    generator, so the caller can len() it for budget accounting)."""
    if limit <= 0:
        return []
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses == 1:
        it = iter([net.network_address])
    else:
        it = net.hosts()
    out = []
    for ip in it:
        out.append(str(ip))
        if len(out) >= limit:
            break
    return out
