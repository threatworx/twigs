"""Tiny on-disk cache for EASM's external data feeds (CISA KEV, EPSS, and
future reverse-WHOIS / passive-DNS / ASN lookups).

One file per key under ~/.twigs/cache/easm/<sub>/ (override with the
TWIGS_EASM_CACHE_DIR env var), TTL by file mtime, with a stale-fallback: if a
refresh fetch fails, the last good copy is returned rather than nothing.
`requests` is imported defensively - with no network `cached_get`/`fetch`
just return whatever (possibly stale) copy is on disk, or None.
"""
import os
import time
import logging
import tempfile

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import USER_AGENT

DEFAULT_TIMEOUT = 30


def cache_dir(sub=''):
    base = os.environ.get('TWIGS_EASM_CACHE_DIR') or \
        os.path.join(os.path.expanduser('~'), '.twigs', 'cache', 'easm')
    path = os.path.join(base, sub) if sub else base
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except OSError:
        path = os.path.join(tempfile.gettempdir(), 'twigs_easm_cache', sub)
        os.makedirs(path, exist_ok=True)
        return path


def read(name, ttl, sub=''):
    """Returns (text, is_fresh). (None, False) if absent/unreadable."""
    p = os.path.join(cache_dir(sub), name)
    try:
        age = time.time() - os.path.getmtime(p)
        with open(p, 'r', encoding='utf-8') as fh:
            return fh.read(), age <= ttl
    except (OSError, ValueError):
        return None, False


def write(name, text, sub=''):
    try:
        with open(os.path.join(cache_dir(sub), name), 'w', encoding='utf-8') as fh:
            fh.write(text)
    except OSError:
        pass


def fetch(url, timeout=DEFAULT_TIMEOUT, headers=None):
    """Plain HTTP GET, no disk. Returns response text or None."""
    if not HAVE_REQUESTS:
        return None
    try:
        h = {'User-Agent': USER_AGENT}
        if headers:
            h.update(headers)
        resp = requests.get(url, timeout=timeout, headers=h)
        if resp.status_code == 200 and resp.text:
            return resp.text
        logging.warning("[EASM] cache: %s -> HTTP %s", url, resp.status_code)
    except Exception as e:
        logging.warning("[EASM] cache: %s failed: %s", url, e)
    return None


def cached_get(url, name, ttl, sub='', timeout=DEFAULT_TIMEOUT, headers=None):
    """Cached HTTP GET: fresh cache -> stale-fallback on fetch failure -> None."""
    text, fresh = read(name, ttl, sub)
    if text is not None and fresh:
        return text
    fetched = fetch(url, timeout=timeout, headers=headers)
    if fetched is not None:
        write(name, fetched, sub)
        return fetched
    if text is not None:
        logging.warning("[EASM] cache: using stale %s", name)
    return text
