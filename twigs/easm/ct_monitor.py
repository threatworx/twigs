"""Incremental Certificate Transparency (CT) monitoring.

Between full EASM scans this catches certificates newly logged for the
monitored domain / its subdomains, and certificates issued for lookalike
domains. It is built for a CLI on a cron (hourly / daily), not a daemon:

  * A per-domain high-water mark (the newest CT entry timestamp already
    processed) is persisted under ~/.twigs/cache/easm/ct_monitor/. Each run
    only processes entries newer than that mark - "incremental".
  * On the first run for a domain, or on any run host with no persistent
    state, there is no mark, so it falls back to a fixed look-back window
    (--ct_monitor_window, default 26h) - "time-window fallback". A very
    stale mark is likewise clamped to a 30-day maximum look-back.
  * A cycle where every CT source fails does NOT advance the mark, so the
    next run simply covers the gap.

Primary source is crt.sh (indexed by domain, no auth, exposes
entry_timestamp). certspotter is queried additionally when
--certspotter_api_key / CERTSPOTTER_API_KEY is set.
"""
import os
import re
import json
import time
import calendar
import logging

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM,
                        ISSUE_TYPE_SUBDOMAIN, ISSUE_TYPE_TYPOSQUATTING,
                        HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, get_registered_domain
from . import _cache
from .subdomains import get_certspotter_api_key

try:
    import dnstwist
    HAVE_DNSTWIST = True
except ImportError:
    HAVE_DNSTWIST = False

_SUB = 'ct_monitor'
DEFAULT_WINDOW = 26 * 3600          # cold-start / no-cursor look-back
MAX_LOOKBACK = 30 * 86400          # clamp for a very stale cursor
CERTSPOTTER_MAX_PAGES = 25
SEEN_ID_CAP = 800                 # bounded per-domain dedup memory

_PERM_CACHE = {}


# --------------------------------------------------------------------------- #
#  state
# --------------------------------------------------------------------------- #
def _state_path(domain):
    slug = re.sub(r'[^a-z0-9._-]', '_', domain.lower()) or 'domain'
    return os.path.join(_cache.cache_dir(_SUB), slug + '.json')


def _load_state(domain):
    try:
        with open(_state_path(domain), 'r') as fh:
            s = json.load(fh)
            return s if isinstance(s, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(domain, state):
    try:
        with open(_state_path(domain), 'w') as fh:
            json.dump(state, fh)
    except OSError as e:
        logging.warning("[EASM] ct_monitor: could not persist state for [%s]: %s", domain, e)


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def _parse_ts(s):
    """CT / crt.sh timestamp string -> epoch seconds (UTC). None on failure."""
    if not s:
        return None
    s = re.sub(r'(Z|[+-]\d{2}:?\d{2})$', '', str(s).strip())
    try:
        return calendar.timegm(time.strptime(s.split('.')[0], '%Y-%m-%dT%H:%M:%S'))
    except (ValueError, TypeError):
        return None


def _clean_name(n):
    return (n or '').strip().lower().lstrip('*.').rstrip('.')


def _lev(a, b):
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _permutations(domain):
    if domain in _PERM_CACHE:
        return _PERM_CACHE[domain]
    perms = set()
    if HAVE_DNSTWIST:
        try:
            fz = dnstwist.Fuzzer(domain)
            fz.generate()
            perms = {p['domain'].lower() for p in fz.permutations() if p.get('fuzzer') != '*original'}
        except Exception as e:
            logging.debug("ct_monitor: dnstwist permutation generation failed: %s", e)
    _PERM_CACHE[domain] = perms
    return perms


def _is_lookalike(reg_dom, monitored_reg, perms):
    if not reg_dom or reg_dom == monitored_reg:
        return False
    if reg_dom in perms:
        return True
    m_label = monitored_reg.split('.')[0]
    r_label = reg_dom.split('.')[0]
    if r_label == m_label:                       # same name, different TLD
        return True
    return len(m_label) >= 4 and _lev(r_label, m_label) <= 1


# --------------------------------------------------------------------------- #
#  CT sources
# --------------------------------------------------------------------------- #
def _fetch_crtsh(domain):
    if not HAVE_REQUESTS:
        raise RuntimeError("requests not available")
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    r = requests.get(url, timeout=HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT})
    if r.status_code != 200:
        raise RuntimeError("HTTP %s" % r.status_code)
    out = []
    for e in r.json():
        ts = _parse_ts(e.get('entry_timestamp')) or _parse_ts(e.get('not_before'))
        names = set((e.get('name_value') or '').split('\n'))
        if e.get('common_name'):
            names.add(e['common_name'])
        out.append({
            'ts': ts,
            'names': {_clean_name(n) for n in names if n and n.strip()},
            'issuer': (e.get('issuer_name') or '').strip(),
            'id': 'crtsh:%s' % e.get('id'),
        })
    return out


def _fetch_certspotter(domain, api_key, after_id):
    if not HAVE_REQUESTS:
        raise RuntimeError("requests not available")
    base = "https://api.certspotter.com/v1/issuances"
    headers = {'User-Agent': USER_AGENT}
    if api_key:
        headers['Authorization'] = 'Bearer ' + api_key
    entries = []
    after = after_id
    last_id = after_id
    for _ in range(CERTSPOTTER_MAX_PAGES):
        params = {'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'}
        if after:
            params['after'] = after
        r = requests.get(base, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code == 429:
            raise RuntimeError("rate-limited (HTTP 429)")
        if r.status_code != 200:
            raise RuntimeError("HTTP %s" % r.status_code)
        batch = r.json()
        if isinstance(batch, dict):
            raise RuntimeError(batch.get('message') or batch.get('code') or 'error object')
        if not batch:
            break
        for iss in batch:
            iid = iss.get('id')
            if iid:
                last_id = iid
            issuer = iss.get('issuer')
            entries.append({
                'ts': _parse_ts(iss.get('not_before')),
                'names': {_clean_name(n) for n in (iss.get('dns_names') or []) if n and n.strip()},
                'issuer': (issuer.get('name') if isinstance(issuer, dict) else str(issuer or '')).strip(),
                'id': 'cs:%s' % iid,
            })
        after = last_id
        if len(batch) < 100:
            break
    return entries, last_id


# --------------------------------------------------------------------------- #
#  entry point
# --------------------------------------------------------------------------- #
def check_ct_monitor(domain, asset_id, args, known_subdomains=None):
    """Incremental CT check for `domain`. Returns (issues, new_in_scope_names).
    new_in_scope_names are subdomains first seen via CT this run - the caller
    should fold them into its own discovered set so they get assessed now."""
    if getattr(args, 'no_ct_monitor', False):
        return [], set()

    known = {n.lower() for n in (known_subdomains or set())}
    monitored_reg = get_registered_domain(domain) or domain
    now = time.time()
    window = getattr(args, 'ct_monitor_window', DEFAULT_WINDOW) or DEFAULT_WINDOW

    state = _load_state(domain)
    cursor = state.get('last_ts')
    cold = cursor is None
    since = (now - window) if cold else max(float(cursor), now - MAX_LOOKBACK)
    seen_ids = set(state.get('seen_ids', []))

    entries, ok, failed = [], [], []
    try:
        entries += _fetch_crtsh(domain)
        ok.append('crt.sh')
    except Exception as e:
        failed.append('crt.sh (%s)' % e)
        logging.warning("[EASM] ct_monitor: crt.sh unavailable for [%s]: %s", domain, e)

    cs_key = get_certspotter_api_key(args)
    if cs_key:
        try:
            cs_entries, cs_last = _fetch_certspotter(domain, cs_key, state.get('cs_last_id'))
            entries += cs_entries
            ok.append('certspotter')
            if cs_last:
                state['cs_last_id'] = cs_last
        except Exception as e:
            failed.append('certspotter (%s)' % e)
            logging.warning("[EASM] ct_monitor: certspotter unavailable for [%s]: %s", domain, e)

    if not ok:
        # degraded cycle - leave the cursor untouched so the next run catches up
        return [_new_issue(
            'ct-monitor-degraded', "CT monitoring degraded this cycle",
            "Continuous certificate-transparency monitoring for [%s] could not reach any CT source this run (%s). No new-certificate detection ran for this interval; it retries next run and the look-back window covers the gap."
            % (domain, '; '.join(failed)),
            RATING_INFO, asset_id, ISSUE_TYPE_SUBDOMAIN, object_id=domain,
            remediation="Usually transient (crt.sh rate-limiting/outage). Configure --certspotter_api_key to add a second, more reliable CT source.")], set()

    dated = [e for e in entries if e['ts']]
    max_ts = max((e['ts'] for e in dated), default=since)
    new = [e for e in dated if e['ts'] > since and e['id'] not in seen_ids]

    new_names = set()
    for e in new:
        new_names |= e['names']

    new_in_scope = sorted(
        n for n in new_names
        if (n == domain or n.endswith('.' + domain)) and n not in known and n != domain)

    # lookalike domains among the freshly-issued SANs
    perms = _permutations(monitored_reg)
    lookalikes = {}
    for e in new:
        for n in e['names']:
            if n == domain or n.endswith('.' + domain):
                continue
            reg = get_registered_domain(n)
            if _is_lookalike(reg, monitored_reg, perms):
                lookalikes.setdefault(reg, {'sans': set(), 'issuers': set(), 'ts': e['ts']})
                lookalikes[reg]['sans'].add(n)
                lookalikes[reg]['issuers'].add(e['issuer'])

    issues = []

    if new_in_scope:
        listing = "\n".join(new_in_scope[:200])
        issues.append(_new_issue(
            'ct-monitor-new-subdomains', "New subdomain(s) seen in Certificate Transparency logs",
            "%d hostname(s) under [%s] appeared in newly logged certificates since the last check (%s) and were not previously known to this assessment:\n%s"
            % (len(new_in_scope), domain,
               "first run - last %.0fh" % (window / 3600) if cold else time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(since)),
               listing),
            RATING_LOW, asset_id, ISSUE_TYPE_SUBDOMAIN, object_id=domain,
            object_meta=",".join(new_in_scope),
            remediation="Confirm each new subdomain is an authorized, intended deployment. An unexpected name with a valid certificate can indicate shadow IT, a compromised DNS/CDN account, or an attacker who obtained a cert for your domain - investigate promptly and revoke the certificate if it is not yours."))

    for reg, info in sorted(lookalikes.items()):
        sans = sorted(info['sans'])
        issues.append(_new_issue(
            'ct-monitor-lookalike-%s' % reg, "Certificate issued for a lookalike domain: %s" % reg,
            "A certificate covering [%s] (resembling [%s]) was newly logged in Certificate Transparency%s. A freshly issued certificate for a lookalike domain is a strong indicator that a phishing or brand-impersonation site is being stood up, since the operator is preparing to serve HTTPS. SAN(s): %s. Issuer(s): %s."
            % (reg, monitored_reg,
               " at " + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(info['ts'])) if info['ts'] else "",
               ", ".join(sans), ", ".join(sorted(i for i in info['issuers'] if i)) or "unknown"),
            RATING_MEDIUM, asset_id, ISSUE_TYPE_TYPOSQUATTING, object_id=reg,
            object_meta=",".join(sans),
            remediation="Check the domain's live content and MX/DNS now. If it impersonates your brand, report it to the certificate issuer (for revocation) and the hosting provider/registrar abuse contacts, file a UDRP/URS if warranted, and add it to your email/web block-lists. If it is a defensive registration you own, no action is required."))

    # heartbeat / status finding (stable id, updates in place each run)
    issues.append(_new_issue(
        'ct-monitor-status', "Certificate Transparency monitoring active",
        "Incremental CT monitoring for [%s] ran against %s. %s Processed %d certificate record(s), %d newer than the %s; %d new in-scope subdomain(s), %d lookalike-domain certificate(s) this cycle."
        % (domain, " + ".join(ok),
           ("Baseline established (first run); look-back window %.0fh." % (window / 3600)) if cold
           else ("Cursor: %s." % time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(float(cursor)))),
           len(entries), len(new),
           "look-back window" if cold else "cursor",
           len(new_in_scope), len(lookalikes)),
        RATING_INFO, asset_id, ISSUE_TYPE_SUBDOMAIN, object_id=domain,
        remediation="No action required. Runs each time EASM is invoked; schedule EASM hourly/daily for tighter detection latency." + (
            "" if not failed else " Note: %s failed this cycle." % "; ".join(failed))))

    # advance the cursor + dedup memory
    state['last_ts'] = max(max_ts, since)
    state['updated'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
    ordered_ids = [e['id'] for e in sorted(dated, key=lambda x: x['ts'])]
    merged = list(seen_ids) + [i for i in ordered_ids if i not in seen_ids]
    state['seen_ids'] = merged[-SEEN_ID_CAP:]
    _save_state(domain, state)

    logging.info("[EASM] ct_monitor: [%s] %s - %d record(s), %d new, %d new subdomain(s), %d lookalike(s)",
                 domain, "+".join(ok), len(entries), len(new), len(new_in_scope), len(lookalikes))
    return issues, set(new_in_scope)
