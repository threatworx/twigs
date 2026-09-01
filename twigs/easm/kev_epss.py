"""CISA KEV + FIRST.org EPSS enrichment for CVE-bearing EASM findings.

Raises the rating of any finding that references a CVE which is either on the
CISA Known Exploited Vulnerabilities (KEV) catalog or has a high EPSS
exploitation-probability score, then re-orders each asset's config_issues so
the list is risk-ranked rather than a flat pile. Also emits one
"exploitation-prioritized" summary finding per affected asset.

Purely additive: a rating is only ever raised, never lowered. If neither
feed is reachable it degrades to a no-op (cached copies used when present).
"""
import re
import json
import logging
from collections import namedtuple

from . import _cache
from .constants import (RATING_INFO, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL,
                        ISSUE_TYPE_WEB_APPLICATION)
from .util import _new_issue

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_API = 'https://api.first.org/data/v1/epss'
DEFAULT_TTL = 86400
_SUB = 'kev_epss'

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)

EPSS_HIGH = 0.50     # >= this EPSS  -> at least RATING_HIGH
EPSS_MEDIUM = 0.10   # >= this EPSS  -> at least RATING_MEDIUM
EPSS_BATCH = 100     # FIRST.org accepts up to 100 CVEs per query

Enrichment = namedtuple('Enrichment',
                        'cve kev kev_ransomware kev_added kev_due epss epss_pct')

_KEV = None


def _load_kev(ttl):
    global _KEV
    if _KEV is not None:
        return _KEV
    _KEV = {}
    raw = _cache.cached_get(KEV_URL, 'cisa_kev.json', ttl, sub=_SUB)
    if raw:
        try:
            for v in json.loads(raw).get('vulnerabilities', []):
                _KEV[v['cveID'].upper()] = v
        except Exception as e:
            logging.warning("[EASM] kev_epss: KEV parse failed: %s", e)
    logging.info("[EASM] kev_epss: CISA KEV entries loaded: %d", len(_KEV))
    return _KEV


def _load_epss(cves, ttl):
    """{cve: (epss, percentile)}. Per-CVE disk cache; batched API for misses.
    A CVE the API confirms it has no score for is cached as 0.0; a CVE we
    simply couldn't fetch (API down) is left uncached so a later run retries."""
    out = {}
    misses = []
    for cve in cves:
        txt, fresh = _cache.read('epss_%s.txt' % cve, ttl, sub=_SUB)
        if txt is not None and fresh:
            try:
                s, p = txt.strip().split(',')
                out[cve] = (float(s), float(p))
                continue
            except ValueError:
                pass
        misses.append(cve)

    for i in range(0, len(misses), EPSS_BATCH):
        batch = misses[i:i + EPSS_BATCH]
        raw = _cache.fetch(EPSS_API + '?cve=' + ','.join(batch))
        if raw is None:
            continue  # API unreachable - retry next run, don't poison the cache
        got = set()
        try:
            for r in json.loads(raw).get('data', []):
                cve = r['cve'].upper()
                s, p = float(r['epss']), float(r['percentile'])
                out[cve] = (s, p)
                got.add(cve)
                _cache.write('epss_%s.txt' % cve, '%s,%s' % (s, p), sub=_SUB)
        except Exception as e:
            logging.warning("[EASM] kev_epss: EPSS parse failed: %s", e)
            continue
        for cve in batch:
            if cve not in got:            # API responded, genuinely no score
                _cache.write('epss_%s.txt' % cve, '0.0,0.0', sub=_SUB)
    return out


def enrich(cve_ids, ttl=DEFAULT_TTL):
    """{CVE -> Enrichment} for every CVE given (KEV + EPSS combined)."""
    cves = sorted({c.upper() for c in cve_ids if c})
    if not cves:
        return {}
    kev = _load_kev(ttl)
    epss = _load_epss(cves, ttl)
    result = {}
    for cve in cves:
        k = kev.get(cve)
        s, p = epss.get(cve, (None, None))
        result[cve] = Enrichment(
            cve=cve,
            kev=k is not None,
            kev_ransomware=bool(k and str(k.get('knownRansomwareCampaignUse', '')).lower() == 'known'),
            kev_added=k.get('dateAdded') if k else None,
            kev_due=k.get('dueDate') if k else None,
            epss=s, epss_pct=p)
    return result


def _rank(rating, e):
    r = int(rating)
    if e.kev_ransomware:
        r = max(r, int(RATING_CRITICAL))
    elif e.kev:
        r = max(r, int(RATING_HIGH))
    if e.epss is not None:
        if e.epss >= EPSS_HIGH:
            r = max(r, int(RATING_HIGH))
        elif e.epss >= EPSS_MEDIUM:
            r = max(r, int(RATING_MEDIUM))
    return str(r)


def _significant(e):
    return e.kev or (e.epss or 0.0) >= EPSS_MEDIUM


def _sentence(enrs):
    bits = []
    kevs = [e for e in enrs if e.kev]
    if kevs:
        e = kevs[0]
        s = "on the CISA KEV catalog (added %s" % e.kev_added
        if e.kev_due:
            s += ", federal remediation due %s" % e.kev_due
        s += ")"
        if any(x.kev_ransomware for x in kevs):
            s += "; linked to known ransomware campaigns"
        bits.append(s)
    scored = [e for e in enrs if e.epss]
    if scored:
        top = max(scored, key=lambda e: e.epss)
        bits.append("EPSS %.3f (%.0fth percentile) for %s - probability of exploitation in the next 30 days"
                    % (top.epss, (top.epss_pct or 0) * 100, top.cve))
    return ("Exploitation status: " + "; ".join(bits) + ".") if bits else None


def _issue_cves(issue):
    cves = {c.upper() for c in (issue.get('cve') or [])}
    if not cves:
        cves = {m.upper() for m in CVE_RE.findall(issue.get('details', '') or '')}
    return cves


def _summary_finding(asset, enr_map, kev_cves, hi_epss):
    lines = []
    for cve in sorted(kev_cves | hi_epss,
                      key=lambda c: (-(enr_map[c].epss or 0), c)):
        e = enr_map[cve]
        marks = []
        if e.kev:
            marks.append('KEV')
        if e.kev_ransomware:
            marks.append('ransomware')
        if e.epss is not None:
            marks.append('EPSS %.3f' % e.epss)
        lines.append("%s - %s" % (cve, ', '.join(marks)))
    detail = ("%d CVE(s) referenced by findings on this asset are exploitation-prioritized: "
              "%d on the CISA KEV catalog, %d with EPSS >= %.2f. Affected findings have been "
              "re-rated and sorted to the top of this asset's issue list.\n%s"
              % (len(kev_cves | hi_epss), len(kev_cves), len(hi_epss - kev_cves),
                 EPSS_HIGH, '\n'.join(lines)))
    asset['config_issues'].insert(0, _new_issue(
        'exploitation-priority-summary', "Exploitation-prioritized exposure summary",
        detail, RATING_HIGH if kev_cves else RATING_MEDIUM,
        asset['id'], ISSUE_TYPE_WEB_APPLICATION, object_id=asset['id'],
        object_meta=','.join(sorted(kev_cves | hi_epss)),
        remediation="Remediate the KEV-listed CVEs first (they are confirmed exploited in the wild), "
                    "then those with the highest EPSS scores. For KEV items, CISA publishes a fixed "
                    "remediation due date shown above."))


def apply(assets, ttl=DEFAULT_TTL):
    """Enrich + risk-rank every asset's config_issues in place."""
    issue_cves = {}
    all_cves = set()
    for a in assets:
        for iss in a.get('config_issues', []):
            c = _issue_cves(iss)
            issue_cves[id(iss)] = c
            all_cves |= c
    if not all_cves:
        return
    enr_map = enrich(all_cves, ttl)

    total_bumped = 0
    for a in assets:
        asset_kev, asset_hi = set(), set()
        ranked = []
        for iss in a.get('config_issues', []):
            enrs = [enr_map[c] for c in issue_cves[id(iss)]
                    if c in enr_map and _significant(enr_map[c])]
            kev = any(e.kev for e in enrs)
            epss = max((e.epss or 0.0 for e in enrs), default=0.0)
            if enrs:
                before = iss['rating']
                for e in enrs:
                    iss['rating'] = _rank(iss['rating'], e)
                if iss['rating'] != before:
                    total_bumped += 1
                s = _sentence(enrs)
                if s and s not in iss['details']:
                    iss['details'] = iss['details'].rstrip() + ' ' + s
                asset_kev |= {e.cve for e in enrs if e.kev}
                asset_hi |= {e.cve for e in enrs if (e.epss or 0.0) >= EPSS_HIGH}
            ranked.append((iss, kev, epss))

        ranked.sort(key=lambda t: (-int(t[0]['rating']), not t[1], -t[2]))
        a['config_issues'] = [t[0] for t in ranked]

        if asset_kev or asset_hi:
            _summary_finding(a, enr_map, asset_kev, asset_hi)

    logging.info("[EASM] kev_epss: %d CVE(s) checked, %d finding(s) re-rated",
                 len(all_cves), total_bumped)
