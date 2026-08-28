"""ransomware.live victim-listing lookups (optional, only runs if a Pro API
key is supplied via --ransomware_live_api_key or the
RANSOMWARE_LIVE_API_KEY environment variable). Uses the authenticated Pro
API (api-pro.ransomware.live), not the free/anonymous v2 API, since the
latter's terms restrict it to personal, non-commercial use. Runs once
against the registered domain only (not per-subdomain): victim listings are
keyed by organization/website, and /victims/search matches `q` as a
substring of that website field, so a subdomain query would not match a
listing recorded under the apex domain."""
import os
import logging

import requests

from .constants import RATING_INFO, RATING_CRITICAL, ISSUE_TYPE_RANSOMWARE, HTTP_TIMEOUT, USER_AGENT
from .util import _new_issue

RANSOMWARE_LIVE_BASE_URL = 'https://api-pro.ransomware.live'


def get_ransomware_live_api_key(args):
    return getattr(args, 'ransomware_live_api_key', None) or os.environ.get('RANSOMWARE_LIVE_API_KEY')


def check_ransomware_live(domain, asset_id, api_key):
    issues = []
    if not api_key:
        return issues
    try:
        resp = requests.get(
            RANSOMWARE_LIVE_BASE_URL + '/victims/search',
            params={'q': domain},
            headers={'X-API-KEY': api_key, 'Accept': 'application/json', 'User-Agent': USER_AGENT},
            timeout=HTTP_TIMEOUT * 2)
    except requests.exceptions.RequestException as e:
        logging.debug("ransomware.live lookup failed for [%s]: %s", domain, str(e))
        return issues

    if resp.status_code in (401, 403):
        logging.warning("ransomware.live API key was rejected (HTTP %s) - skipping ransomware victim-listing check", resp.status_code)
        return issues
    if resp.status_code == 429:
        logging.warning("ransomware.live rate limit exceeded (429) - skipping ransomware victim-listing check")
        return issues
    if resp.status_code != 200:
        logging.debug("ransomware.live search for [%s] returned HTTP [%s]", domain, resp.status_code)
        return issues

    try:
        data = resp.json()
    except ValueError:
        logging.debug("ransomware.live search for [%s] returned a non-JSON response", domain)
        return issues

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = None
        for key in ('victims', 'results', 'data', 'items'):
            if isinstance(data.get(key), list):
                records = data[key]
                break
        if records is None:
            records = [data] if data.get('victim') else []
    else:
        records = []

    # q matches victim name OR website as a substring, so filter to records
    # whose website actually references our domain to avoid reporting an
    # unrelated victim whose name merely happens to contain the keyword.
    matched = [r for r in records if isinstance(r, dict) and domain.lower() in (r.get('website') or '').lower()]

    if not matched:
        issues.append(_new_issue(
            'ransomware-live-none-found', "No ransomware victim listing found",
            "A ransomware.live search for [%s] found no matching entries on known ransomware-group leak/extortion sites." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_RANSOMWARE, object_id=domain,
            remediation="No action required. Ransomware groups continuously post new victims, so consider periodic re-scanning or ransomware.live's own notification feature for this domain."))
        return issues

    for r in matched:
        victim = r.get('victim') or domain
        group = r.get('group') or 'unknown group'
        attackdate = r.get('attackdate') or 'unknown date'
        activity = r.get('activity')
        permalink = r.get('permalink')
        press = r.get('press')
        detail_bits = ["Domain [%s] matches a victim listing posted by the [%s] ransomware group (attack/publication date: %s)." % (domain, group, attackdate)]
        if activity:
            detail_bits.append("Sector: %s." % activity)
        if permalink:
            detail_bits.append("Details: %s" % permalink)
        if press:
            detail_bits.append("Press coverage: %s" % press)
        issues.append(_new_issue(
            'ransomware-live-victim-%s' % (r.get('id') or (str(group) + str(attackdate))),
            "Domain listed as a ransomware victim: %s (%s)" % (victim, group),
            ' '.join(detail_bits),
            RATING_CRITICAL, asset_id, ISSUE_TYPE_RANSOMWARE, object_id=domain,
            remediation="Treat this as a strong indicator of a confirmed or claimed compromise. Activate incident response, verify with internal security/legal teams, assess what data may have been exfiltrated (leak sites often post samples or full dumps), rotate any credentials that may have been exposed, and notify affected stakeholders/regulators as required. If this listing is inaccurate or your organization was not actually affected, request removal/correction directly with ransomware.live."))
    return issues

