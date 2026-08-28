"""LeakRadar credential-leak lookups (optional, only runs if an API key is
supplied via --leakradar_api_key or the LEAKRADAR_API_KEY environment
variable). We deliberately only ever request the "light"/sampled domain
report - we never call LeakRadar's unlock endpoints, so no plaintext
credentials are ever fetched or stored in reported findings."""
import os
import logging

import requests

from .constants import RATING_INFO, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_CREDENTIAL_LEAK, HTTP_TIMEOUT, USER_AGENT
from .util import _new_issue

LEAKRADAR_BASE_URL = 'https://api.leakradar.io'

_LEAKRADAR_COUNT_FIELDS = [
    'employees_compromised', 'customers_compromised', 'third_parties_compromised',
    'total_compromised', 'total', 'leaks_total',
]


def get_leakradar_api_key(args):
    return getattr(args, 'leakradar_api_key', None) or os.environ.get('LEAKRADAR_API_KEY')


def check_leakradar(domain, asset_id, api_key):
    issues = []
    if not api_key:
        return issues
    try:
        resp = requests.get(
            LEAKRADAR_BASE_URL + '/search/domain/' + domain,
            params={'light': 'true'},
            headers={'Authorization': 'Bearer ' + api_key, 'Accept': 'application/json', 'User-Agent': USER_AGENT},
            timeout=HTTP_TIMEOUT * 2)
    except requests.exceptions.RequestException as e:
        logging.debug("LeakRadar lookup failed for [%s]: %s", domain, str(e))
        return issues

    if resp.status_code == 401:
        logging.warning("LeakRadar API key was rejected (401 Unauthorized) - skipping credential leak check")
        return issues
    if resp.status_code == 402:
        logging.warning("LeakRadar account does not have enough quota for domain search (402 Payment Required)")
        return issues
    if resp.status_code == 403:
        logging.warning("LeakRadar plan does not include domain search (403 Forbidden)")
        return issues
    if resp.status_code == 429:
        logging.warning("LeakRadar rate limit exceeded (429 Too Many Requests) - skipping credential leak check")
        return issues
    if resp.status_code != 200:
        logging.debug("LeakRadar domain search for [%s] returned HTTP [%s]", domain, resp.status_code)
        return issues

    try:
        report = resp.json()
    except ValueError:
        logging.debug("LeakRadar domain search for [%s] returned a non-JSON response", domain)
        return issues

    counts = {f: report[f] for f in _LEAKRADAR_COUNT_FIELDS if isinstance(report.get(f), int)}
    total_found = max(counts.values()) if counts else None

    if total_found is None:
        # Unknown/changed response schema - still surface whatever came back rather than staying silent.
        issues.append(_new_issue(
            'leakradar-report-%s' % domain, "LeakRadar credential leak report retrieved: %s" % domain,
            "A LeakRadar domain report was retrieved for [%s] but did not contain a recognized summary count field; raw keys returned: %s. This may indicate the LeakRadar API response schema has changed." % (domain, ', '.join(sorted(report.keys())) or 'none'),
            RATING_INFO, asset_id, ISSUE_TYPE_CREDENTIAL_LEAK, object_id=domain,
            remediation="Review the LeakRadar dashboard directly for [%s] to interpret this report." % domain))
        return issues

    if total_found == 0:
        issues.append(_new_issue(
            'leakradar-no-leaks-%s' % domain, "No credential leaks found via LeakRadar",
            "A LeakRadar domain search for [%s] found no compromised employee/customer/third-party credentials in its indexed stealer-log, combolist, and dark-web/forum data at scan time." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_CREDENTIAL_LEAK, object_id=domain,
            remediation="No action required. New leaks surface continuously, so consider periodic re-scanning or LeakRadar's continuous monitoring/alerting for this domain."))
        return issues

    if total_found < 10:
        rating = RATING_MEDIUM
    elif total_found < 100:
        rating = RATING_HIGH
    else:
        rating = RATING_CRITICAL

    breakdown = ', '.join('%s: %s' % (k.replace('_', ' '), v) for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
    issues.append(_new_issue(
        'leakradar-leaks-found-%s' % domain, "Credentials associated with this domain found in leaked data (%s)" % total_found,
        ("A LeakRadar domain search for [%s] found credentials associated with this domain in indexed stealer-log, combolist, and dark-web/forum data: %s. This is a sampled/summary count (no plaintext usernames or passwords were retrieved or stored by this scan) and typically indicates employees or customers have reused credentials that were captured by malware or exposed in a third-party breach.") % (domain, breakdown),
        rating, asset_id, ISSUE_TYPE_CREDENTIAL_LEAK, object_id=domain,
        remediation="Treat this as a credential-exposure signal, not confirmation of an active compromise. Use your LeakRadar account (or another breach-intelligence source) to review the specific affected accounts, force password resets for any confirmed matches, enforce MFA everywhere it isn't already required, and monitor for credential-stuffing/account-takeover attempts against exposed accounts."))
    return issues

