"""can-i-take-over-xyz fingerprint set for dangling-CNAME / subdomain-takeover
detection.

The canonical list is maintained by the community project
EdOverflow/can-i-take-over-xyz (CC BY-SA 4.0). It is fetched and cached for a
week; a bundled snapshot (below) is used whenever the upstream copy cannot be
reached, so the check works fully offline. Only entries marked "Vulnerable"
or "Edge case" are loaded.

Each loaded entry becomes a Fingerprint:

  service        provider name
  status         "Vulnerable" (high confidence) | "Edge case" (needs manual
                 confirmation - some precondition, e.g. the resource name
                 being currently unregistered, still applies)
  cnames         CNAME target substrings that point at this provider
  body_markers   strings/regexes that appear in the provider's
                 "this resource is unclaimed" HTTP response
  http_status    an HTTP status code that alone indicates the unclaimed state
                 (used when body_markers is empty)
  nxdomain       True  -> takeover is confirmed when the CNAME target itself
                 returns NXDOMAIN (the provider resource was deleted)
  documentation  reference URL(s), may be empty
"""
import re
import json
import logging
from collections import namedtuple

from . import _cache

UPSTREAM = 'https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json'
DEFAULT_TTL = 7 * 86400
_SUB = 'takeover'

Fingerprint = namedtuple('Fingerprint',
                         'service status cnames body_markers http_status nxdomain documentation')

# Body markers this generic are dropped from cname-less entries - they match
# ordinary 404 pages and would flood results with false positives.
_GENERIC_MARKERS = {
    '404', '404 not found', 'not found', 'page not found', 'error 404',
    '404 error', '404 - page not found', 'notfound', 'no such page',
}

# Snapshot of the Vulnerable / Edge-case entries from
# EdOverflow/can-i-take-over-xyz (used only when the upstream file is
# unreachable; refreshed automatically otherwise).
_BUNDLED = [
    {"service": 'AWS/Elastic Beanstalk', "status": 'Vulnerable', "cname": ['elasticbeanstalk.com'], "fingerprint": 'NXDOMAIN', "nxdomain": True},
    {"service": 'AWS/S3', "status": 'Vulnerable', "cname": ['s3.amazonaws.com'], "fingerprint": 'The specified bucket does not exist', "nxdomain": False},
    {"service": 'Agile CRM', "status": 'Vulnerable', "cname": ['agilecrm.com'], "fingerprint": 'Sorry, this page is no longer available.', "nxdomain": False},
    {"service": 'Airee.ru', "status": 'Vulnerable', "cname": ['airee.ru'], "fingerprint": 'Ошибка 402. Сервис Айри.рф не оплачен', "nxdomain": False},
    {"service": 'Anima', "status": 'Vulnerable', "cname": ['animaapp.io'], "fingerprint": 'The page you were looking for does not exist.', "nxdomain": False, "documentation": 'https://docs.animaapp.com/v1/launchpad/08-custom-domain.html'},
    {"service": 'Bitbucket', "status": 'Vulnerable', "cname": ['bitbucket.io'], "fingerprint": 'Repository not found', "nxdomain": False},
    {"service": 'Campaign Monitor', "status": 'Vulnerable', "cname": ['createsend.com'], "fingerprint": 'Trying to access your account?', "nxdomain": False, "documentation": 'https://help.campaignmonitor.com/custom-domain-names'},
    {"service": 'Canny', "status": 'Vulnerable', "cname": ['canny.io'], "fingerprint": 'Company Not Found` `There is no such company. Did you enter the right URL?', "nxdomain": False},
    {"service": 'Digital Ocean', "status": 'Vulnerable', "cname": [], "fingerprint": 'Domain uses DO name servers with no records in DO.', "nxdomain": False},
    {"service": 'Discourse', "status": 'Vulnerable', "cname": ['trydiscourse.com'], "fingerprint": 'NXDOMAIN', "nxdomain": True, "documentation": 'https://hackerone.com/reports/264494'},
    {"service": 'Frontify', "status": 'Edge case', "cname": ['frontify.com'], "fingerprint": '404 - Page Not Found` `Oops… looks like you got lost', "nxdomain": False},
    {"service": 'Gemfury', "status": 'Vulnerable', "cname": ['furyns.com'], "fingerprint": '404: This page could not be found.', "nxdomain": False, "documentation": 'https://khaledibnalwalid.wordpress.com/2020/06/25/gemfury-subdomain-takeover/'},
    {"service": 'Getresponse', "status": 'Vulnerable', "cname": [], "fingerprint": 'With GetResponse Landing Pages, lead generation has never been easier', "nxdomain": False},
    {"service": 'Ghost', "status": 'Vulnerable', "cname": ['ghost.io'], "fingerprint": 'Site unavailable\\.&#124;Failed to resolve DNS path for this host', "nxdomain": False},
    {"service": 'Github', "status": 'Edge case', "cname": ['github.io'], "fingerprint": "There isn't a GitHub Pages site here.", "nxdomain": False},
    {"service": 'HatenaBlog', "status": 'Vulnerable', "cname": ['hatenablog.com'], "fingerprint": '404 Blog is not found', "nxdomain": False},
    {"service": 'Help Juice', "status": 'Vulnerable', "cname": ['helpjuice.com'], "fingerprint": "We could not find what you're looking for.", "nxdomain": False, "documentation": 'https://help.helpjuice.com/en_US/using-your-custom-domain/how-to-set-up-a-custom-domain'},
    {"service": 'Help Scout', "status": 'Vulnerable', "cname": ['helpscoutdocs.com'], "fingerprint": 'No settings were found for this company:', "nxdomain": False, "documentation": 'https://docs.helpscout.net/article/42-setup-custom-domain'},
    {"service": 'Helprace', "status": 'Vulnerable', "cname": ['helprace.com'], "fingerprint": 'HTTP_STATUS=301', "nxdomain": False},
    {"service": 'Heroku', "status": 'Edge case', "cname": ['herokuapp.com', 'herokudns.com', 'herokussl.com'], "fingerprint": 'No such app', "nxdomain": False},
    {"service": 'Intercom', "status": 'Edge case', "cname": ['custom.intercom.help'], "fingerprint": "Uh oh. That page doesn't exist.", "nxdomain": False, "documentation": 'https://www.intercom.com/help/'},
    {"service": 'JetBrains', "status": 'Vulnerable', "cname": ['youtrack.cloud', 'myjetbrains.com'], "fingerprint": 'is not a registered InCloud YouTrack', "nxdomain": False, "documentation": 'https://www.jetbrains.com/help/youtrack/incloud/Domain-Settings.html'},
    {"service": 'Landingi', "status": 'Edge case', "cname": ['cname.landingi.com'], "fingerprint": 'It looks like you’re lost...', "nxdomain": False},
    {"service": 'LaunchRock', "status": 'Vulnerable', "cname": ['launchrock.com'], "fingerprint": 'HTTP_STATUS=500', "nxdomain": False},
    {"service": 'Mashery', "status": 'Edge case', "cname": ['mashery.com'], "fingerprint": 'Unrecognized domain', "nxdomain": False, "documentation": 'https://hackerone.com/reports/275714'},
    {"service": 'Microsoft Azure', "status": 'Vulnerable', "cname": ['cloudapp.net', 'cloudapp.azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'trafficmanager.net', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net', 'azurecontainer.io', 'database.windows.net', 'azuredatalakestore.net', 'search.windows.net', 'azurecr.io', 'redis.cache.windows.net', 'servicebus.windows.net', 'visualstudio.com', 'azurefd.net', 'azurestaticapps.net'], "fingerprint": 'NXDOMAIN', "nxdomain": True},
    {"service": 'Netlify', "status": 'Edge case', "cname": ['netlify.app', 'netlify.com'], "fingerprint": 'Not Found - Request ID:', "nxdomain": False},
    {"service": 'Ngrok', "status": 'Vulnerable', "cname": ['ngrok.io'], "fingerprint": 'Tunnel .*.ngrok.io not found', "nxdomain": False, "documentation": 'https://ngrok.com/docs#http-custom-domains'},
    {"service": 'Pantheon', "status": 'Vulnerable', "cname": ['pantheonsite.io'], "fingerprint": '404 error unknown site!', "nxdomain": False, "documentation": 'https://pantheon.io/docs/guides/domains/custom-domains'},
    {"service": 'Pingdom', "status": 'Vulnerable', "cname": ['stats.pingdom.com'], "fingerprint": "Sorry, couldn't find the status page", "nxdomain": False, "documentation": 'https://help.pingdom.com/hc/en-us/articles/205386171-Public-Status-Page'},
    {"service": 'Readme.io', "status": 'Vulnerable', "cname": ['readme.io'], "fingerprint": 'The creators of this project are still working on making everything perfect!', "nxdomain": False},
    {"service": 'Readthedocs', "status": 'Vulnerable', "cname": ['readthedocs.io'], "fingerprint": 'The link you have followed or the URL that you entered does not exist.', "nxdomain": False},
    {"service": 'Shopify', "status": 'Edge case', "cname": ['myshopify.com'], "fingerprint": 'Sorry, this shop is currently unavailable.', "nxdomain": False, "documentation": 'https://help.shopify.com/en/manual/domains'},
    {"service": 'Short.io', "status": 'Vulnerable', "cname": ['cname.short.io', 'secure.short.cm'], "fingerprint": 'Link does not exist', "nxdomain": False},
    {"service": 'SmartJobBoard', "status": 'Vulnerable', "cname": ['52.16.160.97'], "fingerprint": 'This job board website is either expired or its domain name is invalid.', "nxdomain": False, "documentation": 'https://help.smartjobboard.com/en/articles/1269655-connecting-a-custom-domain-name'},
    {"service": 'Smartling', "status": 'Edge case', "cname": ['smartling.com'], "fingerprint": 'Domain is not configured', "nxdomain": False},
    {"service": 'Strikingly', "status": 'Vulnerable', "cname": ['s.strikinglydns.com'], "fingerprint": 'PAGE NOT FOUND.', "nxdomain": False, "documentation": 'https://medium.com/@sherif0x00/takeover-subdomains-pointing-to-strikingly-5e67df80cdfd'},
    {"service": 'Surge.sh', "status": 'Vulnerable', "cname": ['surge.sh'], "fingerprint": 'project not found', "nxdomain": False, "documentation": 'https://surge.sh/help/adding-a-custom-domain'},
    {"service": 'SurveySparrow', "status": 'Vulnerable', "cname": ['surveysparrow.com'], "fingerprint": 'Account not found.', "nxdomain": False, "documentation": 'https://help.surveysparrow.com/custom-domain'},
    {"service": 'Tilda', "status": 'Edge case', "cname": ['tilda.ws'], "fingerprint": 'Please renew your subscription', "nxdomain": False},
    {"service": 'Tumblr', "status": 'Edge case', "cname": ['domains.tumblr.com'], "fingerprint": "Whatever you were looking for doesn't currently exist at this address", "nxdomain": False, "documentation": 'https://www.tumblr.com/docs/en/custom_domains'},
    {"service": 'Uberflip', "status": 'Vulnerable', "cname": ['read.uberflip.com'], "fingerprint": "The URL you've accessed does not provide a hub.", "nxdomain": False, "documentation": 'https://help.uberflip.com/hc/en-us/articles/360018786372-Custom-Domain-Set-up-Your-Hub-on-a-Subdomain'},
    {"service": 'Uptimerobot', "status": 'Vulnerable', "cname": ['stats.uptimerobot.com'], "fingerprint": 'page not found', "nxdomain": False, "documentation": 'https://exploit.linuxsec.org/uptimerobot-com-custom-domain-subdomain-takeover/'},
    {"service": 'Vercel', "status": 'Edge case', "cname": ['cname.vercel-dns.com', 'vercel.app'], "fingerprint": 'DEPLOYMENT_NOT_FOUND.', "nxdomain": False, "documentation": 'https://vercel.com/docs/concepts/projects/domains/add-a-domain'},
    {"service": 'Webflow', "status": 'Edge case', "cname": ['proxy-ssl.webflow.com', 'proxy.webflow.com'], "fingerprint": "The page you are looking for doesn't exist or has been moved.", "nxdomain": False, "documentation": 'https://forum.webflow.com/t/hosting-a-subdomain-on-webflow/59201'},
    {"service": 'Wix', "status": 'Edge case', "cname": ['wixdns.net'], "fingerprint": "Looks Like This Domain Isn't Connected To A Website Yet!", "nxdomain": False},
    {"service": 'Wordpress', "status": 'Vulnerable', "cname": ['wordpress.com'], "fingerprint": 'Do you want to register .*.wordpress.com?', "nxdomain": False},
    {"service": 'Worksites', "status": 'Vulnerable', "cname": ['worksites.net', '69.164.223.206'], "fingerprint": 'Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.', "nxdomain": False},
]

_CACHE = None


def _norm_cname(c):
    c = (c or '').strip().lower()
    for pre in ('https://', 'http://'):
        if c.startswith(pre):
            c = c[len(pre):]
    return c.strip('/').rstrip('.')


def _parse_entry(e):
    cnames = tuple(x for x in (_norm_cname(c) for c in (e.get('cname') or [])) if x)
    fp_raw = (e.get('fingerprint') or '').strip()
    nxdomain = bool(e.get('nxdomain')) or fp_raw.upper() == 'NXDOMAIN'

    http_status = None
    markers = []
    if fp_raw and fp_raw.upper() != 'NXDOMAIN':
        m = re.match(r'HTTP_STATUS=(\d{3})\s*$', fp_raw)
        if m:
            http_status = int(m.group(1))
        else:
            markers = [p.strip() for p in fp_raw.split('`') if p.strip()]

    # Drop generic markers from cname-less entries (FP magnets on ordinary 404s).
    if not cnames:
        markers = [mk for mk in markers if mk.lower() not in _GENERIC_MARKERS and len(mk) >= 10]

    if not (cnames or markers or http_status is not None or nxdomain):
        return None
    return Fingerprint(
        service=e.get('service') or 'unknown',
        status=(e.get('status') or 'Unknown').strip(),
        cnames=cnames,
        body_markers=tuple(markers),
        http_status=http_status,
        nxdomain=nxdomain,
        documentation=(e.get('documentation') or '').strip(),
    )


def load(ttl=DEFAULT_TTL):
    """Full Fingerprint list (memoised). Upstream if reachable, else bundled."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    data, src = None, 'bundled'
    raw = _cache.cached_get(UPSTREAM, 'canitakeover_fingerprints.json', ttl, sub=_SUB)
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list) and parsed:
                data, src = parsed, 'upstream'
        except ValueError:
            pass
    if data is None:
        data = _BUNDLED

    out = []
    for e in data:
        if not isinstance(e, dict):
            continue
        status = str(e.get('status', '')).lower()
        keep = (src == 'bundled') or e.get('vulnerable') is True or status.startswith('edge') or 'vulnerable' in status
        if not keep:
            continue
        try:
            fp = _parse_entry(e)
        except Exception:
            fp = None
        if fp is not None:
            out.append(fp)

    _CACHE = out
    logging.info("[EASM] takeover fingerprints loaded: %d entries (%s)", len(out), src)
    return out


def cname_candidates(entries, cname_target, resolved_ids=()):
    """Entries whose CNAME pattern matches the given target (or a resolved
    IP / intermediate name)."""
    hay = [h for h in ([cname_target] + list(resolved_ids)) if h]
    hits = []
    for fp in entries:
        for pat in fp.cnames:
            if any(h == pat or h.endswith('.' + pat) or h.endswith(pat) or pat in h for h in hay):
                hits.append(fp)
                break
    return hits


def fingerprint_only_entries(entries):
    """Entries with no CNAME pattern - matched purely on HTTP response."""
    return [fp for fp in entries if not fp.cnames]


def marker_hit(fp, status_code, body):
    """Return a short description of why `fp` matched, or None."""
    if fp.http_status is not None and status_code == fp.http_status and not fp.body_markers:
        return 'HTTP %d' % status_code
    low = body.lower()
    for mk in fp.body_markers:
        try:
            if re.search(mk, body, re.I):
                return '"%s"' % mk[:100]
        except re.error:
            if mk.lower() in low:
                return '"%s"' % mk[:100]
    return None
