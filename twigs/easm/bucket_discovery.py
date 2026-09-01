"""Cloud object-storage discovery for a domain: generate candidate bucket /
container names from the organisation's label and its discovered subdomain
labels, then probe AWS S3, Google Cloud Storage and Azure Blob for
existence and public listability.

  200 + XML listing  -> public, listable         (HIGH)
  403 / AccessDenied -> bucket exists, private    (LOW - namespace claimed,
                                                   recon value, takeover risk
                                                   if later deleted)
  404 / NoSuchBucket -> nothing there
"""
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .constants import (RATING_INFO, RATING_LOW, RATING_HIGH,
                        ISSUE_TYPE_EXPOSED_PANEL, HTTP_TIMEOUT, USER_AGENT)
from .util import _new_issue, get_registered_domain

MAX_CANDIDATES = 160
WORKERS = 30

_SUFFIXES = [
    '', '-assets', '-static', '-media', '-images', '-img', '-uploads', '-files',
    '-public', '-private', '-data', '-db', '-database', '-backup', '-backups',
    '-bak', '-dump', '-dumps', '-logs', '-log', '-archive', '-cdn', '-www',
    '-web', '-app', '-api', '-prod', '-production', '-stage', '-staging',
    '-dev', '-development', '-test', '-qa', '-internal', '-secret', '-secrets',
    '-config', '-terraform', '-tf', '-tfstate', '-state', '-artifacts',
    '-build', '-releases', '-download', '-downloads', '-share', '-tmp',
]


def _candidates(domain, extra_labels):
    reg = get_registered_domain(domain) or domain
    sld = reg.split('.')[0].lower()
    dashed = reg.replace('.', '-').lower()
    dotless = reg.replace('.', '').lower()
    bases = {sld, dashed, dotless}
    for lbl in (extra_labels or []):
        lbl = lbl.lower().strip('.')
        if lbl and lbl != sld and re.match(r'^[a-z0-9-]{2,40}$', lbl):
            # only org-prefixed - a bare "api"/"app" bucket name is not ours
            bases.add('%s-%s' % (sld, lbl))
            bases.add('%s-%s' % (lbl, sld))
    out = []
    for b in bases:
        for suf in _SUFFIXES:
            name = (b + suf).strip('-')
            if 3 <= len(name) <= 63 and re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', name):
                out.append(name)
    # de-dupe, keep order, cap
    seen, uniq = set(), []
    for n in out:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq[:MAX_CANDIDATES]


def _classify(resp):
    if resp is None:
        return None
    body = (resp.text or '')[:2000]
    if resp.status_code == 200 and ('<ListBucketResult' in body or '<EnumerationResults' in body
                                    or '<?xml' in body and ('<Contents>' in body or '<Blob>' in body)):
        return 'listable'
    if resp.status_code == 200 and body.strip().startswith('<?xml') and 'Error' not in body:
        return 'listable'
    if resp.status_code in (401, 403):
        return 'private'
    if resp.status_code == 400 and 'InvalidBucketName' not in body:
        return 'private'      # Azure: account exists, bad request shape
    return None


def _probe(name):
    hits = []
    checks = [
        ('AWS S3',      'https://%s.s3.amazonaws.com/' % name),
        ('Google GCS',  'https://storage.googleapis.com/%s/' % name),
        ('Azure Blob',  'https://%s.blob.core.windows.net/?comp=list' % name),
    ]
    for provider, url in checks:
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, headers={'User-Agent': USER_AGENT},
                             allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        state = _classify(r)
        if state:
            hits.append((provider, name, url, state))
    return hits


def check_bucket_discovery(domain, asset_id, args, extra_labels=None):
    if getattr(args, 'no_bucket_discovery', False) or not HAVE_REQUESTS:
        return []
    cands = _candidates(domain, extra_labels)
    if not cands:
        return []
    logging.info("[EASM] bucket_discovery: probing %d candidate name(s) for [%s]", len(cands), domain)

    listable, private = [], []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(_probe, n) for n in cands]
        for fut in as_completed(futs):
            for provider, name, url, state in fut.result():
                (listable if state == 'listable' else private).append('%s  %s  (%s)' % (provider, name, url))

    issues = []
    if listable:
        issues.append(_new_issue(
            'bucket-public-listable', "Publicly listable cloud storage bucket(s)",
            "Cloud object-storage bucket(s) matching this organisation's naming are publicly listable (contents enumerable without credentials):\n%s"
            % '\n'.join(sorted(listable)),
            RATING_HIGH, asset_id, ISSUE_TYPE_EXPOSED_PANEL, object_id=domain,
            object_meta=','.join(x.split('  ')[1] for x in listable),
            remediation="Confirm ownership. If yours, disable anonymous list/read access immediately (bucket policy / ACL / 'block public access' / container access level = private) and review what was exposed. If not yours, it may be brand-squatting worth reporting."))
    if private:
        issues.append(_new_issue(
            'bucket-exists-private', "Cloud storage bucket(s) exist under this organisation's naming",
            "Bucket(s) matching this organisation's naming exist but deny anonymous access. Listed for inventory / attack-surface completeness - a bucket that is later deleted leaves a claimable name (storage-bucket takeover):\n%s"
            % '\n'.join(sorted(private)[:100]),
            RATING_LOW, asset_id, ISSUE_TYPE_EXPOSED_PANEL, object_id=domain,
            object_meta=','.join(x.split('  ')[1] for x in private[:100]),
            remediation="Confirm which buckets are yours and keep the names claimed for as long as any resource references them. Ensure none inadvertently allow public read on individual objects even while listing is denied."))
    if not issues:
        logging.info("[EASM] bucket_discovery: no buckets found for [%s]", domain)
    return issues
