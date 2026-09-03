"""Typosquatting checks: lookalike domain permutations (dnstwist), each
checked for *registration status* - not just whether it resolves, but whether
it is a live registration at all (A/AAAA, MX, or NS/SOA delegation) - and for
MX records, which mark a lookalike that is set up to send or receive email as
the brand (business-email-compromise / phishing infrastructure). A bounded
WHOIS lookup enriches the most interesting hits.

Deliberately does NOT fetch live content or take screenshots of each
lookalike - that belongs to the screenshot pipeline (gap-list item 9) and can
be layered on later. Ongoing CT-log watching for freshly issued
lookalike-domain certificates is handled separately by ct_monitor.py.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dnstwist
    HAVE_DNSTWIST = True
except ImportError:
    HAVE_DNSTWIST = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH,
                        ISSUE_TYPE_TYPOSQUATTING)
from .util import (HAVE_DNSPYTHON, resolve_ips, _get_dns_resolver,
                   _resolve_record, _new_issue)
from .whois_lookup import check_whois

# Ceiling on how many permutations get the (A + MX + NS/SOA) registration
# probe - dnstwist can emit several thousand for a short domain. --typosquat_limit
# still applies first; this is a second, DNS-specific bound.
DEFAULT_DNS_LIMIT = 1000


def _record_texts(resolver, name, rtype):
    ans = _resolve_record(resolver, name, rtype)
    if not ans:
        return []
    out = []
    for rr in ans:
        try:
            if rtype == 'MX':
                out.append(str(rr.exchange).rstrip('.').lower())
            elif rtype == 'NS':
                out.append(str(rr.target).rstrip('.').lower())
            else:
                out.append(str(rr).strip())
        except Exception:
            continue
    return [x for x in out if x]


def _classify(perm, resolver):
    """Returns a dict for a permutation that is a live registration, else
    None. A domain counts as registered if it has an address, an MX, or is
    delegated (NS / SOA present) even with no address."""
    candidate = perm['domain']
    ips = resolve_ips(candidate)
    mx = _record_texts(resolver, candidate, 'MX')
    ns = []
    if not ips:
        ns = _record_texts(resolver, candidate, 'NS')
        if not ns and _resolve_record(resolver, candidate, 'SOA'):
            ns = ['(SOA record present)']
    if not ips and not mx and not ns:
        return None
    return {'perm': perm, 'candidate': candidate, 'ips': ips, 'mx': mx, 'ns': ns}


def check_typosquatting(domain, asset_id, args):
    issues = []
    if not HAVE_DNSTWIST or not HAVE_DNSPYTHON:
        return issues
    try:
        fuzzer = dnstwist.Fuzzer(domain)
        fuzzer.generate()
        permutations = [p for p in fuzzer.permutations() if p['fuzzer'] != '*original']
    except Exception as e:
        logging.debug("dnstwist permutation generation failed: %s", str(e))
        return issues

    limit = getattr(args, 'typosquat_limit', 0) or 0
    if limit and len(permutations) > limit:
        permutations = permutations[:limit]

    dns_limit = getattr(args, 'typosquat_dns_limit', DEFAULT_DNS_LIMIT) or 0
    truncated = bool(dns_limit and len(permutations) > dns_limit)
    to_check = permutations[:dns_limit] if truncated else permutations

    resolver = _get_dns_resolver()
    workers = getattr(args, 'typosquat_workers', 30)
    logging.info("Checking [%s] domain permutation(s) of [%s] for registration status (A/MX/NS)",
                 len(to_check), domain)

    classified = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_classify, perm, resolver) for perm in to_check]
        for future in as_completed(futures):
            try:
                rec = future.result()
            except Exception:
                rec = None
            if rec:
                classified.append(rec)

    classified.sort(key=lambda r: (0 if r['mx'] else 1 if r['ips'] else 2, r['candidate']))

    for rec in classified:
        candidate, perm = rec['candidate'], rec['perm']
        ips, mx, ns = rec['ips'], rec['mx'], rec['ns']

        bits = []
        bits.append("resolves to %s" % ', '.join(ips[:5]) if ips
                    else "does not currently resolve to an address")
        if mx:
            bits.append("publishes MX record(s) (%s), so it is configured to send or receive email"
                        % ', '.join(sorted(set(mx))[:5]))
        if ns and not ips:
            bits.append("is delegated to nameserver(s) (%s), so it is a live registration"
                        % ', '.join(ns[:4]))

        if mx:
            rating, status = RATING_HIGH, "registered and email-capable"
        elif ips:
            rating, status = RATING_MEDIUM, "registered and serving"
        else:
            rating, status = RATING_LOW, "registered but dormant"

        meta = ','.join(t for t in ('mx' if mx else '', 'resolves' if ips else '', 'registered') if t)
        detail = ("Domain [%s] (dnstwist variation type: %s) closely resembles [%s] and %s. This lookalike is %s - it could be a defensive registration you own, an unrelated third party who happens to hold a similar name, or a lookalike being staged or used for phishing, business-email-compromise, credential harvesting, or brand abuse against your users/customers. Registered-but-dormant lookalikes are reported too because they are commonly parked ahead of a campaign."
                  % (candidate, perm['fuzzer'], domain, '; '.join(bits), status))
        issues.append(_new_issue(
            'typosquat-%s' % candidate,
            "Lookalike domain (%s): %s" % (status, candidate),
            detail, rating, asset_id, ISSUE_TYPE_TYPOSQUATTING, object_id=candidate,
            object_meta=meta,
            remediation="Check the WHOIS/registrant and, if it resolves, the hosted content to determine intent. A lookalike with MX records is a particular concern: it can send mail that appears to come from your domain (BEC), so treat it as active infrastructure. If it impersonates your brand or is phishing/email infrastructure, report it to the registrar and hosting provider abuse contacts, consider a UDRP/URS domain dispute, and add it to the email/web block-lists you manage. If it is a domain you legitimately own, no action is required."))

    checked = len(to_check)
    n_reg = len(classified)
    n_res = sum(1 for r in classified if r['ips'])
    n_mx = sum(1 for r in classified if r['mx'])
    n_dormant = sum(1 for r in classified if not r['ips'] and not r['mx'])

    if classified:
        summary = ("Generated %d dnstwist permutation(s) of [%s]%s and checked each for registration (A/AAAA address, MX, or NS/SOA delegation): [%d] are live registrations - [%d] resolve to an address, [%d] publish MX records and are capable of sending/receiving email as a lookalike, and [%d] are registered but currently dormant (delegated, no address, no MX)."
                   % (checked, domain,
                      " (capped from %d)" % len(permutations) if truncated else "",
                      n_reg, n_res, n_mx, n_dormant))
        issues.append(_new_issue(
            'typosquat-registration-summary', "Lookalike domain registration summary",
            summary, RATING_INFO, asset_id, ISSUE_TYPE_TYPOSQUATTING, object_id=domain,
            object_meta=','.join(r['candidate'] for r in classified[:60]),
            remediation="Triage the individual lookalike findings above, starting with any that publish MX records. Consider defensively registering the highest-risk unregistered permutations, and re-scan periodically - lookalike domains can be registered at any time."))
    else:
        issues.append(_new_issue(
            'typosquat-none-found', "No registered typosquatting domains found",
            "Checked [%s] domain-name permutation(s) of [%s] (additions, bitsquatting, homoglyphs, hyphenation, insertion, omission, repetition, transposition, vowel-swap, subdomain/combosquats, etc.) generated by dnstwist, and none are currently registered (no A/AAAA, MX, or NS/SOA)." % (checked, domain),
            RATING_INFO, asset_id, ISSUE_TYPE_TYPOSQUATTING, object_id=domain,
            remediation="No action required now. Lookalike domains can be registered at any time, so consider periodic re-scanning and/or a continuous brand-monitoring service for early detection."))

    if classified and not getattr(args, 'no_whois', False):
        whois_limit = getattr(args, 'typosquat_whois_limit', 15) or 0
        targets = [r['candidate'] for r in classified]     # already MX-first ordered
        if whois_limit and len(targets) > whois_limit:
            targets = targets[:whois_limit]
        with ThreadPoolExecutor(max_workers=min(10, len(targets)) or 1) as pool:
            futures = [pool.submit(check_whois, candidate, asset_id, candidate) for candidate in targets]
            for future in as_completed(futures):
                try:
                    issues.extend(future.result())
                except Exception as e:
                    logging.debug("WHOIS lookup task failed: %s", str(e))

    return issues
