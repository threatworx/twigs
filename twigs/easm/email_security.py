"""Email security checks: SPF, DMARC, DKIM (common selectors), MX, MTA-STS
(inbound mail transport encryption policy), TLS-RPT, and BIMI."""
import re

import requests

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_EMAIL_SECURITY, HTTP_TIMEOUT
from .util import HAVE_DNSPYTHON, _get_dns_resolver, _resolve_record, _new_issue

DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim',
    'smtp', 'mandrill', 'sendgrid', 'pm', 'zoho', 'mx', 's1', 's2',
]


def _check_mta_sts(domain, resolver, asset_id):
    """MTA-STS is SMTP's analogue of HSTS - it lets a domain force sending
    mail servers to require TLS (and validate the receiving MX's identity)
    for inbound delivery, preventing a network attacker from stripping
    STARTTLS or redirecting mail to a rogue server. Only meaningful for
    domains that actually receive mail - callers should gate this on MX
    presence."""
    issues = []
    dns_answers = _resolve_record(resolver, '_mta-sts.' + domain, 'TXT')
    has_dns_record = False
    if dns_answers:
        for rr in dns_answers:
            if b''.join(rr.strings).decode('utf-8', errors='replace').lower().startswith('v=stsv1'):
                has_dns_record = True
                break

    policy_mode = None
    if has_dns_record:
        try:
            resp = requests.get('https://mta-sts.' + domain + '/.well-known/mta-sts.txt',
                                 timeout=HTTP_TIMEOUT, verify=False)
            if resp.status_code == 200:
                m = re.search(r'^\s*mode:\s*(\w+)', resp.text, re.MULTILINE | re.IGNORECASE)
                if m:
                    policy_mode = m.group(1).lower()
        except requests.exceptions.RequestException:
            pass

    if not has_dns_record:
        issues.append(_new_issue('email-no-mta-sts', "No MTA-STS policy configured",
            "Domain [%s] does not publish an MTA-STS (_mta-sts TXT) record. Without MTA-STS, a network attacker performing a MITM attack against inbound mail delivery can strip STARTTLS or redirect delivery to a rogue mail server, since SMTP has no equivalent of HSTS by default." % domain,
            RATING_LOW, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="Consider publishing an MTA-STS policy: a '_mta-sts' TXT record plus a policy file at 'https://mta-sts.%s/.well-known/mta-sts.txt' listing your MX hosts, moving to mode=enforce once confirmed working. This is defense-in-depth for inbound mail transport encryption, not urgent for most domains." % domain))
    elif policy_mode == 'testing':
        issues.append(_new_issue('email-mta-sts-testing', "MTA-STS policy present but in testing mode",
            "Domain [%s] publishes an MTA-STS policy in 'testing' mode, which (with TLS-RPT configured) reports violations but does not actually enforce TLS for inbound mail delivery yet." % domain,
            RATING_LOW, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="Once TLS-RPT reports confirm no legitimate mail delivery would break, switch the policy mode to 'enforce'."))
    elif policy_mode == 'enforce':
        issues.append(_new_issue('email-mta-sts-enforced', "MTA-STS policy enforced",
            "Domain [%s] publishes an MTA-STS policy in 'enforce' mode: conforming sending mail servers will refuse to deliver mail over an unencrypted or MITM'd connection." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="No action required."))
    else:
        issues.append(_new_issue('email-mta-sts-policy-unreachable', "MTA-STS DNS record present but policy file not retrievable",
            "Domain [%s] publishes an '_mta-sts' TXT record, but the policy file at https://mta-sts.%s/.well-known/mta-sts.txt could not be retrieved or parsed. Mail senders that support MTA-STS will be unable to apply this policy." % (domain, domain),
            RATING_LOW, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="Ensure https://mta-sts.%s/.well-known/mta-sts.txt is reachable over valid TLS and returns a well-formed policy body (version/mode/mx/max_age lines)." % domain))

    tlsrpt_answers = _resolve_record(resolver, '_smtp._tls.' + domain, 'TXT')
    has_tlsrpt = False
    if tlsrpt_answers:
        for rr in tlsrpt_answers:
            if b''.join(rr.strings).decode('utf-8', errors='replace').lower().startswith('v=tlsrptv1'):
                has_tlsrpt = True
                break
    if has_tlsrpt:
        issues.append(_new_issue('email-tlsrpt-configured', "TLS-RPT reporting configured",
            "Domain [%s] publishes a TLS-RPT record, providing visibility into TLS/MTA-STS delivery failures encountered by senders." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="No action required."))
    else:
        issues.append(_new_issue('email-no-tlsrpt', "No TLS-RPT reporting configured",
            "Domain [%s] does not publish a TLS-RPT (_smtp._tls TXT) record, so there is no visibility into TLS/MTA-STS delivery failures sending mail servers encounter for this domain." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="Consider publishing a TLS-RPT record, e.g. '_smtp._tls.%s TXT v=TLSRPTv1;rua=mailto:tlsrpt@%s', especially alongside an MTA-STS policy so delivery failures it causes are visible." % (domain, domain)))
    return issues


def _check_bimi(domain, resolver, asset_id):
    """BIMI displays a brand logo alongside authenticated email in
    supporting inbox providers, and requires DMARC enforcement (p=quarantine
    or p=reject) to actually take effect. Adoption is optional/low overall,
    so absence is reported at INFO, not as a hardening gap the way missing
    SPF/DMARC/CAA are."""
    answers = _resolve_record(resolver, 'default._bimi.' + domain, 'TXT')
    bimi_record = None
    if answers:
        for rr in answers:
            val = b''.join(rr.strings).decode('utf-8', errors='replace')
            if val.lower().startswith('v=bimi1'):
                bimi_record = val
                break
    if not bimi_record:
        return [_new_issue('email-no-bimi', "No BIMI record configured",
            "Domain [%s] does not publish a BIMI (Brand Indicators for Message Identification) record. BIMI is optional - it displays a brand logo alongside authenticated email in supporting inbox providers - and only takes effect once DMARC is already enforced (p=quarantine/reject)." % domain,
            RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
            remediation="Optional. If brand recognition in the inbox is valuable for this domain and DMARC is already enforced, consider publishing a BIMI record with a Verified Mark Certificate (VMC).")]
    has_vmc = bool(re.search(r'\ba=', bimi_record))
    return [_new_issue('email-bimi-configured', "BIMI record configured" + (" with a Verified Mark Certificate" if has_vmc else ""),
        "Domain [%s] publishes a BIMI record%s." % (domain, ' referencing a Verified Mark Certificate (a=), proving brand/logo ownership via a CA' if has_vmc else ' without a Verified Mark Certificate (a=) - some inbox providers require a VMC for the logo to actually display'),
        RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
        remediation="No action required. Confirm the domain's DMARC policy is at p=quarantine or p=reject, since most inbox providers only display BIMI logos when DMARC is enforced.")]


def check_email_security(domain, asset_id):
    issues = []
    if not HAVE_DNSPYTHON:
        return issues
    resolver = _get_dns_resolver()
    problems = []
    dkim_found = []

    mx_answers = _resolve_record(resolver, domain, 'MX')
    has_mx = mx_answers is not None and len(mx_answers) > 0
    if not has_mx:
        problems.append(_new_issue('email-no-mx', "No MX records found",
                                    "Domain [%s] has no MX records, meaning it is not currently configured to receive email directly. Domains without mail service are nonetheless common spoofing targets since recipients cannot easily tell a forged message apart." % domain,
                                    RATING_LOW, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                    remediation="If this domain is not expected to receive email, publish a null MX record ('.' with priority 0, per RFC 7505) and a restrictive SPF record (e.g. 'v=spf1 -all') and a DMARC record with p=reject to explicitly prevent spoofing."))

    txt_answers = _resolve_record(resolver, domain, 'TXT')
    spf_records = []
    if txt_answers:
        for rr in txt_answers:
            val = b''.join(rr.strings).decode('utf-8', errors='replace')
            if val.lower().startswith('v=spf1'):
                spf_records.append(val)

    if not spf_records:
        problems.append(_new_issue('email-no-spf', "No SPF record found",
                                    "Domain [%s] does not publish an SPF (Sender Policy Framework) record. Without SPF, receiving mail servers have no authoritative list of which hosts are allowed to send email as this domain, making it easier for third parties to spoof email claiming to be from this domain (a common precursor to phishing/BEC attacks against your customers/partners)." % domain,
                                    RATING_MEDIUM, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                    remediation="Publish an SPF TXT record on the domain apex listing your legitimate sending infrastructure, ending in a hard-fail qualifier, e.g. 'v=spf1 include:_spf.example.com -all'."))
    else:
        if len(spf_records) > 1:
            problems.append(_new_issue('email-multiple-spf', "Multiple SPF records found",
                                        "Domain [%s] publishes [%s] SPF records. RFC 7208 requires exactly one SPF record per domain; multiple records cause SPF validation to fail entirely (treated as a permanent error/permerror), which can cause legitimate mail to be rejected or spoofed mail to not be properly evaluated." % (domain, len(spf_records)),
                                        RATING_MEDIUM, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                        remediation="Consolidate all authorized senders into a single SPF record (use 'include:' mechanisms to reference third-party senders) and remove the duplicate record(s)."))
        for spf in spf_records:
            if re.search(r'[+]?all\b', spf) and '+all' in spf.replace(' ', ''):
                problems.append(_new_issue('email-spf-allow-all', "SPF record allows all senders",
                                            "The SPF record for [%s] ends with '+all', which explicitly permits any host on the internet to send email as this domain, completely defeating the purpose of SPF. Record: [%s]" % (domain, spf),
                                            RATING_HIGH, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                            remediation="Change the SPF record to end with '-all' (hard fail) once all legitimate senders are enumerated, or '~all' (soft fail) as an interim step."))
            elif spf.strip().endswith('?all'):
                problems.append(_new_issue('email-spf-neutral', "SPF record uses neutral policy",
                                            "The SPF record for [%s] ends with '?all' (neutral), which provides no real protection against spoofing since it takes no position on unlisted senders. Record: [%s]" % (domain, spf),
                                            RATING_LOW, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                            remediation="Change the qualifier to '-all' (hard fail) or at minimum '~all' (soft fail) once legitimate senders are confirmed to be fully enumerated in the record."))

    dmarc_answers = _resolve_record(resolver, '_dmarc.' + domain, 'TXT')
    dmarc_records = []
    if dmarc_answers:
        for rr in dmarc_answers:
            val = b''.join(rr.strings).decode('utf-8', errors='replace')
            if val.lower().startswith('v=dmarc1'):
                dmarc_records.append(val)

    if not dmarc_records:
        problems.append(_new_issue('email-no-dmarc', "No DMARC record found",
                                    "Domain [%s] does not publish a DMARC record. Without DMARC, there is no domain-level policy telling receiving mail servers what to do with messages that fail SPF/DKIM checks, and no reporting mechanism (rua/ruf) to alert you to spoofing attempts, significantly reducing protection against email spoofing/phishing that impersonates this domain." % domain,
                                    RATING_MEDIUM, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                    remediation="Publish a DMARC record at '_dmarc.%s', starting in monitor mode to avoid disrupting legitimate mail, e.g. 'v=DMARC1; p=none; rua=mailto:dmarc-reports@%s;', then progress to p=quarantine and eventually p=reject once reports confirm legitimate senders are correctly authenticated." % (domain, domain)))
    else:
        dmarc = dmarc_records[0]
        pmatch = re.search(r'p=(\w+)', dmarc, re.I)
        policy = pmatch.group(1).lower() if pmatch else None
        if policy == 'none':
            problems.append(_new_issue('email-dmarc-policy-none', "DMARC policy set to 'none'",
                                        "The DMARC policy for [%s] is set to 'none' (monitor only), meaning that even messages that fail SPF/DKIM are still delivered as normal; spoofed email is not rejected or quarantined, only (optionally) reported on. Record: [%s]" % (domain, dmarc),
                                        RATING_LOW, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                        remediation="Once DMARC aggregate reports (rua) confirm all legitimate mail sources pass SPF/DKIM alignment, move the policy to p=quarantine and eventually p=reject to actively block spoofed mail."))
        pctmatch = re.search(r'pct=(\d+)', dmarc, re.I)
        if pctmatch and int(pctmatch.group(1)) < 100:
            problems.append(_new_issue('email-dmarc-pct-partial', "DMARC policy applied to a subset of messages",
                                        "The DMARC record for [%s] applies its policy to only [%s%%] of messages (pct=%s), meaning the remainder are handled as if the policy were 'none'. This is often used as a gradual rollout mechanism but leaves a spoofing gap while pct < 100. Record: [%s]" % (domain, pctmatch.group(1), pctmatch.group(1), dmarc),
                                        RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                        remediation="Increase 'pct' to 100 once monitoring confirms the current policy does not impact legitimate mail flow."))

    for selector in DKIM_SELECTORS:
        dkim_answers = _resolve_record(resolver, selector + '._domainkey.' + domain, 'TXT')
        if dkim_answers:
            for rr in dkim_answers:
                val = b''.join(rr.strings).decode('utf-8', errors='replace')
                if 'v=dkim1' in val.lower() or 'p=' in val.lower():
                    dkim_found.append(selector)
                    issues.append(_new_issue('email-dkim-found-%s' % selector, "DKIM record found (selector: %s)" % selector,
                                              "A DKIM record was found for domain [%s] under selector [%s], indicating DKIM signing is configured for at least one mail stream. DKIM allows receiving servers to cryptographically verify that a message was not altered in transit and was sent by a party with access to the private key." % (domain, selector),
                                              RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                              remediation="This is a positive finding. Ensure DKIM keys are rotated periodically and that all legitimate outbound mail streams (including third-party senders) are DKIM-signed."))
                    break

    if has_mx:
        issues.extend(_check_mta_sts(domain, resolver, asset_id))
    issues.extend(_check_bimi(domain, resolver, asset_id))

    issues.extend(problems)
    if not problems:
        issues.append(_new_issue('email-security-no-issues', "No critical email security issues found",
                                  "Domain [%s]%s has SPF and DMARC records published with a reasonably strict configuration (no permissive '+all'/neutral SPF qualifier, and no DMARC p=none policy detected). %s" % (
                                      domain, ' has MX records and' if has_mx else ' has no MX records but',
                                      ("DKIM was additionally confirmed under selector(s): %s." % ', '.join(dkim_found)) if dkim_found else "DKIM selectors were not confirmed using the common selector wordlist checked; this does not necessarily mean DKIM is absent."),
                                  RATING_INFO, asset_id, ISSUE_TYPE_EMAIL_SECURITY, object_id=domain,
                                  remediation="No action required. Periodically re-verify SPF/DMARC records after any change to mail sending infrastructure."))
    return issues
