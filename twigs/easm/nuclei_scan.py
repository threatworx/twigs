"""Web application vulnerability testing via the nuclei CLI - used only if
present on PATH; entirely skipped (no subprocess calls at all) otherwise."""
import os
import json
import hashlib
import logging
import shutil
import subprocess
import tempfile

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_WEB_APPLICATION
from .util import _http_get, _new_issue

NUCLEI = shutil.which('nuclei')

# nuclei's out-of-the-box pacing (150 req/s, 25 concurrent templates,
# -max-host-error 30) is tuned for hosts the operator owns/whitelisted. Against
# an arbitrary internet-facing target it routinely trips rate limiting: the
# server starts returning 429/503/timeouts, nuclei counts those as host errors,
# hits the threshold within seconds, and skips the host from the scan - every
# remaining template (thousands of them) is silently dropped and the run
# "completes" with a fraction of the real findings.
#
# Observed against a real target: even a raised -max-host-error 100 was tripped
# (~8% of ~9.5k requests errored, a burst exceeded 100) and the host was dropped
# at the 50% mark, so results swung run-to-run (63 findings one run, 7 the next).
# So host-error skipping is disabled entirely (-no-mhe) and the rate is lowered
# further; the subprocess-level `timeout` (nuclei_timeout, default 1h) is the
# sole bound and still protects against a genuinely dead host hanging forever.
# These are deliberately not exposed on the CLI yet; revisit for faster/slower
# targets.
NUCLEI_RATE_LIMIT = 15       # -rate-limit : max requests per second
NUCLEI_CONCURRENCY = 15      # -c          : max templates executed in parallel
NUCLEI_NO_HOST_ERROR_SKIP = True  # -no-mhe : never drop a host mid-scan on errors
NUCLEI_HTTP_TIMEOUT = 10     # -timeout    : seconds per request
NUCLEI_RETRIES = 1           # -retries    : retries per failed request

NUCLEI_SEVERITY_TO_RATING = {
    'info': RATING_INFO, 'low': RATING_LOW, 'medium': RATING_MEDIUM,
    'high': RATING_HIGH, 'critical': RATING_CRITICAL,
}


def nuclei_exists():
    return NUCLEI is not None and os.access(NUCLEI, os.X_OK)


def run_nuclei(host, asset_id, severity, timeout):
    issues = []
    if not nuclei_exists():
        return issues
    target = None
    for scheme in ('https', 'http'):
        if _http_get("%s://%s/" % (scheme, host)) is not None:
            target = "%s://%s/" % (scheme, host)
            break
    if target is None:
        return issues

    out_file = tempfile.NamedTemporaryFile(prefix='easm-nuclei-', suffix='.json', delete=False)
    out_file.close()
    cmd = [NUCLEI, '-u', target, '-severity', severity, '-jsonl', '-silent', '-no-color',
           '-rate-limit', str(NUCLEI_RATE_LIMIT),
           '-c', str(NUCLEI_CONCURRENCY),
           '-timeout', str(NUCLEI_HTTP_TIMEOUT),
           '-retries', str(NUCLEI_RETRIES),
           '-o', out_file.name]
    if NUCLEI_NO_HOST_ERROR_SKIP:
        cmd.append('-no-mhe')
    try:
        logging.info("Starting nuclei web application tests against [%s] - this may take some time", target)
        subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        logging.warning("nuclei scan against [%s] timed out", target)
    except Exception as e:
        logging.warning("nuclei scan against [%s] failed: %s", target, str(e))

    seen_ids = set()
    try:
        with open(out_file.name, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = finding.get('info', {})
                template_id = finding.get('template-id', finding.get('templateID', 'unknown'))
                sev = info.get('severity', 'info').lower()
                rating = NUCLEI_SEVERITY_TO_RATING.get(sev, RATING_INFO)
                matched_at = finding.get('matched-at', finding.get('host', target))
                classification = info.get('classification') or {}
                cve_id = classification.get('cve-id')
                cwe_id = classification.get('cwe-id')
                extra_bits = []
                if cve_id:
                    extra_bits.append('CVE(s): ' + ', '.join(cve_id) if isinstance(cve_id, list) else 'CVE: ' + str(cve_id))
                if cwe_id:
                    extra_bits.append('CWE(s): ' + ', '.join(cwe_id) if isinstance(cwe_id, list) else 'CWE: ' + str(cwe_id))
                if info.get('reference'):
                    extra_bits.append('References: ' + ', '.join(info.get('reference')))
                detail = "%s Matched at [%s]. Check ID [%s] (severity: %s). %s" % (
                    info.get('description', '').strip(), matched_at, template_id, sev, ' '.join(extra_bits))
                remediation = info.get('remediation') or (
                    "Validate this finding manually (automated web application vulnerability scans can produce false positives). If confirmed, apply the vendor patch/security update for the affected "
                    "software/CVE, or correct the misconfiguration described above. See the references for authoritative guidance.")

                # Build a stable, collision-resistant id. A single template can
                # legitimately fire multiple times against the same matched-at
                # URL (different named matcher, different extracted value - e.g.
                # http-missing-security-headers reports one match per missing
                # header), so template-id + matched-at alone is not unique. Fold
                # in the matcher name, extracted results and finding type, and
                # hash them with a deterministic digest (builtin hash() is
                # per-process salted, which would make ids unstable across runs).
                matcher_name = finding.get('matcher-name') or ''
                extracted = finding.get('extracted-results') or []
                extracted_key = ','.join(sorted(str(x) for x in extracted)) if isinstance(extracted, (list, tuple)) else str(extracted)
                fingerprint_src = '|'.join([
                    str(template_id), str(finding.get('type', '')), str(matched_at),
                    str(matcher_name), extracted_key,
                ])
                fingerprint = hashlib.sha1(fingerprint_src.encode('utf-8', 'replace')).hexdigest()[:12]
                twc_id = 'webapp-vuln-%s-%s' % (template_id, fingerprint)
                if twc_id in seen_ids:
                    # exact-duplicate line from nuclei - already recorded
                    continue
                seen_ids.add(twc_id)

                issues.append(_new_issue(
                    twc_id,
                    "%s" % info.get('name', template_id),
                    detail, rating, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=matched_at,
                    remediation=remediation))
    except FileNotFoundError:
        pass
    finally:
        try:
            os.remove(out_file.name)
        except OSError:
            pass

    if not issues:
        issues.append(_new_issue('webapp-vuln-none-found', "No web application vulnerabilities found",
                                  "Web application vulnerability testing completed against [%s] for severities [%s] with no matching findings. This does not guarantee the application is free of vulnerabilities; it only reflects the current test coverage used." % (target, severity),
                                  RATING_INFO, asset_id, ISSUE_TYPE_WEB_APPLICATION, object_id=target,
                                  remediation="No action required. Consider periodically re-running web application vulnerability testing with updated signatures/checks and broader severity coverage, for continued protection."))
    return issues

