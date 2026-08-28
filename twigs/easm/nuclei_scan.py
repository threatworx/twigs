"""Web application vulnerability testing via the nuclei CLI - used only if
present on PATH; entirely skipped (no subprocess calls at all) otherwise."""
import os
import json
import logging
import shutil
import subprocess
import tempfile

from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_WEB_APPLICATION
from .util import _http_get, _new_issue

NUCLEI = shutil.which('nuclei')

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
           '-o', out_file.name]
    try:
        logging.info("Running nuclei web application tests against [%s]", target)
        subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        logging.warning("nuclei scan against [%s] timed out", target)
    except Exception as e:
        logging.warning("nuclei scan against [%s] failed: %s", target, str(e))

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
                issues.append(_new_issue(
                    'webapp-vuln-%s-%s' % (template_id, abs(hash(matched_at)) % 100000),
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

