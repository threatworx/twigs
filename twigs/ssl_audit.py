import sys
import re
import os
import shutil
import stat
import signal
import subprocess
import logging
import json
import tempfile
import traceback

def get_rating(sev):
    if sev == 'INFO' or sev == 'OK':
        return '1'
    if sev == 'LOW':
        return '2'
    if sev == 'MEDIUM':
        return '3'
    if sev == 'HIGH':
        return '4'
    if sev == 'CRITICAL':
        return '5'
    return '1'

# Section name -> title prefix used to build each finding's twc_title.
SSL_AUDIT_SECTIONS = [
    ('pretest', ''),
    ('protocols', 'protocol: '),
    ('grease', ''),
    ('ciphers', 'cipher: '),
    ('fs', 'forward secrecy: '),
    ('serverPreferences', 'server preference: '),
    ('serverDefaults', 'server default: '),
    ('headerResponse', 'header response: '),
    ('vulnerabilities', 'vulnerability: '),
    ('cipherTests', 'cipher test: '),
    ('browserSimulations', 'browser simulation: '),
]

# Plain-language description + remediation for testssl.sh's named
# vulnerability check IDs (the 'vulnerabilities' section, i.e. what a -U/
# --vulnerable scan returns). This only post-processes testssl.sh's own JSON
# output client-side - it does not modify testssl.sh itself. Each value is
# (description, remediation_if_flagged, remediation_if_not_flagged).
VULNERABILITY_ENRICHMENT = {
    'heartbleed': (
        "Heartbleed (CVE-2014-0160) is an OpenSSL flaw in the TLS heartbeat extension that lets an attacker read up to 64KB of server process memory per request without authentication - potentially exposing private keys, session data, or credentials.",
        "Upgrade OpenSSL to a patched version immediately, then treat the private key as compromised: reissue the certificate with a new key pair and revoke the old one, and rotate any credentials that may have transited the server.",
        "No action required.",
    ),
    'CCS': (
        "The CCS injection flaw (CVE-2014-0224) is an OpenSSL bug in ChangeCipherSpec processing that can let a man-in-the-middle force use of weak/predictable keying material, potentially allowing traffic decryption or manipulation.",
        "Upgrade OpenSSL to a patched version.",
        "No action required.",
    ),
    'ticketbleed': (
        "Ticketbleed (CVE-2016-9244) is a bug in some F5 BIG-IP TLS session-ticket implementations that can leak up to 31 bytes of uninitialized memory per request, potentially exposing other sessions' data.",
        "Apply F5's patch / upgrade firmware, or disable TLS session tickets on the device if patching is not immediately possible.",
        "No action required.",
    ),
    'ROBOT': (
        "ROBOT (Return Of Bleichenbacher's Oracle Threat) is a padding-oracle flaw in RSA PKCS#1 v1.5 key exchange handling that can allow decryption of captured TLS traffic or, in some setups, signing/forgery.",
        "Disable RSA key exchange cipher suites in favor of ECDHE/DHE (which provide forward secrecy and are not affected), and patch the TLS stack to a version with proper Bleichenbacher countermeasures.",
        "No action required.",
    ),
    'Secure Renegotiation': (
        "Secure renegotiation (RFC 5746) protects against a TLS renegotiation flaw (CVE-2009-3555) that could otherwise let a man-in-the-middle inject plaintext data into an authenticated session.",
        "Upgrade the TLS stack to one that supports secure renegotiation (RFC 5746), and disable legacy insecure renegotiation.",
        "No action required - secure renegotiation is supported.",
    ),
    'secure_client_renego': (
        "Client-initiated renegotiation, if enabled, can be abused for denial-of-service (each renegotiation is computationally expensive for the server) and has historically been linked to renegotiation-based attacks.",
        "Disable client-initiated TLS renegotiation at the server/load-balancer, while keeping secure (server-initiated) renegotiation supported.",
        "No action required - client-initiated renegotiation is disabled.",
    ),
    'CRIME_TLS': (
        "CRIME is a compression-ratio side-channel attack: if TLS-level compression is enabled, an attacker who can influence part of the encrypted request/response can recover secret data (such as session cookies) by observing how well the response compresses.",
        "Disable TLS-level compression on the server/load-balancer.",
        "No action required - TLS compression is disabled.",
    ),
    'BREACH': (
        "BREACH is the HTTP-level analogue of CRIME: if HTTP response compression (e.g. gzip) is enabled and a response contains both attacker-influenced content and a secret (such as a CSRF token), the secret can be recovered via a compression-ratio side channel.",
        "Disable HTTP compression for responses containing secrets, add per-request random padding/masking to sensitive tokens, or disable compression entirely on sensitive endpoints.",
        "No action required.",
    ),
    'POODLE_SSL': (
        "POODLE (CVE-2014-3566) is a padding-oracle flaw in SSLv3's CBC-mode ciphers that lets a man-in-the-middle who can force a protocol downgrade to SSLv3 recover plaintext (e.g. session cookies) byte by byte.",
        "Disable SSLv3 entirely on the server - there is no safe way to keep SSLv3 enabled.",
        "No action required - SSLv3 is not supported.",
    ),
    'fallback_SCSV': (
        "TLS_FALLBACK_SCSV is a signal clients can send to detect when they are being forced to retry a connection at a lower (potentially vulnerable) protocol version, which helps prevent downgrade attacks like POODLE.",
        "Upgrade the TLS stack to a version that supports TLS_FALLBACK_SCSV and ensure it is not disabled.",
        "No action required - downgrade attack prevention (TLS_FALLBACK_SCSV) is supported.",
    ),
    'SWEET32': (
        "SWEET32 (CVE-2016-2183) is a birthday-bound collision attack against 64-bit block ciphers (3DES, Blowfish/IDEA) that can allow partial plaintext recovery from long-lived HTTPS connections transferring large amounts of data.",
        "Disable 3DES and other 64-bit block cipher suites; prefer AES-GCM or ChaCha20-Poly1305.",
        "No action required.",
    ),
    'FREAK': (
        "FREAK (CVE-2015-0204) is a flaw allowing a man-in-the-middle to force use of deliberately weakened 'export-grade' RSA (≤512-bit) key exchange, which can then be factored to decrypt the session.",
        "Disable export-grade cipher suites entirely - modern TLS stacks should not offer these by default, but explicitly confirm they are disabled.",
        "No action required.",
    ),
    'DROWN': (
        "DROWN (CVE-2016-0800) is a cross-protocol attack: if SSLv2 is enabled anywhere a certificate/private key is also used for TLS (even on a different service/port), an attacker can use SSLv2 weaknesses to decrypt captured TLS traffic protected by the same key.",
        "Disable SSLv2 entirely on this and any other service sharing the same certificate/private key.",
        "No action required - SSLv2 is not supported.",
    ),
    'DROWN_hint': (
        "This indicates the certificate/private key used here is also associated with another host; if that other host has SSLv2 enabled, this service is indirectly exposed to the DROWN attack via the shared key.",
        "Identify the other host(s) sharing this certificate/private key and confirm SSLv2 is disabled on all of them.",
        "No action required.",
    ),
    'LOGJAM': (
        "LOGJAM (CVE-2015-4000) is a flaw allowing a man-in-the-middle to force use of weak (export-grade or otherwise undersized, typically ≤1024-bit) Diffie-Hellman parameters, which can then be broken to recover the session key.",
        "Use Diffie-Hellman parameters of at least 2048 bits, and disable export-grade DHE cipher suites.",
        "No action required.",
    ),
    'LOGJAM-common_primes': (
        "Using a well-known/shared Diffie-Hellman prime (rather than a uniquely generated one) makes precomputation-based attacks against the key exchange far more feasible, even at an otherwise adequate bit length.",
        "Generate unique, server-specific Diffie-Hellman parameters rather than using a well-known default prime, or prefer ECDHE over classic DHE.",
        "No action required - a non-common DH prime is in use.",
    ),
    'BEAST': (
        "BEAST is a plaintext-recovery attack against CBC-mode ciphers in TLS 1.0, exploiting predictable initialization vectors. Modern browsers include client-side mitigations, but the durable fix is server-side.",
        "Disable TLS 1.0, or ensure the server prioritizes AEAD/non-CBC cipher suites (AES-GCM, ChaCha20-Poly1305) ahead of CBC-mode ciphers.",
        "No action required.",
    ),
    'BEAST_CBC_TLS1': (
        "This specific check flags CBC-mode cipher suites offered under TLS 1.0, the combination exploited by the BEAST attack.",
        "Disable TLS 1.0, or deprioritize CBC-mode cipher suites in favor of AEAD ciphers.",
        "No action required.",
    ),
    'LUCKY13': (
        "LUCKY13 (CVE-2013-0169) is a timing side-channel in CBC-mode record padding validation that can, under favorable conditions, allow plaintext recovery. Most current TLS libraries include constant-time countermeasures.",
        "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) over CBC-mode ciphers, and ensure the TLS library is patched to a version with constant-time CBC padding checks.",
        "No action required.",
    ),
    'RC4': (
        "RC4 is a stream cipher with known statistical biases that can allow plaintext recovery given enough captured traffic. It has been formally deprecated for TLS (RFC 7465) since 2015.",
        "Disable RC4 cipher suites entirely.",
        "No action required - RC4 is not offered.",
    ),
    'pre_128cipher': (
        "This is a pre-scan sanity check confirming the scanning client itself can negotiate a 128-bit-or-stronger cipher with the target before running the full vulnerability battery - it reflects the scan environment, not the target's configuration.",
        "If unexpected, verify network connectivity and cipher support on the machine running the scan rather than the target.",
        "No action required.",
    ),
}


def _enrich_finding(p, section):
    """Builds a richer details string on top of testssl.sh's raw finding
    text/severity - this only post-processes testssl.sh's own JSON output
    client-side and does not modify testssl.sh itself."""
    rating = get_rating(p.get('severity'))
    is_concern = rating not in ('1', '2')

    parts = [p.get('finding', '')]
    if p.get('cve'):
        parts.append(p['cve'])
    if p.get('cwe'):
        parts.append(p['cwe'])
    details = ' '.join(x for x in parts if x).strip()

    enrichment = VULNERABILITY_ENRICHMENT.get(p.get('id', ''))
    if enrichment:
        description, remediation_if_concern, remediation_if_ok = enrichment
        details = (details + ' ' + description).strip()
        remediation = remediation_if_concern if is_concern else remediation_if_ok
    elif section == 'vulnerabilities':
        remediation = ("Investigate this finding against current SSL/TLS best practices and the CVE/CWE reference above; "
                        "this typically means disabling the affected protocol/cipher/feature and upgrading the underlying TLS library.") if is_concern else "No action required for this check."
    else:
        remediation = None

    if remediation:
        details = details + ' Remediation: ' + remediation
    return details

def run_ssl_audit(url, assetid, timeout=None, vulnerable_only=False):
    findings = []
    SSL_AUDIT_PATH = os.path.dirname(os.path.realpath(__file__)) + '/ssl_audit/testssl.sh'
    temp_name = next(tempfile._get_candidate_names())
    defult_tmp_dir = tempfile._get_default_tempdir()
    audit_out = defult_tmp_dir + '/' + temp_name + '.json'
    # -U/--vulnerable limits testssl.sh to just its named-vulnerability checks
    # (Heartbleed, POODLE, FREAK, Logjam, DROWN, ROBOT, BEAST, CRIME, etc.),
    # skipping the much slower full cipher/protocol/header enumeration that a
    # default run performs.
    vuln_flag = ' -U' if vulnerable_only else ''
    cmd = SSL_AUDIT_PATH + vuln_flag + ' -oJ ' + audit_out + ' ' +url
    cmdarr = [cmd]
    if timeout is None:
        # Preserves prior behavior exactly (no timeout) for existing callers.
        try:
            dev_null_device = open(os.devnull, "w")
            subprocess.check_output(cmdarr, stderr=dev_null_device, shell=True)
            dev_null_device.close()
        except subprocess.CalledProcessError as e:
            logging.debug("ssl audit error")
            logging.debug(str(e))
    else:
        # start_new_session=True puts testssl.sh in its own process group so
        # that, on timeout, we can kill the actual testssl.sh/openssl
        # process(es) rather than just the shell wrapper spawned by
        # shell=True (killing only the shell leaves them running as orphans).
        dev_null_device = open(os.devnull, "w")
        proc = subprocess.Popen(cmdarr, stdout=dev_null_device, stderr=dev_null_device,
                                 shell=True, start_new_session=True)
        try:
            proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            logging.debug("ssl audit against [%s] timed out after %ss - terminating", url, timeout)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.communicate()
        finally:
            dev_null_device.close()

    try:
        jf = open(audit_out, 'r')
        out = jf.read()
        jf.close()
        os.remove(audit_out)
        odict = json.loads(out)
    except Exception as e:
        logging.debug("error processing ssl audit output")
        logging.debug(str(e))
        return findings

    if 'scanResult' in odict:
        section_data = odict['scanResult'][0]
        for section, title_prefix in SSL_AUDIT_SECTIONS:
            if section not in section_data:
                continue
            for p in section_data[section]:
                issue = {}
                issue['twc_id'] = 'ssl-audit-' + p['id']
                issue['twc_title'] = title_prefix + p['id']
                issue['details'] = _enrich_finding(p, section)
                issue['rating'] = get_rating(p['severity'])
                issue['object_id'] = url
                issue['asset_id'] = assetid
                issue['object_meta'] = ''
                issue['type'] = 'SSL'
                findings.append(issue)
    return findings
