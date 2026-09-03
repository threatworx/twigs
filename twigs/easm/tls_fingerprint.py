"""Active TLS-stack fingerprinting for infrastructure clustering.

Sends a fixed battery of deliberately-varied TLS ClientHellos (different
version floors/ceilings, cipher orderings, cipher-strength levels and ALPN
offers) and records exactly how the server negotiates each one - protocol,
cipher, ALPN, and the way failed handshakes fail. The ordered tuple of
outcomes is hashed into a stable per-server fingerprint.

Two servers that produce the same fingerprint are running the same TLS
termination stack with the same configuration - so the fingerprint clusters
load balancers, WAFs, CDN edges, appliances and C2 redirectors across a
scan even when they present different certificates or hostnames. It is
reported as a TLS_STACK: asset tag (like the favicon hash), not a finding on
its own; the leaf-certificate SHA-256 is tagged alongside it for the same
correlation purpose.

This is a JARM-style methodology (multiple probe Hellos, hash the responses)
implemented on top of the standard library. It is NOT the wire-compatible
JARM hash and cannot be matched against published JARM values - see the EASM
gap list, item 27, for that follow-up.
"""
import ssl
import socket
import hashlib
import logging

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

from .constants import RATING_INFO, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_SSL, HTTP_TIMEOUT

try:
    from .ssl_checks import _get_tls_candidate_ports
except Exception:                       # pragma: no cover - defensive
    def _get_tls_candidate_ports(host_result):
        return [443]

_V = ssl.TLSVersion

# (label, min_version, max_version, cipher_string, [alpn]) - order is part of
# the fingerprint, do not reorder.
_PROBES = [
    ('tls13',        _V.TLSv1_3, _V.TLSv1_3, None, ['h2', 'http/1.1']),
    ('tls12',        _V.TLSv1_2, _V.TLSv1_2, 'DEFAULT', ['h2', 'http/1.1']),
    ('tls12_rev',    _V.TLSv1_2, _V.TLSv1_2, 'DEFAULT:-ALL:ALL', ['http/1.1']),
    ('tls12_aes128', _V.TLSv1_2, _V.TLSv1_2, 'AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256', None),
    ('tls12_aes256', _V.TLSv1_2, _V.TLSv1_2, 'AES256-SHA:ECDHE-RSA-AES256-SHA', None),
    ('tls12_weak',   _V.TLSv1_2, _V.TLSv1_2, 'ALL:COMPLEMENTOFALL:@SECLEVEL=0', None),
    ('tls11',        _V.TLSv1_1, _V.TLSv1_1, 'ALL:@SECLEVEL=0', ['http/1.1']),
    ('tls10',        _V.TLSv1,   _V.TLSv1,   'ALL:@SECLEVEL=0', None),
    ('span',         _V.TLSv1,   _V.TLSv1_3, 'DEFAULT:@SECLEVEL=0', ['h2', 'http/1.1', 'spdy/3']),
    ('alpn_bogus',   _V.TLSv1_2, _V.TLSv1_3, 'DEFAULT', ['jarm/9', 'imap']),
]

_WEAK_CIPHER_TOKENS = ('NULL', 'EXP', 'EXPORT', 'RC4', 'DES-CBC-', '3DES', 'DES-CBC3',
                       'ADH', 'AECDH', 'anon', 'MD5', 'IDEA', 'SEED', 'CAMELLIA')


def _one_probe(host, port, minv, maxv, ciphers, alpn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = minv
        ctx.maximum_version = maxv
    except (ValueError, OSError):
        return 'unsupported', None
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            return 'nocipher', None
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except (NotImplementedError, ssl.SSLError):
            pass
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                neg = '%s|%s|%s' % (ss.version() or '?',
                                    (ss.cipher() or ('?',))[0],
                                    ss.selected_alpn_protocol() or '-')
                der = ss.getpeercert(True)
                return neg, der
    except ssl.SSLError as e:
        code = getattr(e, 'reason', None) or (e.args[0] if e.args else 'sslerror')
        return 'sslerr:%s' % code, None
    except socket.timeout:
        return 'timeout', None
    except (ConnectionResetError, ConnectionRefusedError):
        return 'reset', None
    except OSError as e:
        return 'oserr:%s' % (getattr(e, 'errno', '?'),), None


def _leaf_sha256(der):
    if not der:
        return None
    return hashlib.sha256(der).hexdigest()


def check_tls_fingerprint(host, host_result, tags, asset_id, args):
    if getattr(args, 'no_tls_fingerprint', False):
        return []

    ports = _get_tls_candidate_ports(host_result)
    port = 443 if 443 in ports else (ports[0] if ports else 443)

    results = []
    negotiated_ciphers = []
    der_seen = None
    for label, minv, maxv, ciphers, alpn in _PROBES:
        outcome, der = _one_probe(host, port, minv, maxv, ciphers, alpn)
        results.append('%s=%s' % (label, outcome))
        if der and der_seen is None:
            der_seen = der
        if '|' in outcome:
            negotiated_ciphers.append(outcome.split('|')[1])

    if all(r.split('=', 1)[1] in ('timeout', 'reset', 'unsupported', 'nocipher')
           or r.split('=', 1)[1].startswith(('oserr', 'sslerr'))
           for r in results):
        logging.debug("[EASM] tls_fingerprint: no TLS handshake completed on [%s:%s]", host, port)
        return []

    canonical = ';'.join(results)
    fp = hashlib.sha256(canonical.encode()).hexdigest()[:32]
    tag = 'TLS_STACK:%s' % fp
    if tags is not None and tag not in tags:
        tags.append(tag)
    cert_sha = _leaf_sha256(der_seen)
    if cert_sha and tags is not None:
        ct = 'TLS_CERT_SHA256:%s' % cert_sha
        if ct not in tags:
            tags.append(ct)

    succeeded = [r.split('=', 1)[0] for r in results if '|' in r.split('=', 1)[1]]
    issues = [_mk_issue(
        'tls-stack-fingerprint', "TLS stack fingerprint (for infrastructure correlation)",
        "Fingerprinting [%s:%s] with %d varied TLS ClientHellos produced stack fingerprint [%s]. %d/%d probe handshakes completed. Servers sharing this fingerprint run an identical TLS termination stack and configuration (load balancer / WAF / CDN edge / appliance), which is useful for clustering related infrastructure across the scan. Probe outcomes: %s"
        % (host, port, len(_PROBES), fp, len(succeeded), len(_PROBES), canonical),
        RATING_INFO, asset_id, host,
        "No action required. This is a correlation signal, reported as the TLS_STACK asset tag, not a vulnerability.")]

    weak = sorted({c for c in negotiated_ciphers
                   if any(tok in c.upper() for tok in (t.upper() for t in _WEAK_CIPHER_TOKENS))})
    if weak:
        issues.append(_mk_issue(
            'tls-weak-cipher-negotiated', "Server negotiated a weak/legacy TLS cipher",
            "During TLS stack fingerprinting, [%s:%s] completed a handshake using weak or legacy cipher(s): %s. These ciphers (export-grade, NULL, RC4, single-DES/3DES, anonymous DH, or MD5-MAC) are broken or deprecated and should not be offered by an internet-facing service."
            % (host, port, ', '.join(weak)),
            RATING_HIGH if any(t in ' '.join(weak).upper() for t in ('NULL', 'EXP', 'ADH', 'AECDH', 'RC4')) else RATING_MEDIUM,
            asset_id, host,
            "Restrict the server's cipher list to modern AEAD suites (AES-GCM, ChaCha20-Poly1305) over ECDHE, and disable export/NULL/RC4/DES/3DES/anonymous ciphers. On OpenSSL-based servers ensure SECLEVEL is at least 2."))
    return issues


def _mk_issue(twc_id, title, details, rating, asset_id, host, remediation):
    from .util import _new_issue
    return _new_issue(twc_id, title, details, rating, asset_id, ISSUE_TYPE_SSL,
                      object_id=host, remediation=remediation)
