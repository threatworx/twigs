"""SSL/TLS certificate hygiene checks (expiry, self-signed, weak key/sig,
hostname mismatch, deprecated protocols) plus named-vulnerability scanning
(Heartbleed, POODLE, FREAK, Logjam, DROWN, ROBOT, BEAST, CRIME, etc.) via the
vendored testssl.sh (twigs.ssl_audit)."""
import os
import re
import socket
import ssl
import logging
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

from .. import ssl_audit
from .constants import RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL, ISSUE_TYPE_SSL, TLS_PORT_HINTS, HTTP_TIMEOUT
from .util import _new_issue

# ssl_audit's testssl.sh binary lives at twigs/ssl_audit/testssl.sh - derive
# the path from ssl_audit's own __file__ (not this module's) so it stays
# correct regardless of how deep twigs.easm's own package nesting goes.
SSL_AUDIT_PATH = os.path.dirname(os.path.realpath(ssl_audit.__file__)) + '/ssl_audit/testssl.sh'


def _cert_expiry_issue(cert, asset_id, host, port):
    """Always reports a finding on certificate expiry, with severity graduated
    by how close the certificate is to (or past) its expiry date."""
    not_after = cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days

    remediation = ("Renew the certificate before it expires to avoid service disruption, browser trust warnings and failed client connections. "
                   "Consider enabling automated renewal (e.g. via ACME/Let's Encrypt or your CA's auto-renew capability, or a certificate-expiry monitoring alert) to prevent this from recurring.")

    if days_left < 0:
        title = "SSL certificate expired on port [%s]" % port
        detail = ("The SSL/TLS certificate for [%s:%s] expired [%s] day(s) ago, on [%s]. An expired certificate causes browser/client trust "
                   "warnings or outright connection failures for users and integrations, and often indicates a lapsed or broken automated renewal process.") % (host, port, abs(days_left), not_after)
        rating = RATING_CRITICAL
    elif days_left <= 7:
        title = "SSL certificate expires imminently on port [%s]" % port
        detail = ("The SSL/TLS certificate for [%s:%s] expires in [%s] day(s), on [%s]. Expiry is imminent; unless renewal is already in progress, "
                   "clients will very soon start seeing certificate trust errors or connection failures.") % (host, port, days_left, not_after)
        rating = RATING_CRITICAL
    elif days_left <= 30:
        title = "SSL certificate expiring soon on port [%s]" % port
        detail = ("The SSL/TLS certificate for [%s:%s] expires in [%s] day(s), on [%s]. Certificates nearing expiry should be renewed promptly "
                   "to avoid service disruption.") % (host, port, days_left, not_after)
        rating = RATING_HIGH
    elif days_left <= 60:
        title = "SSL certificate expiring within 60 days on port [%s]" % port
        detail = ("The SSL/TLS certificate for [%s:%s] expires in [%s] day(s), on [%s]. It is not yet urgent, but renewal should be scheduled.") % (host, port, days_left, not_after)
        rating = RATING_MEDIUM
    elif days_left <= 90:
        title = "SSL certificate expiring within 90 days on port [%s]" % port
        detail = ("The SSL/TLS certificate for [%s:%s] expires in [%s] day(s), on [%s]. No immediate action is required, but this is worth tracking.") % (host, port, days_left, not_after)
        rating = RATING_LOW
    else:
        title = "SSL certificate validity is healthy on port [%s]" % port
        detail = ("The SSL/TLS certificate for [%s:%s] is valid for [%s] more day(s), expiring on [%s]. No action is required at this time.") % (host, port, days_left, not_after)
        rating = RATING_INFO
        remediation = None

    return [_new_issue('ssl-cert-expiry-%s' % port, title, detail, rating, asset_id, ISSUE_TYPE_SSL,
                        object_id=host, remediation=remediation)]


def check_ssl_port(host, port, asset_id):
    issues = []
    if not HAVE_CRYPTOGRAPHY:
        return issues
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der = None
    proto = None
    cipher = None
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(True)
                proto = ssock.version()
                cipher = ssock.cipher()
    except Exception as e:
        logging.debug("SSL handshake failed for [%s:%s]: %s", host, port, str(e))
        return issues

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:
        logging.debug("Unable to parse certificate for [%s:%s]: %s", host, port, str(e))
        return issues

    issues.extend(_cert_expiry_issue(cert, asset_id, host, port))

    problems = []

    self_signed = cert.issuer == cert.subject
    if self_signed:
        problems.append(_new_issue('ssl-self-signed-%s' % port, "Self-signed SSL certificate on port [%s]" % port,
                                    "The SSL/TLS certificate presented on [%s:%s] is self-signed (subject == issuer), meaning it was not issued by a trusted public Certificate Authority. Browsers and clients will show trust warnings or reject the connection outright." % (host, port),
                                    RATING_MEDIUM, asset_id, ISSUE_TYPE_SSL, object_id=host,
                                    remediation="Replace the self-signed certificate with one issued by a publicly trusted Certificate Authority (e.g. Let's Encrypt, DigiCert, Sectigo) for any internet-facing service, especially if it serves end-user traffic."))

    try:
        pubkey = cert.public_key()
        key_size = pubkey.key_size
        is_ec = isinstance(pubkey, ec.EllipticCurvePublicKey)
        min_size = 224 if is_ec else 2048
        if key_size < min_size:
            problems.append(_new_issue('ssl-weak-key-%s' % port, "Weak SSL certificate key size on port [%s]" % port,
                                        "The SSL/TLS certificate on [%s:%s] uses a [%s] bit %s key, below the recommended minimum of [%s] bits. Weaker keys are more susceptible to being broken via cryptanalysis or brute force, undermining confidentiality of the connection." % (host, port, key_size, 'EC' if is_ec else 'RSA/DSA', min_size),
                                        RATING_HIGH, asset_id, ISSUE_TYPE_SSL, object_id=host,
                                        remediation="Reissue the certificate with a stronger key: RSA >= 2048 bits (3072/4096 preferred) or ECDSA using the P-256 curve or stronger."))
    except Exception:
        pass

    sig_algo = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else '').lower()
    if sig_algo in ('md5', 'sha1'):
        problems.append(_new_issue('ssl-weak-sig-%s' % port, "Weak SSL certificate signature algorithm on port [%s]" % port,
                                    "The SSL/TLS certificate on [%s:%s] is signed using [%s], which is cryptographically weak and vulnerable to collision attacks that could allow certificate forgery." % (host, port, sig_algo),
                                    RATING_HIGH, asset_id, ISSUE_TYPE_SSL, object_id=host,
                                    remediation="Reissue the certificate using a modern signing algorithm such as SHA-256 or stronger, which is supported by all current CAs."))

    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []
    if sans and not any(_hostname_matches(host, san) for san in sans):
        problems.append(_new_issue('ssl-hostname-mismatch-%s' % port, "SSL certificate hostname mismatch on port [%s]" % port,
                                    "The SSL/TLS certificate on [%s:%s] does not list [%s] in its Subject Alternative Names %s. Clients connecting to this hostname will see a certificate name-mismatch warning, which trains users to click through security warnings and can be abused for phishing/MITM." % (host, port, host, sans),
                                    RATING_MEDIUM, asset_id, ISSUE_TYPE_SSL, object_id=host,
                                    remediation="Reissue the certificate with the correct hostname(s) included in the Subject Alternative Name (SAN) list, or correct DNS/load-balancer configuration so this hostname is served by the correct certificate."))

    weak_protocols = []
    for tls_version in ('SSLv3', 'TLSv1', 'TLSv1_1'):
        if not hasattr(ssl.TLSVersion, tls_version):
            continue
        try:
            wctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            wctx.check_hostname = False
            wctx.verify_mode = ssl.CERT_NONE
            version_enum = getattr(ssl.TLSVersion, tls_version)
            wctx.minimum_version = version_enum
            wctx.maximum_version = version_enum
            with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
                with wctx.wrap_socket(sock, server_hostname=host):
                    weak_protocols.append(tls_version.replace('_', '.'))
        except Exception:
            continue
    if weak_protocols:
        problems.append(_new_issue('ssl-weak-protocol-%s' % port, "Deprecated SSL/TLS protocol(s) supported on port [%s]" % port,
                                    "The host [%s:%s] accepts connections using deprecated/insecure protocol(s): %s. These older protocols have known cryptographic weaknesses (e.g. POODLE, BEAST) and are disallowed by PCI-DSS and most modern compliance frameworks." % (host, port, ', '.join(weak_protocols)),
                                    RATING_HIGH, asset_id, ISSUE_TYPE_SSL, object_id=host,
                                    remediation="Disable support for SSLv3/TLS 1.0/TLS 1.1 in the server's TLS configuration and enforce TLS 1.2 or higher (TLS 1.3 preferred)."))

    issues.extend(problems)

    issuer_cn = _rdn_value(cert.issuer, 'commonName') or str(cert.issuer)
    subject_cn = _rdn_value(cert.subject, 'commonName') or str(cert.subject)
    issues.append(_new_issue('ssl-cert-info-%s' % port, "SSL certificate details for port [%s]" % port,
                              "Subject [%s], Issuer [%s], Expires [%s], Negotiated protocol [%s], Negotiated cipher [%s]. This entry is informational and summarizes the certificate/connection observed during this scan." % (
                                  subject_cn, issuer_cn, cert.not_valid_after, proto, cipher[0] if cipher else 'unknown'),
                              RATING_INFO, asset_id, ISSUE_TYPE_SSL, object_id=host))

    if not problems:
        issues.append(_new_issue('ssl-no-issues-%s' % port, "No SSL/TLS configuration issues detected on port [%s]" % port,
                                  "The certificate on [%s:%s] is not self-signed, uses an adequately sized key and modern signature algorithm, matches the requested hostname, and the server did not accept connections using deprecated SSL/TLS protocols. See the certificate expiry finding above for renewal timing." % (host, port),
                                  RATING_INFO, asset_id, ISSUE_TYPE_SSL, object_id=host))
    return issues


def _rdn_value(name, attr):
    try:
        oid = getattr(x509.oid.NameOID, re.sub('([a-z])([A-Z])', r'\1_\2', attr).upper())
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else None
    except Exception:
        return None


def _hostname_matches(hostname, pattern):
    hostname = hostname.lower()
    pattern = pattern.lower()
    if pattern.startswith('*.'):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count('.') == pattern.count('.')
    return hostname == pattern


def _get_tls_candidate_ports(host_result):
    tls_ports = set(TLS_PORT_HINTS)
    if not host_result:
        return [443]
    for p in host_result['ports']:
        svc = (p['service'] or '').lower()
        if p['port'] in TLS_PORT_HINTS or 'ssl' in svc or 'https' in svc or svc.endswith('s'):
            tls_ports.add(p['port'])
    open_ports = set(p['port'] for p in host_result['ports'])
    return sorted(set([p for p in tls_ports if p in open_ports] or [443]))


def check_ssl(host, host_result, asset_id):
    issues = []
    for port in _get_tls_candidate_ports(host_result):
        issues.extend(check_ssl_port(host, port, asset_id))
    return issues


def check_ssl_vulnerabilities(host, host_result, asset_id, timeout):
    """Runs the vendored testssl.sh (via ssl_audit.run_ssl_audit, in -U/
    vulnerable-only mode) against each candidate TLS port to test for named
    SSL/TLS vulnerabilities (Heartbleed, POODLE, FREAK, Logjam, DROWN, ROBOT,
    BEAST, CRIME, etc.) and weak/NULL/export ciphers - coverage that
    check_ssl_port() above does not attempt. -U skips the much slower full
    cipher/protocol/header enumeration a default testssl.sh run performs.
    ssl_audit.run_ssl_audit() is called with an explicit timeout, which makes
    it run testssl.sh in its own process group and kill the actual
    testssl.sh/openssl process (not just abandon a Python thread) if it runs
    over - a plain thread-based timeout wrapper cannot do this, since the
    interpreter won't exit until an abandoned thread's blocking call returns."""
    issues = []
    if not (os.path.exists(SSL_AUDIT_PATH) and os.access(SSL_AUDIT_PATH, os.X_OK)):
        logging.debug("testssl.sh not found/executable at [%s] - skipping SSL vulnerability scan", SSL_AUDIT_PATH)
        return issues
    for port in _get_tls_candidate_ports(host_result):
        url = "https://%s" % host if port == 443 else "https://%s:%s" % (host, port)
        try:
            issues.extend(ssl_audit.run_ssl_audit(url, asset_id, timeout=timeout, vulnerable_only=True))
        except Exception as e:
            logging.debug("SSL vulnerability scan (testssl.sh) against [%s] failed: %s", url, str(e))
    return issues
