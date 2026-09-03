"""UDP top-port exposure scan.

A curated set of UDP services that are (a) common to leave accidentally
internet-facing and (b) frequently abused as reflection/amplification DDoS
vectors: SNMP, NTP, DNS, IKE/ISAKMP, mDNS, NetBIOS, SSDP, memcached,
CLDAP, chargen/echo/qotd.

Pure-Python, response-only: each port gets a protocol-specific probe and is
counted open only when the service actually sends UDP bytes back. That
sidesteps the open|filtered ambiguity of a blind UDP scan entirely and needs
no root. Where a service answers, the response/request size ratio and
service type are used to call out amplification exposure (and the NTP monlist
and SNMP public-community cases specifically).
"""
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.message
    import dns.rdataclass
    import dns.rdatatype
    import dns.flags
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

from .constants import (RATING_INFO, RATING_LOW, RATING_MEDIUM, RATING_HIGH, RATING_CRITICAL,
                        ISSUE_TYPE_PORTS)
from .util import _new_issue, _is_ip_address, _is_ipv6

WORKERS = 12
RECV_BYTES = 8192
SOCK_TIMEOUT = 3.0

# --- probe payloads --------------------------------------------------------

def _ntp_client():
    # NTPv2, mode 3 (client). 48-byte payload.
    return b'\x1b' + b'\x00' * 47

def _ntp_monlist():
    # NTPv2 mode 7 (private), implementation NTP, request code MON_GETLIST_1.
    return b'\x17\x00\x03\x2a' + b'\x00' * 4

def _netbios_nbstat():
    # NBSTAT node-status request for the wildcard name '*'.
    header = b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00'
    encoded_name = b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
    return header + encoded_name + b'\x00\x21\x00\x01'

def _ssdp_msearch():
    return (b'M-SEARCH * HTTP/1.1\r\n'
            b'HOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\n'
            b'MX: 1\r\n'
            b'ST: ssdp:all\r\n\r\n')

# SNMPv2c GET of sysDescr.0 with community "public".
_SNMP_GET_PUBLIC = bytes.fromhex(
    '302902010104'          # SEQ; INTEGER version=1 (v2c); OCTET STRING tag+len
    '067075626c6963'        # "public"
    'a01c0204' '71727374'   # GetRequest PDU; INTEGER request-id
    '020100' '020100'       # error-status 0; error-index 0
    '300e300c'              # varbindlist; varbind
    '06082b06010201010100'  # OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    '0500')                 # NULL

# CLDAP searchRequest for the rootDSE (base "", scope base, filter
# objectClass=*, attribute list empty). Best-effort BER encoding; a server
# that does not recognise it simply stays silent (no false positive).
_CLDAP_ROOTDSE = bytes.fromhex(
    '30250201'              # LDAPMessage SEQ (len 0x25); INTEGER messageID...
    '01'                    # messageID = 1
    '6320'                  # searchRequest [APPLICATION 3], len 0x20
    '0400'                  # baseObject: OCTET STRING "" (rootDSE)
    '0a0100'               # scope: ENUMERATED baseObject
    '0a0100'               # derefAliases: ENUMERATED neverDerefAliases
    '020100'               # sizeLimit 0
    '020100'               # timeLimit 0
    '010100'               # typesOnly FALSE
    '870b6f626a656374436c617373'  # filter: [7] present "objectClass"
    '3000'                 # attributes: empty SEQUENCE
)

# IKE/ISAKMP main-mode phase-1 with a single transform (3DES / SHA-1 /
# MODP-1024 / PSK). Best-effort; response-only detection.
_IKE_MAIN_MODE = bytes.fromhex(
    '00000000000000000000000000000000'  # initiator cookie (zeroed)
    '0000000000000000'                  # responder cookie
    '01'                                # next payload: SA (1)
    '10'                                # version 1.0
    '02'                                # exchange type: Identity Protection (main mode)
    '00'                                # flags
    '00000000'                          # message ID
    '00000050'                          # total length (80)
    '0000002c'                          # SA payload: next payload none, len 0x2c
    '00000001'                          # DOI = IPSEC
    '00000001'                          # situation = SIT_IDENTITY_ONLY
    '00000020'                          # Proposal payload: next none, len 0x20
    '01'                                # proposal #1
    '01'                                # protocol ISAKMP
    '00'                                # SPI size 0
    '01'                                # 1 transform
    '00000018'                          # Transform payload: next none, len 0x18
    '01'                                # transform #1
    '01'                                # transform ID KEY_IKE
    '0000'                              # reserved
    '80010005'                          # Enc = 3DES-CBC
    '80020002'                          # Hash = SHA
    '80040002'                          # Group = MODP-1024
    '80030001'                          # Auth = PSK
)

def _dns_version_bind():
    if HAVE_DNSPYTHON:
        try:
            return dns.message.make_query('version.bind', dns.rdatatype.TXT,
                                          dns.rdataclass.CH).to_wire()
        except Exception:
            pass
    # hand-rolled CHAOS TXT query for version.bind
    return bytes.fromhex('abcd0100000100000000000007') + b'version' + bytes.fromhex('04') + b'bind' + bytes.fromhex('0000100003')

def _dns_recursion():
    if HAVE_DNSPYTHON:
        try:
            return dns.message.make_query('www.google.com', dns.rdatatype.A).to_wire()
        except Exception:
            pass
    return bytes.fromhex('abce0100000100000000000003') + b'www' + bytes.fromhex('06') + b'google' + bytes.fromhex('03') + b'com' + bytes.fromhex('0000010001')

def _mdns_services():
    if HAVE_DNSPYTHON:
        try:
            return dns.message.make_query('_services._dns-sd._udp.local',
                                          dns.rdatatype.PTR).to_wire()
        except Exception:
            pass
    return b''

def _coap_wellknown():
    # CoAP CON GET /.well-known/core  (ver 1, type CON, code 0.01 GET)
    return bytes.fromhex('40017d70') + b'\xbb' + b'.well-known' + b'\x04' + b'core'


# port -> (service, probe bytes, is_amplifier, base_rating)
_PROBES = {
    7:     ('echo',       b'\x01\x02\x03\x04\x05\x06\x07\x08', True,  RATING_HIGH),
    17:    ('qotd',       b'\x0d\x0a',                          True,  RATING_HIGH),
    19:    ('chargen',    b'\x0d\x0a',                          True,  RATING_HIGH),
    53:    ('dns',        _dns_version_bind(),                  True,  RATING_MEDIUM),
    123:   ('ntp',        _ntp_client(),                       True,  RATING_MEDIUM),
    137:   ('netbios-ns', _netbios_nbstat(),                   True,  RATING_MEDIUM),
    161:   ('snmp',       _SNMP_GET_PUBLIC,                    True,  RATING_MEDIUM),
    389:   ('cldap',      _CLDAP_ROOTDSE,                      True,  RATING_HIGH),
    500:   ('ike',        _IKE_MAIN_MODE,                      False, RATING_LOW),
    1900:  ('ssdp',       _ssdp_msearch(),                     True,  RATING_HIGH),
    5060:  ('sip',        b'OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK\r\nMax-Forwards: 0\r\nTo: <sip:nm@nm>\r\nFrom: <sip:nm@nm>;tag=r\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n', False, RATING_LOW),
    5353:  ('mdns',       _mdns_services(),                    True,  RATING_MEDIUM),
    5683:  ('coap',       _coap_wellknown(),                   True,  RATING_MEDIUM),
    11211: ('memcached',  b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n', True, RATING_CRITICAL),
}


def _send_recv(ip, port, payload, family):
    if not payload:
        return None
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(SOCK_TIMEOUT)
    try:
        s.sendto(payload, (ip, port))
        data, _ = s.recvfrom(RECV_BYTES)
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()


def _dns_answered_recursively(resp):
    if not (HAVE_DNSPYTHON and resp):
        return False
    try:
        msg = dns.message.from_wire(resp)
    except Exception:
        return False
    return bool(msg.flags & dns.flags.RA) and len(msg.answer) > 0


def check_udp_scan(host, ips, asset_id, args):
    if getattr(args, 'no_udp_scan', False):
        return []

    target = None
    family = socket.AF_INET
    if _is_ip_address(host):
        target = host
        family = socket.AF_INET6 if _is_ipv6(host) else socket.AF_INET
    else:
        for ip in (ips or []):
            if not _is_ipv6(ip):
                target = ip
                break
        if target is None and ips:
            target, family = ips[0], socket.AF_INET6
    if not target:
        return []

    ports_arg = getattr(args, 'udp_scan_ports', None)
    if ports_arg:
        wanted = {int(p) for p in str(ports_arg).replace(' ', '').split(',') if p.isdigit()}
        probes = {p: v for p, v in _PROBES.items() if p in wanted}
    else:
        probes = dict(_PROBES)

    responders = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(_send_recv, target, port, spec[1], family): port
                for port, spec in probes.items()}
        for fut in as_completed(futs):
            port = futs[fut]
            try:
                data = fut.result()
            except Exception:
                data = None
            if data:
                responders[port] = data

    issues = []
    if not responders:
        return [_new_issue(
            'udp-scan-none', "No exposed UDP services found",
            "Probed [%d] curated UDP port(s) on [%s] (%s) with protocol-specific payloads and none responded." % (len(probes), host, target),
            RATING_INFO, asset_id, ISSUE_TYPE_PORTS, object_id=target,
            remediation="No action required. This is a curated amplification-focused list, not a full 65535-port UDP scan.")]

    # --- targeted, higher-severity cases ---------------------------------
    if 11211 in responders:
        issues.append(_new_issue(
            'udp-memcached-amplifier', "memcached exposed over UDP (severe amplification vector)",
            "memcached on [%s:11211/udp] responded to an unauthenticated 'stats' request (%d bytes). UDP memcached is the reflection vector behind the largest recorded DDoS attacks (amplification factor up to ~50,000x) and exposes cached application data to anyone." % (target, len(responders[11211])),
            RATING_CRITICAL, asset_id, ISSUE_TYPE_PORTS, object_id='%s:11211' % target,
            remediation="Disable the memcached UDP listener entirely (memcached -U 0), bind it to 127.0.0.1, and firewall port 11211 from the internet. UDP support has been off by default since memcached 1.5.6 - upgrade if this install predates that."))

    if 123 in responders:
        monlist = _send_recv(target, 123, _ntp_monlist(), family)
        if monlist and len(monlist) > len(_ntp_monlist()) * 5:
            issues.append(_new_issue(
                'udp-ntp-monlist', "NTP server answers monlist (CVE-2013-5211 amplification)",
                "NTP on [%s:123/udp] answered a mode-7 monlist request with %d bytes (request was %d bytes, ~%dx amplification). monlist returns the last 600 clients and is a classic reflection/amplification DDoS vector."
                % (target, len(monlist), len(_ntp_monlist()), len(monlist) // max(len(_ntp_monlist()), 1)),
                RATING_HIGH, asset_id, ISSUE_TYPE_PORTS, object_id='%s:123' % target,
                remediation="Disable the monitor facility ('disable monitor' in ntp.conf) or restrict queries ('restrict default noquery ...'), or upgrade to ntp 4.2.7p26+ where monlist is removed. Consider chrony instead. Firewall UDP/123 from untrusted sources if this host does not need to serve public time."))
        else:
            issues.append(_new_issue(
                'udp-ntp-open', "NTP service reachable over UDP",
                "NTP on [%s:123/udp] responded to a client-mode query. monlist did not appear to be enabled. An open NTP server can still be used for modest amplification (e.g. via get/readvar) and reveals its version/config." % target,
                RATING_LOW, asset_id, ISSUE_TYPE_PORTS, object_id='%s:123' % target,
                remediation="If this host does not need to serve time to the public internet, firewall UDP/123 to trusted sources. Otherwise apply 'restrict default noquery nomodify' and keep the daemon patched."))

    if 161 in responders:
        data = responders[161]
        snippet = ''
        try:
            printable = bytes(b for b in data if 32 <= b < 127)
            snippet = printable.decode('ascii', 'replace')[:180]
        except Exception:
            pass
        issues.append(_new_issue(
            'udp-snmp-public', "SNMP readable with the default 'public' community",
            "SNMP on [%s:161/udp] answered a GET for sysDescr.0 using community string 'public' (%d-byte response). This leaks system/software inventory to anyone and is also a UDP amplification vector (GetBulk). Response text: %s"
            % (target, len(data), snippet or '(non-printable)'),
            RATING_HIGH, asset_id, ISSUE_TYPE_PORTS, object_id='%s:161' % target,
            remediation="Remove or rename the 'public' (and 'private') community, or move to SNMPv3 with authentication and privacy. Restrict UDP/161 to the monitoring system's source IPs via firewall/ACL, and bind snmpd to management interfaces only."))

    if 53 in responders:
        rec = _send_recv(target, 53, _dns_recursion(), family)
        if _dns_answered_recursively(rec):
            issues.append(_new_issue(
                'udp-open-resolver', "Open DNS resolver",
                "DNS on [%s:53/udp] recursively resolved an external name (www.google.com) for an arbitrary client. Open resolvers are heavily abused for DNS amplification DDoS and DNS cache-poisoning research." % target,
                RATING_HIGH, asset_id, ISSUE_TYPE_PORTS, object_id='%s:53' % target,
                remediation="Disable recursion on this authoritative server, or restrict recursion (allow-recursion / allow-query-cache) to your own client networks. If it must be a public resolver, deploy response-rate-limiting (RRL) and consider DNS cookies."))
        else:
            issues.append(_new_issue(
                'udp-dns-open', "DNS service reachable over UDP",
                "DNS on [%s:53/udp] responded to a query but did not recurse for an external name (authoritative-only, as expected). A version.bind response, if any, may disclose the software version." % target,
                RATING_INFO, asset_id, ISSUE_TYPE_PORTS, object_id='%s:53' % target,
                remediation="No action required beyond confirming recursion is intentionally disabled and (optionally) hiding the version.bind response."))

    # --- everything else -------------------------------------------------
    handled = {11211, 123, 161, 53}
    generic = {p: d for p, d in responders.items() if p not in handled}
    for port, data in sorted(generic.items()):
        svc, probe, is_amp, base_rating = probes[port]
        ratio = len(data) / max(len(probe), 1)
        amp_note = ''
        rating = base_rating
        if is_amp and ratio >= 3:
            amp_note = (" The response was %d bytes to a %d-byte request (~%.0fx amplification), so this service is usable as a UDP reflection/amplification DDoS vector against third parties."
                        % (len(data), len(probe), ratio))
            if rating in (RATING_INFO, RATING_LOW):
                rating = RATING_MEDIUM
        issues.append(_new_issue(
            'udp-service-%s' % svc, "UDP service exposed: %s on port %d" % (svc, port),
            "[%s:%d/udp] responded to a %s probe with %d byte(s)%s%s"
            % (target, port, svc, len(data),
               '.' if not amp_note else '', amp_note or ''),
            rating, asset_id, ISSUE_TYPE_PORTS, object_id='%s:%d' % (target, port),
            remediation="Confirm this UDP service needs to be internet-facing. If not, firewall the port to trusted source ranges. If it does, ensure it is patched, does not respond to spoofable/unauthenticated queries larger than the request, and has rate-limiting enabled."))
    return issues
