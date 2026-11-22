#!/usr/bin/env python3
"""Generate the synthetic hospital capture used by the passive discovery tests.

Run as root inside a disposable container (it captures on the loopback
interface):

    apt-get install -y python3-pip tcpdump
    pip install scapy pynetdicom
    python3 make_test_pcaps.py <output dir>

DICOM associations are produced by a real DICOM toolkit (pynetdicom) and
captured, so the DICOM parser is tested against bytes it did not create.
Everything else is crafted with scapy. All names and identifiers are
synthetic; the HL7 PID segment contains an obviously fake patient that the
tests check never appears in any log.
"""

import os
import random
import subprocess
import sys
import time

from scapy.all import (BOOTP, DHCP, DNS, DNSRR, DNSQR, IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap)
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING

BASE = 1795000000.0
random.seed(7)

DEVICES = {
    # ip: (mac, description)
    '10.10.1.21': ('44:4b:5d:00:10:21', 'GE CT scanner (DICOM SCU)'),
    '10.10.1.22': ('88:4b:39:00:10:22', 'Siemens ultrasound (DICOM SCU)'),
    '10.10.1.50': ('ec:f4:bb:00:10:50', 'PACS (DICOM SCP, dcmtk)'),
    '10.10.1.100': ('ec:f4:bb:00:11:00', 'Windows workstation (not a target)'),
    '10.10.2.31': ('00:b0:94:00:20:31', 'BD Alaris infusion pump (DHCP)'),
    '10.10.2.40': ('00:09:5c:00:20:40', 'Philips IntelliVue monitor (DHCP, data export)'),
    '10.10.2.60': ('ec:f4:bb:00:20:60', 'Central station'),
    '10.10.2.45': ('00:0d:d1:00:20:45', 'Stryker SDC (HTTP)'),
    '10.10.2.70': ('ec:f4:bb:00:20:70', 'Nurse workstation'),
    '10.10.2.80': ('ec:f4:bb:00:20:80', 'Pyxis station (NetBIOS)'),
    '10.10.2.1': ('00:13:e8:00:20:01', 'DHCP server'),
    '10.10.3.5': ('00:13:e8:00:30:05', 'BMS server'),
    '10.10.3.20': ('00:10:8d:00:30:20', 'Johnson Controls NAE (BACnet)'),
    '10.10.4.40': ('b8:a4:4f:11:22:33', 'Axis camera (mDNS, SSDP, WSD)'),
    '10.10.5.2': ('00:13:e8:00:50:02', 'LIS (HL7 receiver)'),
    '10.10.5.11': ('00:06:6b:00:50:11', 'Sysmex analyzer (HL7 sender)'),
    '10.10.6.5': ('00:13:e8:00:60:05', 'HMI (Modbus master)'),
    '10.10.6.10': ('00:11:00:00:60:10', 'Schneider PLC (Modbus 43/14, Telnet)'),
    '10.10.7.2': ('00:13:e8:00:70:02', 'NMS'),
    '10.10.7.5': ('00:c0:b7:00:70:05', 'APC UPS (SNMP v1)'),
    '10.10.8.2': ('00:13:e8:00:80:02', 'MQTT broker'),
    '10.10.8.15': ('00:30:de:00:80:15', 'WAGO controller (MQTT client)'),
}
ROUTER_MAC = 'cc:46:d6:00:00:01'          # remote subnets appear behind this MAC
REMOTE = ['10.20.0.%d' % i for i in range(10, 17)]
REMOTE_MONITOR = '10.20.0.15'             # Philips central sending HL7 via the router

t = [BASE]


def ts(step=0.01):
    t[0] += step
    return t[0]


def mac(ip):
    return DEVICES[ip][0] if ip in DEVICES else ROUTER_MAC


def stamp(pkt, step=0.01):
    pkt.time = ts(step)
    return pkt


def tcp_session(cip, sip, sport, dport, exchanges, server_answers=True):
    """Handshake, payload exchange and close. exchanges: [('c'|'s', bytes)]."""
    pkts = []
    cs, ss = random.randint(1000, 1 << 30), random.randint(1000, 1 << 30)

    def p(src, dst, sp, dp, flags, seq, ack, payload=b''):
        pkt = Ether(src=mac(src), dst=mac(dst)) / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
        if payload:
            pkt = pkt / Raw(payload)
        return stamp(pkt)

    pkts.append(p(cip, sip, sport, dport, 'S', cs, 0))
    if not server_answers:
        return pkts
    pkts.append(p(sip, cip, dport, sport, 'SA', ss, cs + 1))
    cs += 1
    ss += 1
    pkts.append(p(cip, sip, sport, dport, 'A', cs, ss))
    for who, data in exchanges:
        if who == 'c':
            pkts.append(p(cip, sip, sport, dport, 'PA', cs, ss, data))
            cs += len(data)
            pkts.append(p(sip, cip, dport, sport, 'A', ss, cs))
        else:
            pkts.append(p(sip, cip, dport, sport, 'PA', ss, cs, data))
            ss += len(data)
            pkts.append(p(cip, sip, sport, dport, 'A', cs, ss))
    pkts.append(p(cip, sip, sport, dport, 'FA', cs, ss))
    pkts.append(p(sip, cip, dport, sport, 'FA', ss, cs + 1))
    pkts.append(p(cip, sip, sport, dport, 'A', cs + 1, ss + 1))
    return pkts


def udp(src, dst, sport, dport, payload, dst_mac=None):
    return stamp(Ether(src=mac(src), dst=dst_mac or mac(dst)) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload)


# ----------------------------------------------------------------- DICOM
def capture_dicom(raw_path):
    from pynetdicom import AE, StoragePresentationContexts
    from pynetdicom.sop_class import (CTImageStorage, ModalityWorklistInformationFind,
                                      UltrasoundImageStorage, Verification)
    tcpdump = subprocess.Popen(['tcpdump', '-i', 'lo', '-U', '-w', raw_path, 'tcp port 104 or tcp port 11112'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    scp = AE(ae_title='PACS01')
    scp.implementation_class_uid = '1.2.276.0.7230010.3.0.3.6.6'
    scp.implementation_version_name = 'OFFIS_DCMTK_366'
    scp.supported_contexts = StoragePresentationContexts
    scp.add_supported_context(Verification)
    scp.add_supported_context(ModalityWorklistInformationFind)
    servers = [scp.start_server(('127.0.0.2', 104), block=False),
               scp.start_server(('127.0.0.2', 11112), block=False)]
    for ae_title, uid, ver, src, port, sops in (
            ('CT_SCANNER1', '1.2.840.113619.6.374', 'GE_REVOLUTION_1', '127.0.0.3', 104,
             [CTImageStorage, ModalityWorklistInformationFind, Verification]),
            ('US_SEQUOIA2', '1.3.12.2.1107.5.99.3', 'SIEMENS_US_VB30', '127.0.0.4', 11112,
             [UltrasoundImageStorage, Verification])):
        ae = AE(ae_title=ae_title)
        ae.implementation_class_uid = uid
        ae.implementation_version_name = ver
        for s in sops:
            ae.add_requested_context(s)
        assoc = ae.associate('127.0.0.2', port, ae_title='PACS01', bind_address=(src, 0))
        if not assoc.is_established:
            raise SystemExit("DICOM association from %s failed" % ae_title)
        assoc.send_c_echo()
        assoc.release()
    time.sleep(1)
    for s in servers:
        s.shutdown()
    time.sleep(1)
    tcpdump.terminate()
    tcpdump.wait()


def dicom_packets(raw_path):
    ipmap = {'127.0.0.2': '10.10.1.50', '127.0.0.3': '10.10.1.21', '127.0.0.4': '10.10.1.22'}
    out = []
    for pkt in rdpcap(raw_path):
        if IP not in pkt:
            continue
        ip = pkt[IP]
        ip.src, ip.dst = ipmap[ip.src], ipmap[ip.dst]
        del ip.chksum
        del ip[TCP].chksum
        new = Ether(src=mac(ip.src), dst=mac(ip.dst)) / ip
        out.append(stamp(new, 0.001))
    return out


# ----------------------------------------------------------- other traffic
def dhcp_packets():
    pkts = []
    for ip, host, vclass, prl in (
            ('10.10.2.31', 'ALARIS-PC-0042', 'AlarisPump/9.33.1', [1, 3, 6, 15, 28, 43]),
            ('10.10.2.40', 'MX800-BED12', 'PHILIPS IntelliVue MX800', [1, 3, 6, 12, 15, 28, 43, 60])):
        m = mac(ip)
        chaddr = bytes.fromhex(m.replace(':', '')) + b'\x00' * 10
        xid = random.randint(1, 1 << 31)
        opts = [('hostname', host), ('vendor_class_id', vclass), ('param_req_list', prl)]
        pkts.append(stamp(Ether(src=m, dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255') /
                          UDP(sport=68, dport=67) / BOOTP(chaddr=chaddr, xid=xid) /
                          DHCP(options=[('message-type', 'discover')] + opts + ['end'])))
        pkts.append(stamp(Ether(src=mac('10.10.2.1'), dst=m) / IP(src='10.10.2.1', dst=ip) /
                          UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=ip, chaddr=chaddr, xid=xid) /
                          DHCP(options=[('message-type', 'offer'), ('server_id', '10.10.2.1'), 'end'])))
        pkts.append(stamp(Ether(src=m, dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255') /
                          UDP(sport=68, dport=67) / BOOTP(chaddr=chaddr, xid=xid) /
                          DHCP(options=[('message-type', 'request'), ('requested_addr', ip), ('server_id', '10.10.2.1')] + opts + ['end'])))
        pkts.append(stamp(Ether(src=mac('10.10.2.1'), dst=m) / IP(src='10.10.2.1', dst=ip) /
                          UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=ip, chaddr=chaddr, xid=xid) /
                          DHCP(options=[('message-type', 'ack'), ('server_id', '10.10.2.1'), ('lease_time', 86400), 'end'])))
    # IntelliVue data export: the central station polls the monitor on UDP 24105.
    pkts.append(udp('10.10.2.60', '10.10.2.40', 40000, 24105, Raw(b'\x00\x01assoc-req')))
    pkts.append(udp('10.10.2.40', '10.10.2.60', 24105, 40000, Raw(b'\x00\x02assoc-resp')))
    # The pump talks to its server once it has an address.
    pkts += tcp_session('10.10.2.31', '10.10.2.60', 50311, 443, [('c', b'\x16\x03\x01\x00\x05hello')])
    return pkts


def hl7_packets():
    msg = (b'\x0bMSH|^~\\&|XN-550|SYSMEX|LIS|LAB|20261122101500||ORU^R01|MSG0001|P|2.5.1\r'
           b'PID|1||TEST123||TEST^PATIENT||19700101|U\r'
           b'OBX|1|NM|WBC||6.1|10*3/uL|||||F\r\x1c\r')
    ack = (b'\x0bMSH|^~\\&|LIS|LAB|XN-550|SYSMEX|20261122101501||ACK^R01|ACK0001|P|2.5.1\r'
           b'MSA|AA|MSG0001\r\x1c\r')
    pkts = tcp_session('10.10.5.11', '10.10.5.2', 50011, 2575, [('c', msg), ('s', ack)])
    remote = (b'\x0bMSH|^~\\&|IntelliVue PIIC|Philips|EMR|HOSP|20261122101600||ORU^R01|MSG0002|P|2.6\r'
              b'PID|1||TEST456||TEST^PATIENT||19700101|U\r\x1c\r')
    pkts += tcp_session(REMOTE_MONITOR, '10.10.5.2', 50015, 2575, [('c', remote), ('s', ack)])
    return pkts


def router_packets():
    # Hosts in another subnet all appear with the router's MAC on this segment.
    pkts = []
    for i, ip in enumerate(REMOTE):
        pkts += tcp_session(ip, '10.10.1.50', 51000 + i, 80, [('c', b'GET / HTTP/1.1\r\nHost: pacs\r\n\r\n')])
    return pkts


def http_packets():
    resp = b'HTTP/1.1 200 OK\r\nServer: Stryker SDC HD/2.3.1\r\nContent-Length: 2\r\n\r\nok'
    pkts = tcp_session('10.10.2.70', '10.10.2.45', 50070, 80,
                       [('c', b'GET /status HTTP/1.1\r\nHost: 10.10.2.45\r\n\r\n'), ('s', resp)])
    # Ordinary workstation browsing: must not be reported.
    pkts += tcp_session('10.10.1.100', '10.10.1.50', 50100, 80,
                        [('c', b'GET / HTTP/1.1\r\nHost: pacs\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n'),
                         ('s', b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\n\r\nok')])
    return pkts


def nbns_packets():
    name = b'PYXIS-MED01'.ljust(15) + b'\x00'
    enc = b''.join(bytes([65 + (b >> 4), 65 + (b & 0x0f)]) for b in name)
    body = (b'\x81\x01' + b'\x29\x10' + b'\x00\x01\x00\x00\x00\x00\x00\x01' + b'\x20' + enc + b'\x00' +
            b'\x00\x20\x00\x01' + b'\xc0\x0c\x00\x20\x00\x01\x00\x04\x93\xe0\x00\x06\x00\x00' +
            bytes(int(x) for x in '10.10.2.80'.split('.')))
    return [udp('10.10.2.80', '10.10.2.255', 137, 137, Raw(body), dst_mac='ff:ff:ff:ff:ff:ff')]


def bacnet_packets():
    dev = '10.10.3.20'
    pkts = []
    i_am = (b'\x01\x00' + b'\x10\x00' + b'\xc4\x02\x00\x00\x65' + b'\x22\x05\xc4' + b'\x91\x00' + b'\x21\x05')
    pkts.append(udp(dev, '10.10.3.255', 47808, 47808, Raw(b'\x81\x0b' + (4 + len(i_am)).to_bytes(2, 'big') + i_am),
                    dst_mac='ff:ff:ff:ff:ff:ff'))

    def charstring(s):
        data = b'\x00' + s.encode()
        return (bytes([0x70 | len(data)]) if len(data) <= 4 else b'\x75' + bytes([len(data)])) + data

    for invoke, prop, value in ((1, 0x46, 'NAE5510-1'), (2, 0x79, 'Johnson Controls, Inc.'),
                                (3, 0x2c, '12.0.1.11')):
        req = b'\x01\x04' + b'\x00\x05' + bytes([invoke]) + b'\x0c' + b'\x0c\x02\x00\x00\x65' + b'\x19' + bytes([prop])
        ack = (b'\x01\x00' + b'\x30' + bytes([invoke]) + b'\x0c' + b'\x0c\x02\x00\x00\x65' + b'\x19' + bytes([prop]) +
               b'\x3e' + charstring(value) + b'\x3f')
        pkts.append(udp('10.10.3.5', dev, 47808, 47808, Raw(b'\x81\x0a' + (4 + len(req)).to_bytes(2, 'big') + req)))
        pkts.append(udp(dev, '10.10.3.5', 47808, 47808, Raw(b'\x81\x0a' + (4 + len(ack)).to_bytes(2, 'big') + ack)))
    return pkts


def modbus_packets():
    def mbap(tid, unit, pdu):
        return tid.to_bytes(2, 'big') + b'\x00\x00' + (len(pdu) + 1).to_bytes(2, 'big') + bytes([unit]) + pdu

    objects = [(0, b'Schneider Electric'), (1, b'BMX P34 2020'), (2, b'v3.20')]
    resp_pdu = b'\x2b\x0e\x01\x01\x00\x00' + bytes([len(objects)]) + b''.join(
        bytes([oid, len(v)]) + v for oid, v in objects)
    exch = [('c', mbap(1, 1, b'\x2b\x0e\x01\x00')), ('s', mbap(1, 1, resp_pdu)),
            ('c', mbap(2, 1, b'\x03\x00\x00\x00\x02')), ('s', mbap(2, 1, b'\x03\x04\x00\x0a\x00\x0b'))]
    pkts = tcp_session('10.10.6.5', '10.10.6.10', 50502, 502, exch)
    pkts += tcp_session('10.10.6.5', '10.10.6.10', 50023, 23, [('s', b'\xff\xfd\x18Schneider Telnet\r\nlogin: ')])
    return pkts


def snmp_packets():
    oids = ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.5.0']
    req = SNMP(version=0, community='public', PDU=SNMPget(id=7, varbindlist=[SNMPvarbind(oid=ASN1_OID(o)) for o in oids]))
    resp = SNMP(version=0, community='public', PDU=SNMPresponse(id=7, varbindlist=[
        SNMPvarbind(oid=ASN1_OID(oids[0]), value=ASN1_STRING(
            b'APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin AF1:v6.9.6 AN1:apc_hw05_sumx_696.bin MN:AP9630 HR:05 SN: ZA1234567890 MD:01/01/2020)')),
        SNMPvarbind(oid=ASN1_OID(oids[1]), value=ASN1_OID('1.3.6.1.4.1.318.1.3.27')),
        SNMPvarbind(oid=ASN1_OID(oids[2]), value=ASN1_STRING(b'UPS-ICU-A'))]))
    return [udp('10.10.7.2', '10.10.7.5', 40161, 161, req), udp('10.10.7.5', '10.10.7.2', 161, 40161, resp)]


def camera_packets():
    cam = '10.10.4.40'
    pkts = []
    inst = 'AXIS P3245-LV - B8A44F112233._axis-video._tcp.local'
    dns = DNS(id=0, qr=1, aa=1, qd=None, an=(
        DNSRR(rrname='_axis-video._tcp.local', type='PTR', rdata=inst, ttl=4500) /
        DNSRR(rrname=inst, type='TXT', rdata=[b'macaddress=B8A44F112233'], ttl=4500) /
        DNSRR(rrname='axis-b8a44f112233.local', type='A', rdata=cam, ttl=120)))
    pkts.append(udp(cam, '224.0.0.251', 5353, 5353, dns, dst_mac='01:00:5e:00:00:fb'))
    notify = (b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\n'
              b'LOCATION: http://10.10.4.40:49152/rootdesc1.xml\r\nNT: urn:axis-com:service:BasicService:1\r\n'
              b'NTS: ssdp:alive\r\nSERVER: Linux/4.14.0, UPnP/1.0, Axis P3245-LV\r\n'
              b'USN: uuid:Upnp-BasicDevice-1_0-B8A44F112233::urn:axis-com:service:BasicService:1\r\n\r\n')
    pkts.append(udp(cam, '239.255.255.250', 1900, 1900, Raw(notify), dst_mac='01:00:5e:7f:ff:fa'))
    hello = (b'<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" '
             b'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
             b'xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><SOAP-ENV:Header><wsa:Action>'
             b'http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><d:Hello>'
             b'<d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/hardware/P3245-LV '
             b'onvif://www.onvif.org/name/AXIS</d:Scopes><d:XAddrs>http://10.10.4.40/onvif/device_service</d:XAddrs>'
             b'</d:Hello></SOAP-ENV:Body></SOAP-ENV:Envelope>')
    pkts.append(udp(cam, '239.255.255.250', 3702, 3702, Raw(hello), dst_mac='01:00:5e:7f:ff:fa'))
    return pkts


def mqtt_packets():
    cid = b'wago-pfc200-line1'
    var = b'\x00\x04MQTT\x04\x02\x00\x3c' + len(cid).to_bytes(2, 'big') + cid
    connect = b'\x10' + bytes([len(var)]) + var
    return tcp_session('10.10.8.15', '10.10.8.2', 50883, 1883, [('c', connect), ('s', b'\x20\x02\x00\x00')])


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    raw = os.path.join(out_dir, 'dicom_raw.pcap')
    capture_dicom(raw)
    pkts = dhcp_packets() + dicom_packets(raw) + hl7_packets() + http_packets() + nbns_packets() + \
        bacnet_packets() + modbus_packets() + snmp_packets() + camera_packets() + mqtt_packets() + router_packets()
    os.remove(raw)
    pkts.sort(key=lambda p: float(p.time))
    out = os.path.join(out_dir, 'hospital_synthetic.pcap')
    wrpcap(out, pkts)
    print("wrote %d packets to %s" % (len(pkts), out))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
