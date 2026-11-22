"""Build per-device evidence from Zeek logs.

Every log record is attributed to the IP address of the device it describes.
IP addresses are then grouped into devices using MAC addresses, taking care
not to use router MACs: on a SPAN port at a routed core every remote host
appears behind its gateway's MAC address.
"""

import copy
import ipaddress
import logging
from collections import Counter, defaultdict

from . import zeek_logs
from .oui import normalize_mac

ESTABLISHED_TCP = {'SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR'}

# Protocols where the client side is itself an OT / building asset
# (HMI, SCADA server, engineering workstation, BMS front end).
OT_CLIENT_PORTS = {
    'tcp/502': ('Modbus/TCP', 'ot'), 'tcp/44818': ('EtherNet/IP', 'ot'), 'tcp/102': ('S7comm', 'ot'),
    'tcp/20000': ('DNP3', 'ot'), 'tcp/2404': ('IEC 60870-5-104', 'ot'), 'udp/47808': ('BACnet/IP', 'building'),
    'tcp/1911': ('Niagara Fox', 'building'),
}


class Host(object):
    def __init__(self, ip):
        self.ips = {ip} if ip else set()
        self.macs = Counter()
        self.mac = None
        self.hostnames = defaultdict(set)     # source -> names
        self.evidence = defaultdict(set)      # field -> strings
        self.server_ports = set()             # "tcp/104"
        self.client_ports = set()
        self.protocols = set()
        self.tcp_fp = set()                   # (role, ttl, win, wscale, mss)
        self.identities = []                  # protocol level identities (dicts)
        self.software = set()                 # (name, version)
        self.dicom = {'requester_sops': set(), 'acceptor_sops': set(), 'impl': set()}
        self.windows = set()                  # (major, minor, build)
        self.snmp_versions = set()
        self.first_seen = None
        self.last_seen = None

    def seen(self, ts):
        if ts is None:
            return
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            return
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    def add(self, field, value):
        if value is None:
            return
        value = str(value).replace('\x00', '').strip()
        if value and value != '-':
            self.evidence[field].add(value[:400])

    def add_hostname(self, source, name):
        if not name:
            return
        name = str(name).replace('\x00', '').strip().rstrip('.')
        if name.endswith('.local'):
            name = name[:-6]
        if name and name != '-' and len(name) <= 128:
            self.hostnames[source].add(name)
            self.add('hostname', name)

    def merge(self, other):
        self.ips |= other.ips
        self.macs.update(other.macs)
        for k, v in other.hostnames.items():
            self.hostnames[k] |= v
        for k, v in other.evidence.items():
            self.evidence[k] |= v
        self.server_ports |= other.server_ports
        self.client_ports |= other.client_ports
        self.protocols |= other.protocols
        self.tcp_fp |= other.tcp_fp
        self.identities.extend(other.identities)
        self.software |= other.software
        for k in self.dicom:
            self.dicom[k] |= other.dicom[k]
        self.windows |= other.windows
        self.snmp_versions |= other.snmp_versions
        self.seen(other.first_seen)
        self.seen(other.last_seen)


def usable_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if a.is_multicast or a.is_unspecified or a.is_loopback:
        return False
    if a.version == 4 and str(a) == '255.255.255.255':
        return False
    return True


def _decode_nbns(encoded):
    """Decode a NetBIOS first-level encoded name (32 chars -> 16 bytes)."""
    if not encoded or len(encoded) < 32:
        return None
    try:
        raw = bytes(((ord(encoded[i]) - 65) << 4) | (ord(encoded[i + 1]) - 65) for i in range(0, 32, 2))
    except ValueError:
        return None
    name = raw[:15].decode('ascii', 'replace').strip()
    return name if name and name.isprintable() else None


class Inventory(object):
    def __init__(self, router_mac_threshold=3):
        self.hosts = {}                            # ip -> Host
        self.mac_hosts = {}                        # mac -> Host (MAC-only evidence, e.g. DHCP)
        self.ip_macs = defaultdict(Counter)        # ip -> mac counts
        self.dhcp_mac_ip = defaultdict(set)        # mac -> ips confirmed by DHCP
        self.router_mac_threshold = router_mac_threshold

    def host(self, ip, ts=None):
        if not usable_ip(ip):
            return None
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = Host(ip)
        h.seen(ts)
        return h

    def mac_host(self, mac):
        h = self.mac_hosts.get(mac)
        if h is None:
            h = self.mac_hosts[mac] = Host(None)
            h.macs[mac] += 1
        return h

    def observe_mac(self, ip, mac, weight=1):
        mac = normalize_mac(mac)
        if mac and usable_ip(ip):
            self.ip_macs[ip][mac] += weight

    # ------------------------------------------------------------------ logs
    def load(self, log_dirs, rotated_only=False):
        """Add the evidence from Zeek logs. Returns the list of files read.

        Can be called repeatedly (continuous capture): evidence accumulates.
        """
        handlers = [
            ('conn', self._conn), ('twigs_mac', self._mac), ('dhcp', self._dhcp), ('twigs_dhcp', self._twigs_dhcp),
            ('twigs_tcp_fp', self._tcp_fp), ('twigs_snmp', self._twigs_snmp), ('snmp', self._snmp),
            ('twigs_http', self._http), ('software', self._software), ('twigs_mdns', self._mdns),
            ('twigs_ssdp', self._ssdp), ('twigs_wsd', self._wsd), ('twigs_nbns', self._nbns),
            ('twigs_ntlm', self._ntlm), ('twigs_tls', self._tls), ('twigs_mqtt', self._mqtt),
            ('twigs_dicom', self._dicom), ('twigs_hl7', self._hl7),
            ('bacnet_discovery', self._bacnet_discovery), ('bacnet_property', self._bacnet_property),
            ('bacnet', self._bacnet), ('modbus', self._modbus),
            ('modbus_read_device_identification', self._modbus_ident),
            ('dnp3', self._dnp3), ('cip_identity', self._enip_identity), ('enip', self._enip),
            ('s7comm', self._s7comm), ('s7comm_plus', self._s7comm),
        ]
        counts = {}
        files = []
        for name, fn in handlers:
            n = 0
            for path in zeek_logs.find_logs(log_dirs, name, rotated_only):
                files.append(path)
                for rec in zeek_logs.read_log(path):
                    try:
                        fn(rec)
                        n += 1
                    except Exception as e:      # one bad record must not stop discovery
                        logging.debug("Error processing %s record: %s", name, e)
            if n:
                counts[name] = n
        if counts or not rotated_only:
            logging.info("Processed Zeek logs: %s", ', '.join('%s=%d' % kv for kv in sorted(counts.items())) or 'none')
        return files

    def _conn(self, r):
        ts, oh, rh = r.get('ts'), r.get('id.orig_h'), r.get('id.resp_h')
        proto = r.get('proto') or 'tcp'
        port = '%s/%s' % (proto, r.get('id.resp_p'))
        self.observe_mac(oh, r.get('orig_l2_addr'))
        self.observe_mac(rh, r.get('resp_l2_addr'))
        o = self.host(oh, ts)
        resp = self.host(rh, ts)
        history = r.get('history') or ''
        answered = False
        if proto == 'tcp':
            answered = r.get('conn_state') in ESTABLISHED_TCP or 'h' in history
        elif proto == 'udp':
            try:
                answered = int(r.get('resp_pkts') or 0) > 0
            except ValueError:
                answered = False
        if resp is not None and answered:
            resp.server_ports.add(port)
        if o is not None and answered:
            o.client_ports.add(port)

    def _mac(self, r):
        self.observe_mac(r.get('host'), r.get('mac'))
        self.host(r.get('host'), r.get('ts'))

    def _dhcp(self, r):
        # Zeek's dhcp.log ties the client MAC to the address the server assigned.
        mac = normalize_mac(r.get('mac'))
        ip = r.get('assigned_addr') or r.get('client_addr')
        if not mac:
            return
        if ip and usable_ip(ip):
            self.dhcp_mac_ip[mac].add(ip)
            self.observe_mac(ip, mac, 10)
        h = self.mac_host(mac)
        h.seen(r.get('ts'))
        h.add_hostname('dhcp', r.get('host_name'))
        fqdn = r.get('client_fqdn')
        if fqdn:
            h.add_hostname('dhcp', fqdn.split('.')[0])
        h.add('dhcp_vendor_class', r.get('client_software'))

    def _twigs_dhcp(self, r):
        mac = normalize_mac(r.get('mac'))
        if not mac:
            return
        ip = r.get('ip')
        if ip and usable_ip(ip):
            self.dhcp_mac_ip[mac].add(ip)
            self.observe_mac(ip, mac, 10)
        h = self.mac_host(mac)
        h.seen(r.get('ts'))
        h.add_hostname('dhcp', r.get('hostname'))
        if r.get('client_fqdn'):
            h.add_hostname('dhcp', r['client_fqdn'].split('.')[0])
        h.add('dhcp_vendor_class', r.get('vendor_class'))
        h.add('dhcp_prl', r.get('param_req_list'))

    def _tcp_fp(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is not None:
            h.tcp_fp.add((r.get('role'), int(r.get('ttl') or 0), int(r.get('win_size') or 0),
                          int(r.get('win_scale') if r.get('win_scale') is not None else -1), int(r.get('mss') or 0)))

    def _twigs_snmp(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is None:
            return
        h.add('snmp_sysdescr', r.get('sys_descr'))
        h.add('snmp_sysobjectid', r.get('sys_objectid'))
        h.add('snmp_sysname', r.get('sys_name'))
        h.add('snmp_trap_enterprise', r.get('trap_enterprise'))
        h.add_hostname('snmp', r.get('sys_name'))
        h.protocols.add('SNMP')

    def _snmp(self, r):
        # The agent is the responder; only versions are kept (never community strings).
        h = self.host(r.get('id.resp_h'), r.get('ts'))
        try:
            answered = int(r.get('get_responses') or 0) > 0
        except ValueError:
            answered = False
        if h is not None and answered and r.get('version'):
            h.snmp_versions.add(r['version'])

    def _http(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is None:
            return
        hdr = r.get('header')
        if hdr in ('server', 'x-powered-by'):
            h.add('http_server', r.get('value'))
        elif hdr == 'user-agent':
            h.add('http_user_agent', r.get('value'))

    def _software(self, r):
        stype = r.get('software_type') or ''
        if 'BROWSER' in stype:
            return
        h = self.host(r.get('host'), r.get('ts'))
        if h is None or not r.get('name'):
            return
        version = r.get('unparsed_version') or ''
        parts = [r.get('version.major'), r.get('version.minor'), r.get('version.minor2'), r.get('version.minor3')]
        parsed = '.'.join(str(p) for p in parts if p not in (None, ''))
        h.software.add((r['name'], parsed or ''))
        h.add('software', ('%s %s' % (r['name'], version)).strip())

    def _mdns(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is None:
            return
        name, value, rtype = r.get('name') or '', r.get('value') or '', r.get('rtype')
        h.add('mdns', ('%s %s' % (name, value)).strip())
        h.protocols.add('mDNS')
        if rtype == 'A' and name.endswith('.local'):
            h.add_hostname('mdns', name)
        elif rtype == 'SRV' and value:
            h.add_hostname('mdns', value.split(':')[0])

    def _ssdp(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is not None:
            h.add('ssdp', ' '.join(r.get(k) or '' for k in ('server', 'st', 'usn', 'location')))
            h.protocols.add('SSDP')

    def _wsd(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is not None:
            h.add('wsd', ' '.join(r.get(k) or '' for k in ('types', 'scopes', 'xaddrs')))
            h.protocols.add('WS-Discovery')

    def _nbns(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        name = _decode_nbns(r.get('encoded_name'))
        if h is not None and name:
            h.add('nbns_name', name)
            h.add_hostname('netbios', name)

    def _ntlm(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is None:
            return
        if r.get('os_major') is not None:
            h.windows.add((int(r['os_major']), int(r.get('os_minor') or 0), int(r.get('os_build') or 0)))
        h.add_hostname('netbios', r.get('nb_computer'))

    def _tls(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is not None:
            h.add('tls_subject', ' '.join(r.get(k) or '' for k in ('subject', 'issuer', 'san_dns')))

    def _mqtt(self, r):
        h = self.host(r.get('host'), r.get('ts'))
        if h is not None:
            h.add('mqtt_client_id', r.get('client_id'))
            h.add('mqtt_client_id', r.get('will_topic'))
            h.protocols.add('MQTT')

    def _dicom(self, r):
        ts = r.get('ts')
        req, acc = self.host(r.get('requester'), ts), self.host(r.get('acceptor'), ts)
        sender = req if r.get('pdu') == 'request' else acc
        for h in (req, acc):
            if h is not None:
                h.protocols.add('DICOM')
        if req is not None:
            req.add('dicom_ae', r.get('calling_ae'))
        if acc is not None:
            acc.add('dicom_ae', r.get('called_ae'))
        if sender is not None:
            uid, ver = r.get('impl_class_uid') or '', r.get('impl_version') or ''
            sender.add('dicom_impl', uid)
            sender.add('dicom_impl', ver)
            sender.dicom['impl'].add((uid, ver))
        sops = r.get('abstract_syntaxes') or []
        if isinstance(sops, str):
            sops = [s for s in sops.split(',') if s]
        if r.get('pdu') == 'request':
            if req is not None:
                req.dicom['requester_sops'].update(sops)
            if acc is not None:
                acc.dicom['acceptor_sops'].update(sops)

    def _hl7(self, r):
        ts = r.get('ts')
        s, rcv = self.host(r.get('sender'), ts), self.host(r.get('receiver'), ts)
        if s is not None:
            s.protocols.add('HL7')
            s.add('hl7_app', ' '.join(r.get(k) or '' for k in ('sending_app', 'sending_facility')))
        if rcv is not None:
            rcv.protocols.add('HL7')
            rcv.add('hl7_receiver_app', ' '.join(r.get(k) or '' for k in ('receiving_app', 'receiving_facility')))

    # ------------------------------------------------------------- ICS / BMS
    def _bacnet_discovery(self, r):
        if (r.get('pdu_service') or '').lower() not in ('i-am', 'i_am', 'i-have', 'i_have'):
            return
        h = self.host(r.get('source_h'), r.get('ts'))
        if h is None:
            return
        h.protocols.add('BACnet')
        h.add('bacnet', r.get('vendor'))
        h.add('bacnet', r.get('object_name'))
        h.identities.append({'protocol': 'BACnet', 'vendor': r.get('vendor'),
                             'instance': r.get('device_id_number')})

    def _bacnet_property(self, r):
        svc = (r.get('pdu_service') or '').lower()
        if 'ack' not in svc:
            return
        h = self.host(r.get('source_h'), r.get('ts'))
        if h is None:
            return
        prop = (r.get('property') or '').lower().replace('_', '-')
        value = r.get('value')
        if prop in ('vendor-name', 'model-name', 'firmware-revision', 'application-software-version',
                    'object-name', 'description') and value:
            h.protocols.add('BACnet')
            h.add('bacnet', value)
            h.identities.append({'protocol': 'BACnet', prop: value})

    def _bacnet(self, r):
        # Any APDU sent from UDP 47808 to a unicast address marks a BACnet device.
        if str(r.get('source_p')) == '47808' and r.get('is_orig') in (False, 'F', 'false'):
            h = self.host(r.get('source_h'), r.get('ts'))
            if h is not None:
                h.protocols.add('BACnet')

    def _modbus(self, r):
        h = self.host(r.get('id.resp_h'), r.get('ts'))
        if h is not None:
            h.protocols.add('Modbus')

    def _modbus_ident(self, r):
        if r.get('request_response') != 'RESPONSE':
            return
        h = self.host(r.get('source_h'), r.get('ts'))
        if h is None or not r.get('object_value'):
            return
        h.protocols.add('Modbus')
        h.add('modbus_ident', r.get('object_value'))
        h.identities.append({'protocol': 'Modbus', (r.get('object_id') or 'value'): r.get('object_value')})

    def _dnp3(self, r):
        h = self.host(r.get('id.resp_h'), r.get('ts'))
        if h is not None:
            h.protocols.add('DNP3')

    def _enip_identity(self, r):
        ip = r.get('socket_address')
        if not ip or not usable_ip(ip) or ip.startswith('0.'):
            ip = r.get('source_h') or r.get('id.resp_h')
        h = self.host(ip, r.get('ts'))
        if h is None:
            return
        h.protocols.add('EtherNet/IP')
        for k in ('vendor_name', 'product_name', 'device_type_name'):
            h.add('enip', r.get(k))
        h.identities.append({'protocol': 'EtherNet/IP', 'vendor': r.get('vendor_name'),
                             'product_name': r.get('product_name'), 'revision': r.get('revision'),
                             'serial': r.get('serial_number'), 'device_type': r.get('device_type_name')})

    def _enip(self, r):
        h = self.host(r.get('id.resp_h'), r.get('ts'))
        if h is not None:
            h.protocols.add('EtherNet/IP')

    def _s7comm(self, r):
        h = self.host(r.get('id.resp_h'), r.get('ts'))
        if h is not None:
            h.protocols.add('S7comm')
            h.add('s7', 'S7comm')

    # -------------------------------------------------------------- devices
    def devices(self):
        """Group IPs into devices by MAC address and return the list of Hosts.

        Works on copies, so it can be called again after more logs are loaded.
        """
        hosts = copy.deepcopy(self.hosts)
        mac_hosts = copy.deepcopy(self.mac_hosts)
        mac_ips = defaultdict(set)
        for ip, macs in self.ip_macs.items():
            for mac in macs:
                if ipaddress.ip_address(ip).version == 4:
                    mac_ips[mac].add(ip)
        routers = {m for m, ips in mac_ips.items()
                   if len(ips - self.dhcp_mac_ip.get(m, set())) > self.router_mac_threshold}
        if routers:
            logging.info("Ignoring %d router / gateway MAC address(es) seen with many IPs", len(routers))

        by_mac = {}
        devices = []
        for ip, h in sorted(hosts.items()):
            mac = None
            dhcp_macs = [m for m, ips in self.dhcp_mac_ip.items() if ip in ips]
            if dhcp_macs:
                mac = dhcp_macs[0]
            else:
                for m, _ in self.ip_macs.get(ip, Counter()).most_common():
                    if m not in routers:
                        mac = m
                        break
            if mac is None:
                devices.append(h)
                continue
            h.mac = mac
            h.macs[mac] += 1
            if mac in by_mac:
                by_mac[mac].merge(h)
            else:
                by_mac[mac] = h
                devices.append(h)
        # MAC-level evidence (DHCP) joins the device using that MAC, or stands alone.
        for mac, mh in mac_hosts.items():
            if mac in routers:
                continue
            if mac in by_mac:
                by_mac[mac].merge(mh)
            else:
                # Known from DHCP only so far: use the address DHCP gave it.
                mh.mac = mac
                mh.ips |= {ip for ip in self.dhcp_mac_ip.get(mac, ()) if usable_ip(ip)}
                devices.append(mh)
        return devices
