"""Classify devices from passive evidence and turn them into twigs assets."""

import csv
import glob
import logging
import os
import re
from collections import defaultdict

import yaml

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
SIGNATURE_DIR = os.path.join(PKG_DIR, 'signatures')
DATA_DIR = os.path.join(PKG_DIR, 'data')

# Weight of one matching evidence field (see README.md).
FIELD_WEIGHTS = {
    'mac_vendor': 20, 'hostname': 30, 'dhcp_vendor_class': 40, 'dhcp_prl': 25,
    'http_server': 45, 'http_user_agent': 45, 'snmp_sysdescr': 60, 'snmp_sysobjectid': 60,
    'snmp_sysname': 30, 'snmp_trap_enterprise': 50, 'mdns': 35, 'ssdp': 35, 'wsd': 35,
    'nbns_name': 30, 'tls_subject': 40, 'mqtt_client_id': 35, 'hl7_app': 65,
    'hl7_receiver_app': 40, 'dicom_impl': 60, 'dicom_ae': 30, 'software': 40, 'bacnet': 55,
    'modbus_ident': 65, 'enip': 65, 's7': 40,
}

CATEGORIES = {
    'medical': ('Medical', 'Medical Device', 'CLINICAL_DEVICE'),
    'ot': ('OT', 'Industrial Device', 'OT_DEVICE'),
    'building': ('Building', 'Building Automation Device', 'BUILDING_DEVICE'),
    'iot': ('IoT', 'IoT Device', 'IOT_DEVICE'),
}
CONFIDENCE_LEVELS = [(60, 'HIGH'), (30, 'MEDIUM'), (1, 'LOW')]
# Category, device class and vendor are carried in the tags (CATEGORY:, DEVICE_CLASS:, VENDOR:).
ASSET_TYPE = 'Device'
ATTACK_SURFACE_LABEL = 'Corporate::Network::Device'
EXACT_SOURCES = ('registry', 'enip-identity', 'modbus-identity', 'bacnet-identity')
WINDOWS_NAMES = {
    (5, 0): 'Windows 2000', (5, 1): 'Windows XP', (5, 2): 'Windows XP x64 / Server 2003',
    (6, 0): 'Windows Vista / Server 2008', (6, 1): 'Windows 7 / Server 2008 R2',
    (6, 2): 'Windows 8 / Server 2012', (6, 3): 'Windows 8.1 / Server 2012 R2',
    (10, 0): 'Windows 10 / 11 / Server 2016+',
}


def _load_yaml(path):
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _compile(pattern, where):
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        logging.warning("Invalid regex %r in %s: %s", pattern, where, e)
        return None


class Rule(object):
    def __init__(self, d, category, source):
        self.id = d.get('id') or 'unnamed'
        self.category = d.get('category') or category
        self.vendor = d.get('vendor') or ''
        self.model = d.get('model') or ''
        self.device_class = d.get('device_class') or ''
        self.scale = float(d.get('weight_scale', 1.0))
        self.match = {}
        for field, pattern in (d.get('match') or {}).items():
            if field not in FIELD_WEIGHTS:
                logging.warning("Unknown match field %r in rule %s (%s)", field, self.id, source)
                continue
            patterns = pattern if isinstance(pattern, list) else [pattern]
            compiled = [c for c in (_compile(p, source) for p in patterns) if c is not None]
            if compiled:
                self.match[field] = compiled
        self.firmware = [c for c in (_compile(p, source) for p in (d.get('firmware') or [])) if c is not None]


class Signatures(object):
    def __init__(self, extra_paths=None):
        self.rules = []
        files = sorted(glob.glob(os.path.join(SIGNATURE_DIR, '*.yaml')))
        for p in extra_paths or []:
            files.extend(sorted(glob.glob(os.path.join(p, '*.yaml'))) if os.path.isdir(p) else [p])
        for f in files:
            d = _load_yaml(f)
            category = d.get('category', 'iot')
            for r in d.get('rules') or []:
                rule = Rule(r, category, f)
                if rule.category not in CATEGORIES:
                    logging.warning("Rule %s in %s has unknown category %r", rule.id, f, rule.category)
                    continue
                self.rules.append(rule)
        logging.debug("Loaded %d signature rules", len(self.rules))
        ports = _load_yaml(os.path.join(DATA_DIR, 'ports.yaml'))
        self.ports = ports.get('ports') or {}
        self.insecure_ports = ports.get('insecure_ports') or {}
        self.dicom = _load_yaml(os.path.join(DATA_DIR, 'dicom.yaml'))
        self.tcp_profiles = _load_yaml(os.path.join(DATA_DIR, 'tcp_stack.yaml')).get('profiles') or []


class Registry(object):
    """Optional customer asset registry (CSV): known serial numbers, hostnames, MACs.

    Columns: match, vendor, model, device_class, category, location, asset_tag
    'match' is a case-insensitive substring looked for in every identity
    string, the MAC address and the IP addresses of a device.
    """

    def __init__(self, path):
        self.entries = []
        if not path:
            return
        with open(path, newline='') as fh:
            for row in csv.DictReader(fh):
                m = (row.get('match') or '').strip()
                if m:
                    self.entries.append(dict((k, (v or '').strip()) for k, v in row.items()) )
        logging.info("Loaded %d asset registry entries from %s", len(self.entries), path)

    def find(self, texts):
        hay = [t.lower() for t in texts]
        for e in self.entries:
            needle = e['match'].lower()
            if any(needle in t for t in hay):
                return e
        return None


# How each kind of evidence is named in the logs ("identified via ...").
EVIDENCE_NAMES = {
    'mac_vendor': 'MAC vendor', 'hostname': 'hostname', 'dhcp_vendor_class': 'DHCP vendor class',
    'dhcp_prl': 'DHCP options', 'http_server': 'HTTP server', 'http_user_agent': 'HTTP user agent',
    'snmp_sysdescr': 'SNMP', 'snmp_sysobjectid': 'SNMP', 'snmp_sysname': 'SNMP', 'snmp_trap_enterprise': 'SNMP trap',
    'mdns': 'mDNS', 'ssdp': 'SSDP', 'wsd': 'WS-Discovery', 'nbns_name': 'NetBIOS', 'tls_subject': 'TLS certificate',
    'mqtt_client_id': 'MQTT', 'hl7_app': 'HL7', 'hl7_receiver_app': 'HL7', 'dicom_impl': 'DICOM', 'dicom_ae': 'DICOM',
    'software': 'software banner', 'bacnet': 'BACnet', 'modbus_ident': 'Modbus identification',
    'enip': 'EtherNet/IP identity', 's7': 'S7comm',
    'enip-identity': 'EtherNet/IP identity', 'modbus-identity': 'Modbus identification',
    'bacnet-identity': 'BACnet', 's7comm': 'S7comm', 'dnp3': 'DNP3', 'dicom-sop': 'DICOM', 'dicom-role': 'DICOM',
    'dicom': 'DICOM', 'hl7': 'HL7', 'registry': 'asset registry',
}


class Finding(object):
    def __init__(self, source, category, score, vendor='', model='', device_class='', firmware='', detail='',
                 fields=None):
        self.source, self.category, self.score = source, category, score
        self.vendor, self.model, self.device_class = vendor or '', model or '', device_class or ''
        self.firmware, self.detail = firmware or '', detail
        self.fields = fields or []          # evidence fields a signature rule matched

    def evidence(self):
        """Human readable names of the evidence behind this finding."""
        if self.fields:
            return [EVIDENCE_NAMES.get(f, f) for f in self.fields]
        if self.source.startswith('port:'):
            return ['port %s' % self.source[5:]]
        if self.source.startswith('client:'):
            return ['%s' % self.detail]
        return [EVIDENCE_NAMES.get(self.source, self.source)]


def identified_via(findings, category):
    """Evidence names for a device, strongest first, without duplicates."""
    names = []
    for f in sorted((f for f in findings if f.category == category), key=lambda f: -f.score):
        for n in f.evidence():
            if n not in names:
                names.append(n)
    return names


def _initial_ttl(ttl):
    for t in (32, 64, 128, 255):
        if ttl <= t:
            return t
    return 255


def _clean_product(*parts):
    s = ' '.join(p for p in parts if p).lower()
    s = re.sub(r'[^a-z0-9.\-_/+ ]', ' ', s)
    return re.sub(r'\s+', ' ', s).strip()


class Classifier(object):
    def __init__(self, signatures, oui, registry=None):
        self.sig = signatures
        self.oui = oui
        self.registry = registry or Registry(None)

    # ------------------------------------------------------------ findings
    def _rule_findings(self, h):
        out = []
        for rule in self.sig.rules:
            matched = {}
            for field, patterns in rule.match.items():
                for text in h.evidence.get(field, ()):
                    if any(p.search(text) for p in patterns):
                        matched.setdefault(field, []).append(text)
            if not matched:
                continue
            score = int(sum(FIELD_WEIGHTS[f] for f in matched) * rule.scale)
            firmware = ''
            for p in rule.firmware:
                for texts in matched.values():
                    for t in texts:
                        m = p.search(t)
                        if m and m.groups() and m.group(1):
                            firmware = m.group(1)
                            break
                    if firmware:
                        break
                if firmware:
                    break
            vendor = rule.vendor or next(iter(h.evidence.get('mac_vendor', [])), '')
            detail = '; '.join('%s=%s' % (f, sorted(v)[0][:80]) for f, v in sorted(matched.items()))
            out.append(Finding('rule:' + rule.id, rule.category, score, vendor, rule.model,
                               rule.device_class, firmware, detail,
                               sorted(matched, key=lambda f: -FIELD_WEIGHTS[f])))
        return out

    def _protocol_findings(self, h):
        out = []
        bacnet = defaultdict(str)
        modbus = defaultdict(str)
        for ident in h.identities:
            proto = ident.get('protocol')
            if proto == 'BACnet':
                for k, v in ident.items():
                    if v and k != 'protocol':
                        bacnet[k] = bacnet[k] or str(v)
            elif proto == 'Modbus':
                for k, v in ident.items():
                    if v and k != 'protocol':
                        modbus[k] = modbus[k] or str(v)
            elif proto == 'EtherNet/IP':
                out.append(Finding('enip-identity', 'ot', 65, ident.get('vendor'), ident.get('product_name'),
                                   ident.get('device_type') or 'Industrial Device', ident.get('revision'),
                                   'serial=%s' % ident.get('serial')))
        if bacnet:
            out.append(Finding('bacnet-identity', 'building', 55, bacnet.get('vendor-name') or bacnet.get('vendor'),
                               bacnet.get('model-name') or bacnet.get('object-name'), 'Building Controller',
                               bacnet.get('firmware-revision') or bacnet.get('application-software-version'),
                               'instance=%s' % bacnet.get('instance')))
        if modbus:
            out.append(Finding('modbus-identity', 'ot', 65, modbus.get('VendorName'),
                               modbus.get('ModelName') or modbus.get('ProductName') or modbus.get('ProductCode'),
                               'Industrial Device', modbus.get('MajorMinorVersion')))
        if 'S7comm' in h.protocols:
            out.append(Finding('s7comm', 'ot', 40, 'Siemens', 'SIMATIC S7', 'PLC'))
        if 'DNP3' in h.protocols:
            out.append(Finding('dnp3', 'ot', 40, '', '', 'RTU / Outstation'))
        out.extend(self._dicom_findings(h))
        if h.evidence.get('hl7_app'):
            out.append(Finding('hl7', 'medical', 25, '', '', 'Clinical System',
                               detail='; '.join(sorted(h.evidence['hl7_app'])[:3])))
        return out

    def _dicom_findings(self, h):
        out = []
        d = self.sig.dicom
        classes = defaultdict(int)
        for sop in h.dicom['requester_sops']:
            c = (d.get('requester_sop_classes') or {}).get(sop)
            if c:
                classes[c] += 1
        acceptor_classes = defaultdict(int)
        for sop in h.dicom['acceptor_sops']:
            c = (d.get('acceptor_sop_classes') or {}).get(sop)
            if c:
                acceptor_classes[c] += 1
            elif sop.startswith('1.2.840.10008.5.1.4.1.1.'):
                # Accepting image storage from modalities: archive / PACS.
                # This is the defining role of a PACS, so it outweighs the
                # worklist or query services it may also offer.
                acceptor_classes['PACS / DICOM Archive'] += 10
        vendor = ''
        for uid, ver in h.dicom['impl']:
            for root, info in (d.get('impl_uid_roots') or {}).items():
                if uid == root or uid.startswith(root + '.'):
                    vendor = vendor or info.get('vendor', '')
        if classes:
            best = sorted(classes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            # A specific modality outranks the generic "Imaging Modality".
            specific = [c for c in classes if c != 'Imaging Modality']
            if specific:
                best = sorted(specific, key=lambda c: -classes[c])[0]
            out.append(Finding('dicom-sop', 'medical', 50, vendor, '', best,
                               detail='requested SOP classes: %d' % len(h.dicom['requester_sops'])))
        if acceptor_classes:
            best = sorted(acceptor_classes.items(), key=lambda kv: -kv[1])[0][0]
            out.append(Finding('dicom-role', 'medical', 40, vendor, '', best))
        if 'DICOM' in h.protocols and not classes and not acceptor_classes:
            out.append(Finding('dicom', 'medical', 30, vendor, '', 'DICOM Node'))
        return out

    def _port_findings(self, h):
        out = []
        for p in sorted(h.server_ports):
            info = self.sig.ports.get(p)
            if info:
                out.append(Finding('port:' + p, info['category'], int(info.get('weight', 10)), '', '',
                                   info.get('device_class', ''), detail=info.get('protocol', '')))
        # Clients of OT / BMS protocols are HMIs, SCADA servers or engineering stations.
        from .inventory import OT_CLIENT_PORTS
        for p in sorted(h.client_ports):
            if p in OT_CLIENT_PORTS and p not in h.server_ports:
                proto, cat = OT_CLIENT_PORTS[p]
                out.append(Finding('client:' + p, cat, 25, '', '',
                                   'HMI / SCADA Client' if cat == 'ot' else 'BMS Server / Workstation',
                                   detail='%s client' % proto))
        return out

    def _os_hint(self, h):
        if h.windows:
            major, minor, build = sorted(h.windows)[-1]
            name = WINDOWS_NAMES.get((major, minor), 'Windows %d.%d' % (major, minor))
            return '%s (build %d)' % (name, build) if build else name
        best = None
        for role, ttl, win, wscale, mss in sorted(h.tcp_fp):
            ittl = _initial_ttl(ttl)
            for prof in self.sig.tcp_profiles:
                if prof['initial_ttl'] != ittl or prof['window'] != win:
                    continue
                if 'win_scale' in prof and prof['win_scale'] != wscale:
                    continue
                best = prof['os']
                break
            if best:
                break
        return best or ''

    # -------------------------------------------------------------- devices
    def classify(self, h):
        mac_vendor = self.oui.lookup(h.mac) if h.mac else None
        if mac_vendor:
            h.add('mac_vendor', mac_vendor)
        findings = self._rule_findings(h) + self._protocol_findings(h) + self._port_findings(h)

        texts = [t for vals in h.evidence.values() for t in vals] + list(h.ips) + ([h.mac] if h.mac else [])
        reg = self.registry.find(texts)
        if reg:
            findings.append(Finding('registry', reg.get('category') or 'medical', 80, reg.get('vendor'),
                                    reg.get('model'), reg.get('device_class'), detail='registry match %s' % reg['match']))
        if not findings:
            return None

        totals = defaultdict(int)
        for f in findings:
            totals[f.category] += f.score
        category = max(totals.items(), key=lambda kv: (kv[1], kv[0] == 'medical'))[0]
        in_cat = sorted((f for f in findings if f.category == category), key=lambda f: -f.score)
        vendor_f = next((f for f in in_cat if f.vendor), None)
        vendor = vendor_f.vendor if vendor_f else (mac_vendor or '')
        # Exact product names reported by the device itself (EtherNet/IP, Modbus
        # device identification, BACnet model-name) or the customer registry
        # beat the generic model text of signature rules.
        exact = [f for f in in_cat if f.source in EXACT_SOURCES and f.model]
        model = exact[0].model if exact else \
            next((f.model for f in in_cat if f.model and (not vendor_f or f.vendor in ('', vendor))), '')
        # DICOM SOP classes give the most specific imaging device class.
        dicom_cls = next((f.device_class for f in in_cat if f.source == 'dicom-sop'), None)
        device_class = dicom_cls or next((f.device_class for f in in_cat if f.device_class), '') \
            or CATEGORIES[category][1]
        firmware = next((f.firmware for f in in_cat if f.firmware), '')
        score = min(100, totals[category])
        level = next(l for t, l in CONFIDENCE_LEVELS if score >= t)
        return {
            'category': category, 'device_class': device_class, 'vendor': vendor, 'model': model,
            'firmware': firmware, 'score': score, 'confidence': level, 'mac_vendor': mac_vendor or '',
            'os': self._os_hint(h), 'registry': reg, 'findings': findings,
        }

    def to_asset(self, h, c, args):
        cat_label, _, cat_tag = CATEGORIES[c['category']]
        ip = sorted(h.ips, key=lambda a: (':' in a, a))[0] if h.ips else ''
        asset_id = h.mac or ip
        name = None
        for src in ('dhcp', 'netbios', 'snmp', 'mdns'):
            if h.hostnames.get(src):
                name = sorted(h.hostnames[src], key=len)[0]
                break
        if not name:
            label = ' '.join(p for p in (c['vendor'], c['device_class']) if p)
            name = '%s (%s)' % (label, ip or asset_id) if label else (ip or asset_id)

        products = []
        # Without a version a vendor / model product is too vague to match
        # vulnerabilities, so it is only reported with firmware.
        if c['vendor'] and c['model'] and c['firmware']:
            products.append(_clean_product(c['vendor'], c['model'], c['firmware']))
        for sw, ver in sorted(h.software):
            products.append(_clean_product(sw, ver))
        for uid, ver in sorted(h.dicom['impl']):
            for item in self.sig.dicom.get('impl_version_names') or []:
                m = re.match(item['pattern'], ver or '', re.IGNORECASE)
                if m:
                    v = re.sub(r'\\(\d)', lambda g: m.group(int(g.group(1))), item['version'])
                    products.append(_clean_product(item['software'], v))
        for major, minor, build in sorted(h.windows):
            products.append('microsoft windows %d.%d' % (major, minor))
        products = [p for p in dict.fromkeys(products) if p]

        tags = ['DISCOVERY_TYPE:Passive', cat_tag, 'CATEGORY:%s' % cat_label,
                'DEVICE_CLASS:%s' % c['device_class'], 'CONFIDENCE:%s' % c['confidence']]
        if c['vendor']:
            tags.append('VENDOR:%s' % c['vendor'])
        if c['model']:
            tags.append('MODEL:%s' % c['model'])
        if c['firmware']:
            tags.append('FIRMWARE:%s' % c['firmware'])
        if c['os']:
            tags.append('OS:%s' % c['os'])
        for a in sorted(h.ips):
            tags.append('IP:%s' % a)
        if h.mac:
            tags.append('MAC:%s' % h.mac)
        for p in sorted(h.protocols):
            tags.append('PROTOCOL:%s' % p)
        reg = c.get('registry')
        if reg:
            for k, t in (('asset_tag', 'ASSET_TAG'), ('location', 'LOCATION')):
                if reg.get(k):
                    tags.append('%s:%s' % (t, reg[k]))

        asset = {
            'id': asset_id,
            'name': name,
            'type': ASSET_TYPE,
            'owner': args.handle,
            'products': products,
            'tags': tags,
            'attack_surface_label': ATTACK_SURFACE_LABEL,
        }
        issues = self._issues(h, c, asset_id)
        if issues:
            asset['config_issues'] = issues
        return asset

    def _issues(self, h, c, asset_id):
        issues = []

        def issue(key, title, details, rating, object_id):
            issues.append({'twc_id': 'PASSIVE_%s' % key, 'twc_title': title, 'details': details,
                           'rating': rating, 'object_id': object_id, 'asset_id': asset_id,
                           'object_meta': '', 'type': 'Passive Discovery'})

        for p in sorted(h.server_ports):
            info = self.sig.insecure_ports.get(p)
            if info:
                issue('INSECURE_%s' % p.replace('/', '_').upper(), '%s in use' % info['protocol'],
                      '%s (observed on %s).' % (info['details'], p), info['rating'], p)
        for v in sorted(h.snmp_versions):
            if v in ('1', '2c', 'v1', 'v2c', '2'):
                issue('SNMP_V%s' % v.lstrip('v').upper(), 'SNMP v%s in use' % v.lstrip('v'),
                      'The device answers SNMP v%s, which sends community strings in cleartext.' % v.lstrip('v'),
                      '2', 'udp/161')
        for major, minor, build in sorted(h.windows):
            if major < 10:
                name = WINDOWS_NAMES.get((major, minor), 'Windows %d.%d' % (major, minor))
                issue('EOL_WINDOWS', 'End-of-life Windows version',
                      'The device runs %s (build %d), which no longer receives security updates.' % (name, build),
                      '4', '%d.%d.%d' % (major, minor, build))
        return issues
