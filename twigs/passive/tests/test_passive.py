"""Tests for twigs passive discovery.

    python3 -m unittest twigs.passive.tests.test_passive -v

test_logs_* run from the Zeek logs saved in tests/zeek_logs and need no
Zeek. test_pcap_* run Zeek over tests/pcaps/hospital_synthetic.pcap and are
skipped when Zeek is not installed.
"""

import argparse
import glob
import json
import os
import shutil
import tempfile
import unittest

from twigs.passive import discovery
from twigs.passive.zeek_runner import Zeek, ZeekError

HERE = os.path.dirname(os.path.abspath(__file__))
PCAP = os.path.join(HERE, 'pcaps', 'hospital_synthetic.pcap')
LOGS = os.path.join(HERE, 'zeek_logs')

# id -> (category, device_class, vendor, firmware or None, confidence)
EXPECTED = {
    '44:4b:5d:00:10:21': ('medical', 'CT Scanner', 'GE Healthcare', None, 'HIGH'),
    '88:4b:39:00:10:22': ('medical', 'Ultrasound', 'Siemens Healthineers', None, 'HIGH'),
    'ec:f4:bb:00:10:50': ('medical', 'PACS / DICOM Archive', None, None, 'HIGH'),
    '00:b0:94:00:20:31': ('medical', 'Infusion Pump', 'BD', '9.33.1', 'HIGH'),
    '00:09:5c:00:20:40': ('medical', 'Patient Monitor', 'Philips', None, 'HIGH'),
    '00:0d:d1:00:20:45': ('medical', 'Surgical System', 'Stryker', None, 'HIGH'),
    '00:06:6b:00:50:11': ('medical', 'Hematology Analyzer', 'Sysmex', None, 'HIGH'),
    '10.20.0.15': ('medical', 'Patient Monitor', 'Philips', None, 'HIGH'),
    'ec:f4:bb:00:20:80': ('medical', 'Medication Dispensing', 'BD', None, None),
    '00:11:00:00:60:10': ('ot', 'PLC', 'Schneider Electric', 'v3.20', 'HIGH'),
    '00:30:de:00:80:15': ('ot', 'PLC', 'WAGO', None, None),
    '00:10:8d:00:30:20': ('building', 'Building Controller', 'Johnson Controls', '12.0.1.11', 'HIGH'),
    '00:c0:b7:00:70:05': ('building', 'UPS / PDU', 'APC (Schneider Electric)', '6.9.6', 'HIGH'),
    'b8:a4:4f:11:22:33': ('iot', 'IP Camera', 'Axis', None, 'HIGH'),
}
NOT_REPORTED = ['ec:f4:bb:00:11:00']          # ordinary Windows workstation
NOT_REPORTED += ['10.20.0.%d' % i for i in range(10, 17) if i != 15]   # remote hosts behind the router
PATIENT_DATA = ['TEST^PATIENT', 'TEST123', 'TEST456', '19700101', 'WBC']


def make_args(**kw):
    p = argparse.ArgumentParser()
    p.add_argument('--handle', default='tester@example.invalid')
    discovery.add_arguments(p)
    argv = []
    for k, v in kw.items():
        argv.append('--' + k)
        argv.extend(v if isinstance(v, list) else [v])
    return p.parse_args(argv)


def by_id(assets):
    return {a['id']: a for a in assets}


def tag(asset, name):
    for t in asset['tags']:
        if t.startswith(name + ':'):
            return t.split(':', 1)[1]
    return None


class Checks(object):
    def check_assets(self, assets):
        found = by_id(assets)
        for aid, (cat, cls, vendor, fw, conf) in EXPECTED.items():
            self.assertIn(aid, found, "device %s not reported" % aid)
            a = found[aid]
            self.assertEqual(tag(a, 'CATEGORY').lower(), cat, aid)
            self.assertEqual(tag(a, 'DEVICE_CLASS'), cls, aid)
            if vendor:
                self.assertEqual(tag(a, 'VENDOR'), vendor, aid)
            if fw:
                self.assertEqual(tag(a, 'FIRMWARE'), fw, aid)
            if conf:
                self.assertEqual(tag(a, 'CONFIDENCE'), conf, aid)
            self.assertIn('DISCOVERY_TYPE:Passive', a['tags'])
            self.assertEqual(a['type'], 'Device')
            self.assertEqual(a['attack_surface_label'], 'Corporate::Network::Device')
        for aid in NOT_REPORTED:
            self.assertNotIn(aid, found, "%s should not be reported" % aid)
        # The router MAC must never become a device identity.
        self.assertNotIn('cc:46:d6:00:00:01', found)

    def check_details(self, assets):
        found = by_id(assets)
        pacs = found['ec:f4:bb:00:10:50']
        self.assertIn('dcmtk 3.6.6', pacs['products'])
        titles = {i['twc_title'] for a in assets for i in a.get('config_issues', [])}
        self.assertIn('Telnet in use', titles)
        self.assertIn('DICOM in use', titles)
        self.assertIn('SNMP v1 in use', titles)
        ups = found['00:c0:b7:00:70:05']
        self.assertEqual(ups['name'], 'UPS-ICU-A')
        self.assertEqual(found['00:b0:94:00:20:31']['name'], 'ALARIS-PC-0042')
        self.assertEqual(found['ec:f4:bb:00:20:80']['name'], 'PYXIS-MED01')


class TestFromLogs(unittest.TestCase, Checks):
    def setUp(self):
        if not glob.glob(os.path.join(LOGS, '*.log')):
            self.skipTest("no saved Zeek logs in %s" % LOGS)

    def test_logs_identification(self):
        self.check_assets(discovery.get_inventory(make_args(zeek_logs=[LOGS])))

    def test_logs_details(self):
        self.check_details(discovery.get_inventory(make_args(zeek_logs=[LOGS])))

    def test_logs_filters(self):
        assets = discovery.get_inventory(make_args(zeek_logs=[LOGS], categories=['ot'], min_confidence='high'))
        self.assertTrue(assets)
        for a in assets:
            self.assertEqual(tag(a, 'CATEGORY'), 'OT')
            self.assertEqual(tag(a, 'CONFIDENCE'), 'HIGH')

    def test_logs_registry(self):
        d = tempfile.mkdtemp()
        try:
            reg = os.path.join(d, 'registry.csv')
            with open(reg, 'w') as fh:
                fh.write('match,vendor,model,device_class,category,location,asset_tag\n'
                         'ALARIS-PC-0042,BD,Alaris 8015,Infusion Pump,medical,ICU Bed 4,BME-0042\n')
            a = by_id(discovery.get_inventory(make_args(zeek_logs=[LOGS], asset_registry=reg)))['00:b0:94:00:20:31']
            self.assertEqual(tag(a, 'ASSET_TAG'), 'BME-0042')
            self.assertEqual(tag(a, 'LOCATION'), 'ICU Bed 4')
        finally:
            shutil.rmtree(d)


class TestOptions(unittest.TestCase):
    def validate(self, argv, schedule=None):
        p = argparse.ArgumentParser()
        discovery.add_arguments(p)
        args = p.parse_args(argv)
        args.schedule = schedule
        discovery._validate(args)

    def test_duration_and_continuous_are_exclusive(self):
        p = argparse.ArgumentParser()
        discovery.add_arguments(p)
        with self.assertRaises(SystemExit):
            p.parse_args(['--interface', 'eth1', '--continuous', '--duration', '1h'])

    def test_live_options_need_interface(self):
        for argv in (['--pcap', 'x', '--continuous'], ['--pcap', 'x', '--duration', '1h'],
                     ['--zeek_logs', 'd', '--report_interval', '1h']):
            with self.assertRaises(ValueError):
                self.validate(argv)

    def test_report_interval(self):
        with self.assertRaises(ValueError):
            self.validate(['--interface', 'eth1', '--report_interval', '1h'])     # needs --continuous
        with self.assertRaises(ValueError):
            self.validate(['--interface', 'eth1', '--continuous', '--report_interval', '30s'])
        self.validate(['--interface', 'eth1', '--continuous', '--report_interval', '15m'])

    def test_continuous_not_scheduled(self):
        with self.assertRaises(ValueError):
            self.validate(['--interface', 'eth1', '--continuous'], schedule='0 * * * *')
        self.validate(['--interface', 'eth1', '--duration', '4h'], schedule='0 */4 * * *')

    def test_parse_duration(self):
        self.assertEqual(discovery.parse_duration('90'), 90)
        self.assertEqual(discovery.parse_duration('30m'), 1800)
        self.assertEqual(discovery.parse_duration('2h'), 7200)
        self.assertEqual(discovery.parse_duration('1d'), 86400)
        with self.assertRaises(ValueError):
            discovery.parse_duration('soon')


class TestFromPcap(unittest.TestCase, Checks):
    @classmethod
    def setUpClass(cls):
        try:
            Zeek()
        except ZeekError as e:
            raise unittest.SkipTest(str(e))
        cls.keep = tempfile.mkdtemp()
        cls.assets = discovery.get_inventory(make_args(pcap=[PCAP], keep_logs=cls.keep))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keep, ignore_errors=True)

    def test_pcap_identification(self):
        self.check_assets(self.assets)

    def test_pcap_details(self):
        self.check_details(self.assets)

    def test_pcap_no_patient_data_in_logs(self):
        for path in glob.glob(os.path.join(self.keep, '*', '*', '*.log')):
            with open(path, errors='replace') as fh:
                content = fh.read()
            for marker in PATIENT_DATA:
                self.assertNotIn(marker, content, "%s found in %s" % (marker, path))

    def test_pcap_no_parser_errors(self):
        for path in glob.glob(os.path.join(self.keep, '*', '*', 'analyzer.log')):
            with open(path) as fh:
                for line in fh:
                    rec = json.loads(line)
                    self.assertNotIn('TWIGS', (rec.get('analyzer_name') or '').upper(), rec)


if __name__ == '__main__':
    unittest.main()
