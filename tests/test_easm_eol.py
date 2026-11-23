"""Tests for twigs.easm.eol_check (end-of-life software findings)."""
import unittest
from argparse import Namespace
from datetime import date

from twigs.easm.eol_check import check_eol, match_product
from twigs.easm.nmap_discovery import parse_nmap_xml
from twigs.easm.constants import RATING_LOW, RATING_MEDIUM, RATING_HIGH, ISSUE_TYPE_EOL

TODAY = date(2026, 11, 23)
HOST = 'example.com'


def port(p, product, version=None, extrainfo=None):
    return {'port': p, 'protocol': 'tcp', 'service': None, 'product': product,
            'version': version, 'extrainfo': extrainfo, 'title': None, 'banner': None}


def run(products=(), ports=(), builds=(), os_names=(), tags=(), args=None):
    hr = {'ports': list(ports), 'windows_builds': list(builds), 'os_names': list(os_names)}
    return check_eol(HOST, list(products), list(tags), hr, HOST, args, today=TODAY)


class TestEolCheck(unittest.TestCase):

    def one(self, issues):
        self.assertEqual(len(issues), 1, [i['twc_title'] for i in issues])
        self.assertEqual(issues[0]['type'], ISSUE_TYPE_EOL)
        return issues[0]

    # --- Microsoft ----------------------------------------------------------
    def test_mssql_2012_from_banner(self):
        i = self.one(run(ports=[port(1433, 'Microsoft SQL Server 2012', '11.00.6607.00; SP3+')],
                         products=['microsoft sql server 2012', 'Microsoft SQL Server 2012 11.00.6607.00; SP3+']))
        self.assertEqual(i['rating'], RATING_HIGH)
        self.assertEqual(i['twc_id'], 'easm-eol-mssql-2012')
        self.assertEqual(i['object_id'], HOST + ':1433')
        self.assertIn('final service pack (SP4', i['details'])

    def test_mssql_build_beats_year(self):
        i = self.one(run(products=['Microsoft SQL Server 13.0.6300.2']))
        self.assertIn('SQL Server 2016', i['twc_title'])
        self.assertEqual(i['rating'], RATING_MEDIUM)   # ESU window

    def test_iis_10_is_undeterminable(self):
        self.assertEqual(run(products=['Microsoft-IIS 10.0', 'Microsoft IIS httpd 10.0']), [])

    def test_iis_85_maps_to_2012r2(self):
        i = self.one(run(products=['Microsoft-IIS 8.5']))
        self.assertEqual(i['rating'], RATING_HIGH)
        self.assertIn('Windows Server 2012 R2', i['twc_title'])

    def test_smb_range_all_eol(self):
        i = self.one(run(ports=[port(445, 'Microsoft Windows Server 2008 R2 - 2012 microsoft-ds')]))
        self.assertEqual(i['rating'], RATING_HIGH)
        self.assertIn('2008 R2', i['twc_title'])
        self.assertIn('2012', i['twc_title'])

    def test_range_with_supported_member(self):
        self.assertEqual(run(ports=[port(445, 'Microsoft Windows 7 - 10 microsoft-ds')]), [])

    def test_ntlm_build_and_smb_name_merge(self):
        i = self.one(run(builds=[{'port': 3389, 'source': 'rdp-ntlm-info', 'version': '6.3.9600'}],
                         os_names=[{'name': 'Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)',
                                    'source': 'smb-os-discovery', 'guess': False}],
                         products=['microsoft windows server 2012 r2']))
        self.assertEqual(i['rating'], RATING_HIGH)

    def test_ntlm_build_overrides_conflicting_smb_range(self):
        # real-world: nmap -sV said '2008 R2 - 2012' on 445, NTLM on 1433 said 6.3.9600
        issues = run(ports=[port(445, 'Microsoft Windows Server 2008 R2 - 2012 microsoft-ds'),
                            port(1433, 'Microsoft SQL Server 2012', '11.00.6607.00; SP3+')],
                     builds=[{'port': 1433, 'source': 'ms-sql-ntlm-info', 'version': '6.3.9600'}],
                     products=['Microsoft Windows Server 2008 R2 - 2012 microsoft-ds'])
        self.assertEqual(sorted(i['twc_id'] for i in issues),
                         ['easm-eol-mssql-2012', 'easm-eol-windows-server2012r2-81'])
        win = [i for i in issues if 'windows' in i['twc_id']][0]
        self.assertIn('Less precise evidence', win['details'])
        self.assertEqual(win['object_id'], HOST + ':1433')

    def test_server_2016_approaching(self):
        i = self.one(run(builds=[{'port': 3389, 'source': 'rdp-ntlm-info', 'version': '10.0.14393'}]))
        self.assertEqual(i['rating'], RATING_LOW)
        self.assertIn('approaching', i['twc_title'])

    def test_os_guess_capped(self):
        i = self.one(run(os_names=[{'name': 'Microsoft Windows Server 2008 R2 - 2012',
                                    'source': 'nmap OS fingerprint (96%)', 'guess': True}]))
        self.assertEqual(i['rating'], RATING_MEDIUM)

    def test_unknown_windows_ignored(self):
        self.assertEqual(run(products=['Microsoft Windows RPC', 'microsoft windows']), [])

    # --- web stack ------------------------------------------------------------
    def test_apache_22_distro_lowered(self):
        i = self.one(run(ports=[port(80, 'Apache httpd', '2.2.15', '(CentOS)')],
                         products=['Apache httpd 2.2.15', 'apache http server 2.2.15']))
        self.assertEqual(i['rating'], RATING_MEDIUM)
        self.assertIn('distribution', i['details'])

    def test_apache_24_ok(self):
        self.assertEqual(run(products=['Apache 2.4.62 (Debian)']), [])

    def test_php(self):
        self.assertEqual(self.one(run(products=['PHP 8.2.20']))['rating'], RATING_LOW)
        self.assertEqual(self.one(run(products=['PHP 7.4.3'], tags=['PHP_BUILD:7.4.3-4ubuntu2.24']))['rating'], RATING_MEDIUM)
        self.assertEqual(run(products=['PHP 8.4.1', 'phpMyAdmin 4.9.0', 'PHP']), [])
        i = self.one(run(products=['PHP 5.1.6']))
        self.assertIn('no later than', i['details'])

    def test_server_header_multiple_products(self):
        names = sorted(f for f, _, _, _ in match_product('Apache 2.2.3 (CentOS) OpenSSL 0.9.8e-fips-rhel5 PHP 5.1.6'))
        self.assertEqual(names, ['apache', 'openssl', 'php'])

    def test_nginx_capped(self):
        self.assertEqual(self.one(run(products=['nginx 1.18.0']))['rating'], RATING_MEDIUM)
        self.assertEqual(self.one(run(products=['nginx 1.18.0 (Ubuntu)']))['rating'], RATING_LOW)

    def test_tomcat(self):
        self.assertEqual(run(products=['Apache Tomcat/Coyote JSP engine 1.1']), [])
        self.assertEqual(self.one(run(products=['Apache Tomcat 8.5.32']))['rating'], RATING_HIGH)

    def test_openssl_fips(self):
        self.assertEqual(self.one(run(products=['OpenSSL 1.0.2k-fips']))['rating'], RATING_MEDIUM)

    def test_js_libraries(self):
        self.assertEqual(self.one(run(products=['jquery 1.12.4']))['rating'], RATING_MEDIUM)
        self.assertEqual(run(products=['jquery-ui 1.12.1', 'jquery 3.7.1', 'angular 17.0.1']), [])
        self.assertEqual(self.one(run(products=['angular.js 1.8.2']))['rating'], RATING_MEDIUM)

    def test_cms(self):
        self.assertEqual(self.one(run(products=['Drupal 7 (https://www.drupal.org)']))['rating'], RATING_HIGH)
        self.assertEqual(run(products=['Drupal 10 (https://www.drupal.org)']), [])

    def test_disabled(self):
        self.assertEqual(run(products=['PHP 5.6.40'], args=Namespace(no_eol_check=True)), [])

    def test_no_host_result(self):
        self.assertEqual(len(check_eol(HOST, ['PHP 5.6.40'], [], None, HOST, today=TODAY)), 1)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports>
 <port protocol="tcp" portid="3389"><state state="open"/>
  <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
  <script id="rdp-ntlm-info" output="&#xa;  Target_Name: CORP&#xa;  Product_Version: 6.1.7601&#xa;  System_Time: 2026-11-23T10:00:00+00:00"/>
 </port>
 <port protocol="tcp" portid="1433"><state state="open"/>
  <service name="ms-sql-s" product="Microsoft SQL Server 2012" version="11.00.6607.00; SP3+"><cpe>cpe:/a:microsoft:sql_server:2012</cpe></service>
 </port>
</ports>
<hostscript><script id="smb-os-discovery" output="&#xa;  OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)&#xa;  Computer name: SRV"/></hostscript>
<os><osmatch name="Microsoft Windows Server 2008 R2 - 2012" accuracy="98"><osclass osfamily="Windows" accuracy="98"/></osmatch></os>
</host></nmaprun>"""


class TestNmapParsing(unittest.TestCase):

    def test_parse_and_check(self):
        hr = parse_nmap_xml(NMAP_XML)['192.0.2.10']
        self.assertEqual(hr['windows_builds'], [{'port': 3389, 'source': 'rdp-ntlm-info', 'version': '6.1.7601'}])
        self.assertEqual([o['source'] for o in hr['os_names']], ['smb-os-discovery', 'nmap OS fingerprint (98%)'])
        issues = check_eol(HOST, list(hr['products']), [], hr, HOST, today=TODAY)
        ids = sorted(i['twc_id'] for i in issues)
        # NTLM build 7601 (2008 R2 / Windows 7), the SMB name (2008 R2) and the
        # OS guess (2008 R2 - 2012) fold into one finding on the narrowest release
        self.assertEqual(ids, ['easm-eol-mssql-2012', 'easm-eol-windows-server2008r2'], [i['twc_title'] for i in issues])
        win = [i for i in issues if 'windows' in i['twc_id']][0]
        self.assertEqual(win['rating'], RATING_HIGH)


if __name__ == '__main__':
    unittest.main()
