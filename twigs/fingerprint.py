import sys
import platform
import os
import subprocess
import logging
import psutil
import ipaddress
import socket
import json
import re
import requests
from xml.dom.minidom import parse, parseString
from distutils.version import LooseVersion
import csv
from . import linux
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

NMAP_default = "/usr/bin/nmap"
NMAP = shutil.which("nmap")

SNMPWALK = shutil.which('snmpwalk')

if NMAP is None:
    NMAP = NMAP_default
NSE_PATH = os.path.dirname(os.path.realpath(__file__)) + '/nse/'

NMAP_HTTP_PORTS = ['80','443','6443','8080','8443','2181','8000','8008','8888','5000','7001','7002','4848']
NSE_APACHE_PATH  = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/apache/'
NSE_HTTP_PATH = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/http/'
NSE_HTTP_SCRIPTS = [
    'http-generator', 'http-wordpress-enum', 'http-apache-server-status',
    'http-server-header', 'http-php-version',
    'http-title', 'http-ntlm-info', 'http-favicon',
    'http-qnap-nas-info', 'http-hp-ilo-info', 'http-trane-info',
    NSE_HTTP_PATH, NSE_APACHE_PATH,
]

NMAP_DB_PORTS = ['9200','9300','27017','27018','27019','3306','5432','7000','7001','9042','7199','523','445','1433','6379','1521','5601','11211','9092','5672','4369','5984','6984','8098','2375','2376','15672','15671','6380','1883','8883','26257']
NSE_DB_PATH  = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/database/'
NSE_DB_SCRIPTS = [NSE_DB_PATH,'mongodb-info','mysql-info','cassandra-info','db2-das-info','ms-sql-info','redis-info','oracle-tns-version','amqp-info','epmd-info','memcached-info','docker-version','riak-http-info']

NMAP_PRINTERS_PORTS = ['80','161','443','9100','U:161']
NSE_PRINTERS_PATH  = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/printers/'
NSE_PRINTERS_SCRIPTS = [NSE_PRINTERS_PATH]

NMAP_CCTV_PORTS = ['21','80','161','443','8080','8443','4321', '37777', '9000', '10554', '5985','9100','5060']
NSE_CCTV_PATH  = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/cctv/'
NSE_CCTV_SCRIPTS = [NSE_CCTV_PATH]

NMAP_OT_PORTS = ['502','102','44818','20000','1962','4840','U:47808']
NSE_OT_SCRIPTS = ['modbus-discover','s7-info','enip-info','pcworx-info','bacnet-info']

NMAP_FTP_PORTS = ['21','990']
NSE_FTP_SCRIPTS = ['ftp-syst','ftp-anon']

NMAP_EMAIL_PORTS = ['25','465','587','110','995','143','993']
NSE_EMAIL_SCRIPTS = ['smtp-commands','smtp-ntlm-info','imap-capabilities','pop3-capabilities']

NMAP_LDAP_PORTS = ['389','636','3268','3269']
NSE_LDAP_SCRIPTS = ['ldap-rootdse']

NMAP_RDP_PORTS = ['3389']
NSE_RDP_SCRIPTS = ['rdp-enum-encryption','rdp-ntlm-info']

NMAP_VNC_PORTS = ['5900','5901','5902','5903','5904','5905']
NSE_VNC_SCRIPTS = ['vnc-info']

NMAP_INFRA_PORTS = ['3000','9090','9091','8500','8501','8200','8201','8086','15672','15671','8161','9000','8081','2379','2380','50070','9870','8088','19888','4848','7474','7687','9093','3100','16686','9411','8428','8065','8001','1936','9901','5555','8222','4222','8111','8085','8123','8529','9001']
NSE_INFRA_SCRIPTS = [NSE_HTTP_PATH]

NSE_OTHER_PATH = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/other/'

def nmap_exists():
    return NMAP and os.access(NMAP, os.X_OK)

def build_snmp_walk_cmd(args, addr):
    cmd = SNMPWALK
    if args.snmp_security_name:
        cmd = cmd + ' -v3 -u '+args.snmp_security_name
    else:
        cmd = cmd + ' -v1 '
    # -t 3: 3-second timeout per retry; -r 1: 1 retry — fail fast on non-responsive hosts
    cmd = cmd + ' -t 3 -r 1 -c '+args.snmp_community + ' ' + addr
    return cmd

def get_snmp_oid_value(args, snmpwalk, oid):
    out = None
    try:
        logging.debug("snmpwalk command: " + snmpwalk + ' ' + oid)
        out = subprocess.check_output([snmpwalk+' '+oid], shell=True, timeout=15)
        out = out.decode(args.encoding)
    except subprocess.TimeoutExpired:
        logging.error("Timeout running snmpwalk command")
        return None
    except subprocess.CalledProcessError:
        logging.error("Error running snmpwalk command")
        return out
    try:
        if ':' in out:
            out = out.strip().split(':')[1].replace('"','')
        else:
            out = out.strip().split('=')[1].replace('"','')
    except Exception as e:
        logging.error("Exception processing snmp oid walk output")
        return None
    logging.debug("snmpwalk output: " + out)
    return out

def discover(args):
    handle = args.handle
    token = args.token
    instance = args.instance

    hosts = args.hosts

def get_private_ip_cidrs():
    """
    Returns a list of class A, B, or C private IP CIDRs visible on the local host.
    """
    private_cidrs = []
    for interface in psutil.net_if_addrs().values():
        for address in interface:
            if address.family == socket.AF_INET:
                ip_address = ipaddress.IPv4Address(address.address)
                if ip_address.is_private:
                    if ipaddress.IPv4Network(ip_address).is_private:
                        if ip_address.is_private and \
                                (ipaddress.IPv4Address('10.0.0.0') <= ip_address <= ipaddress.IPv4Address('10.255.255.255') or
                                ipaddress.IPv4Address('172.16.0.0') <= ip_address <= ipaddress.IPv4Address('172.31.255.255') or
                                ipaddress.IPv4Address('192.168.0.0') <= ip_address <= ipaddress.IPv4Address('192.168.255.255')):
                            private_cidrs.append(str(ipaddress.IPv4Network(ip_address).with_prefixlen))
    return private_cidrs

# get the most accurate os_class object from host xml
def get_best_os_class(host):
    best_os_class = None
    host_os_classes = host.getElementsByTagName("osclass")
    if host_os_classes is not None:
        accuracy = -1
        for host_os_class in host_os_classes:
            host_acc = host_os_class.getAttribute("accuracy")
            if host_acc == "":
                continue
            host_acc = int(host_acc)
            if host_acc >= accuracy:
                best_os_class = host_os_class
                accuracy = host_acc
    return best_os_class

# get the os name from smb-os-discovery scrip output if present
def get_smb_os(host):
    smb_os_name = None
    scripts = host.getElementsByTagName("script")
    for s in scripts:
        if s.getAttribute('id') == 'smb-os-discovery':
            elems = s.getElementsByTagName('elem')
            for elem in elems:
               if elem.getAttribute('key') == 'os':
                  smb_os_name = " ".join(t.nodeValue for t in elem.childNodes if t.nodeType == t.TEXT_NODE)
                  break
    return smb_os_name

# get the most confident os type from services section
def get_os_from_services(host):
    conf = -1
    os_type = None
    services = host.getElementsByTagName("service")
    for service in services:
        ostype = service.getAttribute("ostype")
        if ostype != "":
            if int(service.getAttribute("conf")) > conf:
                os_type = ostype
                conf = int(service.getAttribute("conf"))
    return os_type

def get_os_type(host, products):
    # check the smb output to see if this is a windows host
    if get_smb_os(host):
        logging.debug("Found os_type [Windows] from SMB")
        return 'Windows'

    # check the os class
    os_class = get_best_os_class(host)
    if os_class:
        os_type = os_class.getAttribute("osfamily")
        logging.debug("Found os_type [%s] from os class", os_type)
        return os_type

    # check os type from services
    service_os = get_os_from_services(host)
    if service_os:
        logging.debug("Found os_type [%s] from services", service_os)
        return service_os

    # guess os type from products
    for product in products:
        if 'microsoft windows' in product:
            logging.debug("Found os_type [Windows] from products")
            return 'Windows'
        if 'linux linux kernel' in product:
            logging.debug("Found os_type [Linux] from products")
            return 'Linux'

    logging.debug("Unable to determine os_type...assuming [Other]")
    return 'Other'

def is_port_open(port):
    port_state = port.getElementsByTagName("state")[0]
    if port_state is not None and port_state.getAttribute('state') == "open":
        return True
    return False

def create_open_ports_issues(ports_in_use_dict, asset_id):
    open_port_issues = []
    for key in sorted(ports_in_use_dict.keys()):
        port_details = ports_in_use_dict[key]
        issue = {}
        issue['twc_id'] = 'OPEN_PORT_' + port_details['port']
        issue['twc_title'] = "Open Port [%s] detected" % port_details['port']
        summary = "Port [%s] is open for protocol [%s] on the host" % (port_details['port'], port_details['protocol'])
        if port_details['service'] is not None:
            summary = summary + " running [%s] service" % port_details['service']
        if port_details['product'] != "":
            summary = summary + " for product [%s]" % port_details['product']
        issue['details'] = summary
        issue['rating'] = '1'
        issue['object_id'] = port_details['port']
        issue['asset_id'] = asset_id
        issue['object_meta'] = ''
        issue['type'] = 'Open Ports'
        open_port_issues.append(issue)
    return open_port_issues

def create_nmap_cmd(args):
    ports = []
    scripts = []
    os_detect = ""
    vflag = ""
    if 'default' in args.services:
        vflag = " -sV "
    if "database" in args.services:
        ports += NMAP_DB_PORTS
        scripts += NSE_DB_SCRIPTS
    if "web" in args.services:
        ports += NMAP_HTTP_PORTS
        scripts += NSE_HTTP_SCRIPTS
    if "os" in args.services:
        vflag = " -sV "
        os_detect = " -O "
        scripts += ['smb-os-discovery']
        ports += ['1-100']
        ports += NMAP_FTP_PORTS
        scripts += NSE_FTP_SCRIPTS
        ports += NMAP_EMAIL_PORTS
        scripts += NSE_EMAIL_SCRIPTS
        ports += NMAP_LDAP_PORTS
        scripts += NSE_LDAP_SCRIPTS
        ports += NMAP_RDP_PORTS
        scripts += NSE_RDP_SCRIPTS
        ports += NMAP_VNC_PORTS
        scripts += NSE_VNC_SCRIPTS
        ports += NMAP_INFRA_PORTS
        scripts += NSE_INFRA_SCRIPTS
    if "vmware" in args.services:
        scripts += ['vmware-version']
        ports += ['443']
    if "printers" in args.services:
        ports += NMAP_PRINTERS_PORTS
        scripts += NSE_PRINTERS_SCRIPTS
    if "cctv" in args.services:
        ports += NMAP_CCTV_PORTS
        scripts += NSE_CCTV_SCRIPTS
    if "ot" in args.services:
        vflag = " -sV "
        ports += NMAP_OT_PORTS
        scripts += NSE_OT_SCRIPTS
    if "snmp" in args.services:
        ports = ['161']
        vflag = " -sU "

    # Use version intensity 5 for a good accuracy/speed tradeoff
    vi_flag = " --version-intensity 5 " if vflag and '-sV' in vflag else ""

    cmd = NMAP + vflag + vi_flag + ' -Pn --open -oX - -T ' + args.timing + os_detect
    if len(ports) != 0:
        cmd += ' -p' + ','.join(list(set(ports)))
    if args.extra_ports:
        cmd += ',' + args.extra_ports
    if len(scripts) != 0:
        cmd += ' --script ' + ','.join(list(set(scripts)))
    return cmd

def nmap_scan(args, host):
    logging.info("Fingerprinting "+host)
    if os.geteuid() == 0:
        logging.info("Running nmap as root user")
    else:
        logging.info("Running nmap as non-root user")
    nmap_cmd = create_nmap_cmd(args)
    if args.verbosity >= 3:
        logging.debug('Enabled nmap debug logging...')
        nmap_cmd = nmap_cmd + ' -vvv -d --packet-trace --reason'
    elif args.verbosity == 2:
        nmap_cmd = nmap_cmd + ' -vv -d '
    cmdarr = [nmap_cmd + ' ' + host]
    try:
        logging.debug("NMAP command: " + cmdarr[0])
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Error running nmap command")
        return [] 

    logging.debug("NMAP output:\n" + out)
    dom = parseString(out)
    asset_data_list = []
    hosts = dom.getElementsByTagName("host")
    for h in hosts:
        addr = h.getElementsByTagName("address")[0]
        addr = addr.getAttribute('addr')
        hostname = addr
        harr = h.getElementsByTagName("hostname")
        if harr != None and len(harr) > 0:
            hostname = h.getElementsByTagName("hostname")[0]
            hostname = hostname.getAttribute('name')
            if hostname == 'linux':
                hostname = addr
        
        # Check for ports in use
        ports_in_use_dict = { }
        ports = h.getElementsByTagName("port")
        for port in ports:
            if not is_port_open(port):
                continue
            port_no = int(port.getAttribute('portid'))
            protocol = port.getAttribute('protocol')
            #service = port.getElementsByTagName('service')[0]
            service = port.getElementsByTagName('service')
            if service == None or len(service) == 0:
                continue
            service = service[0]
            service_product = None
            if service is not None:
                service_product = service.getAttribute('product')
                service = service.getAttribute('name')
            ports_in_use_dict[port_no] = { "port": str(port_no), "protocol": protocol, "service": service, "product": service_product}

        # SSH Port in use?
        ssh_port_is_open = True if ports_in_use_dict.get(22) is not None else False
        # HTTP(S) ports in use
        http_port_80_is_open = True if ports_in_use_dict.get(80) is not None else False
        http_port_8080_is_open = True if ports_in_use_dict.get(8080) is not None else False
        https_port_443_is_open = True if ports_in_use_dict.get(443) is not None else False
        https_port_8443_is_open = True if ports_in_use_dict.get(8443) is not None else False

        # check for cpes
        cpes = h.getElementsByTagName("cpe")
        products = []
        for c in cpes:
            # ignore cpes that are part of osclass section
            if c.parentNode.tagName == "osclass":
                continue
            cstr = c.firstChild.data
            carr = cstr.split(':')
            prodstr = carr[2] + ' ' + carr[3] + ' '
            if len(carr) >= 5:
                prodstr += carr[4]
            prodstr = prodstr.strip()
            prodstr = prodstr.replace('_',' ')
            if prodstr not in products:
                products.append(prodstr)

        ostype = get_os_type(h, products)

        # check for services
        services = h.getElementsByTagName("service")
        if services is not None:
            for s in services:
                if s.getAttribute('name') == 'snmp' and ('snmp' in args.services or 'ot' in args.services):
                    # use snmpwalk to find more
                    if not SNMPWALK:
                        logging.warn("snmpwalk command not found")
                        continue
                    # build the snmp walk command
                    cmd = build_snmp_walk_cmd(args, addr)
                    prod = get_snmp_oid_value(args, cmd, '1.3.6.1.2.1.1.1.0')
                    if prod:
                        logging.debug("SNMP sysDescr value:"+prod)
                        # handle Palo Alto Networks products
                        if 'Palo Alto Networks' in prod:
                            panosver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.25461.2.1.2.1.1')
                            prod = 'paloaltonetworks pan-os ' + panosver.strip() if panosver else 'paloaltonetworks pan-os'
                            products.append(prod)
                            ostype = 'Palo Alto Networks'
                        elif 'Juniper Networks' in prod:
                            version_regex = re.compile(r'\s([0-9A-Za-z_\-]+(\.[0-9A-Za-z_\-]+)+)')
                            m = re.findall(version_regex, prod)
                            if m and len(m) > 0:
                                junosver = 'juniper junos ' + [x[0] for x in m][0]
                                products.append(junosver)
                            parts = prod.split(',')
                            if len(parts) > 1:
                                model = parts[1].replace('Inc.','').strip()
                                if '[' in model and ']' in model:
                                    model = model.split()[1].replace('[','').replace(']','').strip()
                                else:
                                    model = model.split()[0].strip()
                                if model:
                                    products.append('juniper '+model)
                            ostype = 'Juniper'
                        elif 'Canon' in prod:
                            model = prod.split()[1].strip()
                            products.append('Canon '+model)
                            ostype = 'Canon Printer'
                        elif 'Honeywell' in prod:
                            prod = prod.replace(';',' ')
                            products.append(prod)
                            ostype = 'Honeywell Printer'
                            logging.info("Found Honeywell Printer")
                        elif 'Zebra' in prod:
                            prod = prod.split('/')[0].strip()
                            products.append(prod)
                            ostype = 'Zebra Printer'
                            logging.info("Found Zebra Printer")
                        elif 'Fortinet' in prod: 
                            fgosver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.12356.101.4.1.1')
                            if fgosver: # fortios
                                fgosver = 'fortinet fortios '+fgosver.split(',')[0].replace('v','')
                                ostype = 'Fortinet'
                                products.append(fgosver)
                                fgmodel = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.12356.100.1.1.1')
                                if fgmodel:
                                    model_regex = re.compile(r'\s([A-Za-z]+([0-9]+[A-Za-z]))')
                                    m = re.findall(model_regex, fgmodel)
                                    if m and len(m) > 0:
                                        model = 'fortinet ' + [x[0] for x in m][0]
                                        products.append(model)
                        elif 'Aruba' in prod:
                            ostype = 'Aruba'
                            words = prod.split()
                            swmodel = words[2].split('-')[0] if len(words) > 2 else ''
                            version_regex = re.compile(r'([0-9]+\.[0-9]+\.[0-9]+)')
                            aos_version = None
                            m = re.findall(version_regex, prod)
                            if m and len(m) > 0:
                                aos_version = m[0]
                            modelnum = re.sub("[^\d]", "", swmodel)
                            if modelnum and int(modelnum) < 6000:
                                if aos_version:
                                    products.append(swmodel+' arubaos-switch '+aos_version)
                                    products.append(swmodel+' firmware '+aos_version)
                            else:
                                if aos_version:
                                    products.append(swmodel+' aos-cx '+aos_version)
                        elif 'Cisco' in prod:
                            ostype = 'Cisco'
                            ver = ''
                            if 'Version' in prod:
                                ver = prod.split('Version')[1].split()[0].strip()
                                ver = ver.replace(',','')
                            os_prod = None 
                            if 'IOS' in prod:
                                if 'XE' in prod or 'IOS-XE' in prod:
                                    os_prod = 'cisco ios xe software '+ver
                                else:
                                    os_prod = 'cisco ios '+ver
                            elif 'NX-OS(tm)' in prod:
                                os_prod = 'cisco nx-os software '+ver
                                device = prod.split(',')[0]
                                if 'Nexus' in device:
                                    device = device.replace('Nexus','Nexus ')
                                    device = device.replace('NX-OS(tm)','')
                                    if len(device.split()) > 3:
                                        dlist = device.split()[:-1]
                                        device = " ".join(dlist)
                                    device = device + " series devices running nx-os software"
                                    products.append(device)
                            if os_prod:
                                os_prod = os_prod.strip()
                                products.append(os_prod)
                        elif 'Siemens' in prod:
                            prod = prod.replace(',','')
                            products.append(prod)
                            ostype = 'Siemens'
                        # --- Network security appliances ---
                        elif 'BIG-IP' in prod or ('F5' in prod and 'Networks' in prod):
                            ostype = 'F5 Networks'
                            ver = None
                            f5ver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.3375.2.1.4.2.0')
                            if f5ver:
                                m = re.search(r'([\d]+\.[\d]+[\.\d]*)', f5ver)
                                ver = m.group(1) if m else f5ver.strip()
                            if not ver:
                                m = re.search(r'BIG-IP[_\s]+v?([\d]+\.[\d]+[\.\d]*)', prod)
                                if m:
                                    ver = m.group(1)
                            prodstr = 'f5 big-ip ' + ver if ver else 'f5 big-ip'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Check Point' in prod or 'Gaia' in prod:
                            ostype = 'Check Point'
                            cpver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.2620.1.6.4.1.0')
                            if cpver:
                                prodstr = 'check point gaia ' + cpver.strip()
                            else:
                                m = re.search(r'(R[\d]+[\.\d]*)', prod)
                                prodstr = 'check point gaia ' + m.group(1) if m else 'check point gaia'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'NetScaler' in prod or 'Citrix ADC' in prod:
                            ostype = 'Citrix'
                            m = re.search(r'NS([\d]+\.[\d]+)', prod)
                            ver = m.group(1) if m else None
                            if not ver:
                                nsver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.5951.4.1.1.1.0')
                                if nsver:
                                    m2 = re.search(r'([\d]+\.[\d]+[\.\d]*)', nsver)
                                    ver = m2.group(1) if m2 else nsver.strip()
                            prodstr = 'citrix netscaler ' + ver if ver else 'citrix netscaler'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'SonicWALL' in prod or 'SonicWall' in prod:
                            ostype = 'SonicWall'
                            m = re.search(r'SonicOS[^\d]+([\d]+\.[\d]+[\.\d\-]*)', prod, re.IGNORECASE)
                            ver = m.group(1) if m else None
                            if not ver:
                                m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d\-]*)', prod)
                                ver = m.group(1) if m else None
                            prodstr = 'sonicwall sonicos ' + ver if ver else 'sonicwall'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'WatchGuard' in prod:
                            ostype = 'WatchGuard'
                            m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'watchguard fireware ' + ver if ver else 'watchguard'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Sophos' in prod or 'Astaro' in prod:
                            ostype = 'Sophos'
                            m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'sophos ' + ver if ver else 'sophos'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Pulse Secure' in prod or 'Pulse Connect' in prod or 'Ivanti Connect' in prod:
                            ostype = 'Ivanti'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'ivanti connect secure ' + ver if ver else 'ivanti connect secure'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Barracuda' in prod:
                            ostype = 'Barracuda'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'barracuda ' + ver if ver else 'barracuda'
                            if prodstr not in products:
                                products.append(prodstr)
                        # --- Network infrastructure ---
                        elif 'RouterOS' in prod or ('MikroTik' in prod and 'RouterOS' in prod):
                            ostype = 'MikroTik'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            if not ver:
                                mkver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.14988.1.1.7.4.0')
                                if mkver:
                                    ver = mkver.strip()
                            prodstr = 'mikrotik routeros ' + ver if ver else 'mikrotik routeros'
                            if prodstr not in products:
                                products.append(prodstr)
                            mkmodel = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.14988.1.1.7.3.0')
                            if mkmodel and mkmodel.strip():
                                products.append('mikrotik ' + mkmodel.strip())
                        elif 'ExtremeXOS' in prod or ('Extreme Networks' in prod and 'ExtremeXOS' in prod):
                            ostype = 'Extreme Networks'
                            m = re.search(r'ExtremeXOS[^\d]+([\d]+\.[\d]+[\.\d]*)', prod)
                            if not m:
                                m = re.search(r'[Vv]ersion\s+([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'extreme networks extremexos ' + ver if ver else 'extreme networks extremexos'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Huawei' in prod or ('VRP' in prod and 'Huawei' in prod):
                            ostype = 'Huawei'
                            m = re.search(r'V([\d]+R[\d]+C[\d]+)', prod)
                            ver = m.group(1) if m else None
                            if not ver:
                                m = re.search(r'[Vv]ersion\s+([\d]+\.[\d]+[\.\d]*)', prod)
                                ver = m.group(1) if m else None
                            prodstr = 'huawei vrp ' + ver if ver else 'huawei'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'TiMOS' in prod:
                            ostype = 'Nokia'
                            m = re.search(r'TiMOS-[A-Z]-([\d]+\.[\d]+\.[A-Z][\d]+)', prod)
                            ver = m.group(1) if m else None
                            if not ver:
                                m = re.search(r'TiMOS-(\S+)', prod)
                                ver = m.group(1) if m else None
                            prodstr = 'nokia sr os ' + ver if ver else 'nokia sr os'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Ruckus' in prod:
                            ostype = 'Ruckus'
                            m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'ruckus ' + ver if ver else 'ruckus'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Ubiquiti' in prod or 'airOS' in prod or 'UniFi' in prod:
                            ostype = 'Ubiquiti'
                            m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            if 'UniFi' in prod:
                                prodstr = 'ubiquiti unifi ' + ver if ver else 'ubiquiti unifi'
                            else:
                                prodstr = 'ubiquiti airos ' + ver if ver else 'ubiquiti airos'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Brocade' in prod:
                            ostype = 'Brocade'
                            m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d]*[a-z]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'brocade nos ' + ver if ver else 'brocade'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'ZyXEL' in prod or 'Zyxel' in prod:
                            ostype = 'Zyxel'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'zyxel ' + ver if ver else 'zyxel'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'D-Link' in prod:
                            ostype = 'D-Link'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'd-link ' + ver if ver else 'd-link'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'NETGEAR' in prod or 'Netgear' in prod:
                            ostype = 'Netgear'
                            m = re.search(r'([A-Z]{2,}\d{3,})', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('netgear ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Aerohive' in prod:
                            ostype = 'Aerohive'
                            m = re.search(r'([\d]+\.[\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'aerohive hiveos ' + ver if ver else 'aerohive'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Meraki' in prod:
                            ostype = 'Cisco Meraki'
                            if 'cisco meraki' not in products:
                                products.append('cisco meraki')
                        # --- Storage ---
                        elif 'NetApp' in prod or 'ONTAP' in prod or 'Data ONTAP' in prod:
                            ostype = 'NetApp'
                            m = re.search(r'(?:Release|ONTAP)\s+([\d]+\.[\d]+[\.\d]*[A-Za-z0-9]*)', prod)
                            ver = m.group(1) if m else None
                            if not ver:
                                naver = get_snmp_oid_value(args, cmd, '1.3.6.1.4.1.789.1.1.2.0')
                                if naver:
                                    m2 = re.search(r'([\d]+\.[\d]+[\.\d]*[A-Za-z0-9]*)', naver)
                                    ver = m2.group(1) if m2 else None
                            prodstr = 'netapp ontap ' + ver if ver else 'netapp'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Synology' in prod:
                            ostype = 'Synology'
                            m = re.search(r'([\d]+\.[\d]+[\.\d\-]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'synology dsm ' + ver if ver else 'synology'
                            if prodstr not in products:
                                products.append(prodstr)
                        # --- Hardware management ---
                        elif 'iDRAC' in prod:
                            ostype = 'Dell'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'dell idrac ' + ver if ver else 'dell idrac'
                            if prodstr not in products:
                                products.append(prodstr)
                        # --- Virtualization ---
                        elif 'VMware ESXi' in prod:
                            ostype = 'VMware'
                            m = re.search(r'ESXi\s+([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'vmware esxi ' + ver if ver else 'vmware esxi'
                            if prodstr not in products:
                                products.append(prodstr)
                        # --- UPS / Power ---
                        elif 'APC' in prod and any(x in prod for x in ['UPS', 'Power', 'Battery', 'Smart-']):
                            ostype = 'APC UPS'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'apc ups ' + ver if ver else 'apc ups'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Eaton' in prod:
                            ostype = 'Eaton'
                            m = re.search(r'([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'eaton ups ' + ver if ver else 'eaton'
                            if prodstr not in products:
                                products.append(prodstr)
                        # --- Printers ---
                        elif 'EPSON' in prod or ('Epson' in prod and any(x in prod for x in ['Printer', 'ET-', 'WF-', 'XP-', 'SC-'])):
                            ostype = 'Epson Printer'
                            words = prod.split()
                            model = words[1] if len(words) > 1 else ''
                            prodstr = ('epson ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Brother' in prod:
                            ostype = 'Brother Printer'
                            m = re.search(r'Brother\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('brother ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Lexmark' in prod:
                            ostype = 'Lexmark Printer'
                            m = re.search(r'Lexmark\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('lexmark ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'KYOCERA' in prod or 'Kyocera' in prod:
                            ostype = 'Kyocera Printer'
                            m = re.search(r'(?:KYOCERA|Kyocera)\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('kyocera ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'RICOH' in prod or 'Ricoh' in prod:
                            ostype = 'Ricoh Printer'
                            m = re.search(r'(?:RICOH|Ricoh)\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('ricoh ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Xerox' in prod:
                            ostype = 'Xerox Printer'
                            m = re.search(r'Xerox\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('xerox ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'KONICA MINOLTA' in prod or 'Konica Minolta' in prod:
                            ostype = 'Konica Minolta Printer'
                            m = re.search(r'(?:KONICA MINOLTA|Konica Minolta)\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('konica minolta ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif 'Sharp' in prod and any(x in prod for x in ['MX-', 'AR-', 'BP-', 'DX-', 'Copier', 'Printer', 'MFP']):
                            ostype = 'Sharp Printer'
                            m = re.search(r'Sharp\s+(\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('sharp ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        elif any(x in prod for x in ['HP LaserJet', 'HP Color LaserJet', 'HP OfficeJet', 'HP DeskJet', 'HP PageWide', 'HP ETHERNET MULTI-ENVIRONMENT']):
                            ostype = 'HP Printer'
                            m = re.search(r'HP\s+((?:Color\s+)?(?:LaserJet|OfficeJet|DeskJet|PageWide)\s+\S+)', prod)
                            model = m.group(1) if m else ''
                            prodstr = ('hp ' + model).strip()
                            if prodstr not in products:
                                products.append(prodstr)
                        # --- Generic OS (must be last) ---
                        elif 'VMware ESX' in prod:
                            ostype = 'VMware'
                            m = re.search(r'ESX\S*\s+([\d]+\.[\d]+[\.\d]*)', prod)
                            ver = m.group(1) if m else None
                            prodstr = 'vmware esx ' + ver if ver else 'vmware esx'
                            if prodstr not in products:
                                products.append(prodstr)
                        elif prod.startswith('Linux'):
                            ostype = 'Linux'
                            m = re.search(r'Linux[^\d]+([\d]+\.[\d]+\.[\d]+[\w\.\-]*)', prod)
                            if m:
                                ver = m.group(1).rstrip('.')
                                prodstr = 'linux linux kernel ' + ver
                                if prodstr not in products:
                                    products.append(prodstr)
                        elif 'Windows' in prod and ('Software' in prod or 'Microsoft' in prod or 'Hardware' in prod):
                            ostype = 'Windows'
                            m = re.search(r'Windows[^\d,]+([\d]+\.[\d]+)', prod)
                            if m:
                                ver = m.group(1)
                                # Map major.minor to readable name where possible
                                win_map = {
                                    '10.0': 'microsoft windows 10.0',
                                    '6.3':  'microsoft windows server 2012',
                                    '6.2':  'microsoft windows server 2012',
                                    '6.1':  'microsoft windows server 2008',
                                    '6.0':  'microsoft windows server 2008',
                                    '5.2':  'microsoft windows server 2003',
                                }
                                major_minor = '.'.join(ver.split('.')[:2])
                                prodstr = win_map.get(major_minor, 'microsoft windows ' + ver)
                                if prodstr not in products:
                                    products.append(prodstr)
                        else:
                            logging.debug("Unrecognized SNMP sysDescr: " + prod[:120])
                prod = s.getAttribute('product')
                if not prod:
                    continue
                ver = s.getAttribute('version')
                if ver:
                    prod = prod + ' ' + ver
                if prod not in products:
                    products.append(prod)
        # check for script output
        scripts = h.getElementsByTagName("script")
        for s in scripts:
            if s.getAttribute('id') == 'http-wordpress-enum':
                wpout = s.getAttribute('output')
                if wpout != None:
                    wplist = wpout.splitlines()
                    for wp in wplist:
                        wp = wp.strip()
                        if wp == '':
                            continue
                        if wp.startswith('Search limited to'):
                            continue
                        if wp.startswith('Nothing found'):
                            continue
                        if wp == 'plugins':
                            continue
                        if wp == 'themes':
                            continue
                        prodstr = 'wordpress plugin '+wp
                        if prodstr not in products:
                            products.append(prodstr)
            elif s.getAttribute('id') == 'tomcat-version':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    prodstr = 'apache tomcat ' + wpout.split(':')[1].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'http-server-header':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    prods = wpout.split(',')
                    for prod in prods:
                        prod = prod.replace('/',' ').strip()
                        prod = prod.replace('(',' ').strip()
                        prod = prod.replace(')',' ').strip()
                        if prod not in products:
                            products.append(prod)
            elif s.getAttribute('id') == 'http-php-version':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    if ':' not in wpout:
                        continue
                    prodstr = wpout.split(':')[1].strip()
                    prodstr = prodstr.split(',')[0]
                    prodstr = prodstr.split(' ')[0]
                    prodstr = prodstr.replace('PHP/','')
                    prodstr = prodstr.replace(',','')
                    prodstr = 'php '+prodstr
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'mirth-connect-version':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    prodstr = 'mirth connect ' + wpout.split(':')[1].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'connectwise-screenconnect-version':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    prodstr = 'connectwise screenconnect ' + wpout.split(':')[1].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'http-generator':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    prodstr = wpout.strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'mysql-info':
                elems = s.getElementsByTagName('elem')
                for e in elems:
                    key = e.getAttribute('key')
                    if key and key == 'Version':
                        prodstr = 'mysql ' + e.firstChild.data
                        if prodstr not in products:
                            products.append(prodstr)
            elif s.getAttribute('id') == 'erldp-info':
                wpout = s.getAttribute('output')
                if wpout != None:
                    prodstr = 'erldp ' + wpout.split('version:')[1].split('node')[0].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'confluence-version':
                wpout = s.getAttribute('output')
                if wpout != None:
                    if 'atlassian.net' in hostname:
                        prodstr = 'atlassian confluence ' + wpout.split('version:')[1].strip()
                    else:
                        prodstr = 'atlassian confluence data center ' + wpout.split('version:')[1].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'jira-version':
                wpout = s.getAttribute('output')
                if wpout != None and 'version:' in wpout:
                    if 'atlassian.net' in hostname:
                        prodstr = 'atlassian jira ' + wpout.split('version:')[1].strip()
                    else:
                        prodstr = 'atlassian jira data center ' + wpout.split('version:')[1].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'ms-sql-info':
                tables = s.getElementsByTagName('table')
                for table in tables:
                    if table.getAttribute('key') =='Version':
                        elems = table.getElementsByTagName('elem')
                        prod = ''
                        version = ''
                        for elem in elems:
                            if elem.getAttribute('key') == 'name':
                                prod = elem.firstChild.nodeValue.strip()
                            if elem.getAttribute('key') == 'number':
                                version = elem.firstChild.nodeValue.strip()
                        prod = prod + ' ' + version
                        if prod not in products:
                            products.append(prod)
            elif s.getAttribute('id') == 'vmware-version':
                wpout = s.getAttribute('output')
                if wpout != None:
                    prod = wpout.split('Server version:')[1].split('Locale')[0].strip()
                    prod = prod.replace('Server ','')
                    prod = prod.replace('\n','')
                    prod = prod.replace('Build: ','build-')
                    if prod not in products:
                        products.append(prod)
            elif s.getAttribute('id') == 'zookeeper-info':
                wpout = s.getAttribute('output')
                if wpout != None and 'zookeeper.version=' in wpout:
                    prod = 'apache zookeeper ' + wpout.split('zookeeper.version=')[1].split('-')[0].strip()
                    if prod not in products:
                        products.append(prod)
            elif s.getAttribute('id') == 'hp-printers':
                wpout = s.getAttribute('output')
                if wpout != None and 'hp printer:' in wpout:
                    prod = wpout.split('hp printer:')[1].strip()
                    if prod not in products:
                        products.append(prod)
                    ostype = 'HP Printer'
            elif s.getAttribute('id') == 'arecont-cctv':
                wpout = s.getAttribute('output')
                if wpout != None:
                    if wpout not in products:
                        products.append(wpout)
                    ostype = 'Arecont Vision'
            elif s.getAttribute('id') == 'axis-cctv':
                wpout = s.getAttribute('output')
                if wpout != None:
                    if wpout not in products:
                        products.append(wpout)
                    ostype = 'Axis Communications'
            elif s.getAttribute('id') == 'hanwhavision-cctv':
                wpout = s.getAttribute('output')
                if wpout != None:
                    wpout = wpout.replace('Hanwha Vision','hanwhavision').strip()
                    if wpout not in products:
                        products.append(wpout)
                    ostype = 'Hanwha Vision'
            elif s.getAttribute('id') == 'goanywhere_version':
                wpout = s.getAttribute('output')
                if wpout != None and wpout not in products:
                    products.append(wpout)
            elif s.getAttribute('id') == 'modbus-discover':
                wpout = s.getAttribute('output')
                if wpout != None:
                    if 'Device identification:' in wpout:
                        prod = wpout.split('Device identification:')[1].strip()
                    elif 'Slave ID data:' in wpout:
                        prod = wpout.split('Slave ID data:')[1].strip()
                    if 'Schneider Electric' in prod:
                        ostype = 'Schneider Electric'
                    products.append(prod)
            elif s.getAttribute('id') == 'jenkins-version':
                wpout = s.getAttribute('output')
                if wpout and 'jenkins version number:' in wpout:
                    ver = wpout.split('jenkins version number:')[1].strip().split('\n')[0].strip()
                    prodstr = 'jenkins ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'elasticsearch-version':
                wpout = s.getAttribute('output')
                if wpout and 'elasticsearch version number:' in wpout:
                    ver = wpout.split('elasticsearch version number:')[1].strip().split('\n')[0].strip()
                    prodstr = 'elasticsearch ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'kibana-version':
                wpout = s.getAttribute('output')
                if wpout and 'kibana version number:' in wpout:
                    ver = wpout.split('kibana version number:')[1].strip().split('\n')[0].strip()
                    prodstr = 'kibana ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'redis-info':
                wpout = s.getAttribute('output')
                if wpout and 'Version:' in wpout:
                    ver = wpout.split('Version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'redis ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'mongodb-info':
                wpout = s.getAttribute('output')
                if wpout and 'version:' in wpout:
                    ver = wpout.split('version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'mongodb ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'grafana-version':
                wpout = s.getAttribute('output')
                if wpout and 'grafana version:' in wpout:
                    ver = wpout.split('grafana version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'grafana ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'prometheus-version':
                wpout = s.getAttribute('output')
                if wpout and 'prometheus version:' in wpout:
                    ver = wpout.split('prometheus version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'prometheus ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'consul-version':
                wpout = s.getAttribute('output')
                if wpout and 'consul version:' in wpout:
                    ver = wpout.split('consul version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'hashicorp consul ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'vault-version':
                wpout = s.getAttribute('output')
                if wpout and 'vault version:' in wpout:
                    ver = wpout.split('vault version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'hashicorp vault ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'influxdb-version':
                wpout = s.getAttribute('output')
                if wpout and 'influxdb version:' in wpout:
                    ver = wpout.split('influxdb version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'influxdb ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'rabbitmq-version':
                wpout = s.getAttribute('output')
                if wpout and 'rabbitmq version:' in wpout:
                    ver = wpout.split('rabbitmq version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'rabbitmq ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'sonarqube-version':
                wpout = s.getAttribute('output')
                if wpout and 'sonarqube version:' in wpout:
                    ver = wpout.split('sonarqube version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'sonarqube ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'nexus-version':
                wpout = s.getAttribute('output')
                if wpout and 'nexus version:' in wpout:
                    ver = wpout.split('nexus version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'sonatype nexus repository manager ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'activemq-version':
                wpout = s.getAttribute('output')
                if wpout and 'activemq version:' in wpout:
                    ver = wpout.split('activemq version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'apache activemq ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'etcd-version':
                wpout = s.getAttribute('output')
                if wpout and 'etcd version:' in wpout:
                    ver = wpout.split('etcd version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'etcd ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'couchdb-version':
                wpout = s.getAttribute('output')
                if wpout and 'couchdb version:' in wpout:
                    ver = wpout.split('couchdb version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'apache couchdb ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'docker-version':
                wpout = s.getAttribute('output')
                if wpout and 'Version:' in wpout:
                    ver = wpout.split('Version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'docker ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'amqp-info':
                wpout = s.getAttribute('output')
                if wpout:
                    prod = None
                    ver = None
                    for line in wpout.splitlines():
                        line = line.strip()
                        if line.startswith('product:'):
                            prod = line.split(':', 1)[1].strip()
                        elif line.startswith('version:'):
                            ver = line.split(':', 1)[1].strip()
                    if prod and ver:
                        prodstr = prod.lower() + ' ' + ver
                        if prodstr not in products:
                            products.append(prodstr)
                    elif prod:
                        if prod not in products:
                            products.append(prod)
            elif s.getAttribute('id') == 'epmd-info':
                wpout = s.getAttribute('output')
                if wpout and 'nodes:' in wpout:
                    # Identify Erlang-based services (RabbitMQ, CouchDB, ejabberd, etc.)
                    for line in wpout.splitlines():
                        line = line.strip()
                        if line and ':' in line and not line.startswith('epmd'):
                            svc_name = line.split(':')[0].strip()
                            if svc_name and svc_name not in products:
                                products.append('erlang ' + svc_name)
            elif s.getAttribute('id') == 'memcached-info':
                elems = s.getElementsByTagName('elem')
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'Authentication' and e.firstChild:
                        # presence of memcached confirmed; no version from this script
                        prodstr = 'memcached'
                        if prodstr not in products:
                            products.append(prodstr)
                        break
            elif s.getAttribute('id') == 'riak-http-info':
                wpout = s.getAttribute('output')
                if wpout and 'Basho version' in wpout:
                    ver = wpout.split('Basho version')[1].strip().split('\n')[0].strip()
                    prodstr = 'basho riak ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'ftp-syst':
                wpout = s.getAttribute('output')
                if wpout and 'SYST:' in wpout:
                    syst = wpout.split('SYST:')[1].strip().split('\n')[0].strip()
                    if syst and syst.upper() != 'UNIX TYPE: L8':
                        prodstr = 'ftp ' + syst
                        if prodstr not in products:
                            products.append(prodstr)
            elif s.getAttribute('id') == 'smtp-commands':
                wpout = s.getAttribute('output')
                if wpout:
                    first_line = wpout.strip().split('\n')[0].strip()
                    mta_map = [
                        ('Postfix',     'postfix'),
                        ('Sendmail',    'sendmail'),
                        ('Exim',        'exim'),
                        ('Dovecot',     'dovecot'),
                        ('Exchange',    'microsoft exchange'),
                        ('Lotus',       'ibm lotus domino'),
                        ('hMailServer', 'hmailserver'),
                        ('MailEnable',  'mailenable'),
                        ('Zimbra',      'zimbra'),
                    ]
                    # MTA name appears after "ESMTP" or "SMTP" in the banner,
                    # not in the hostname part — restrict search to avoid
                    # hostname false positives (e.g. "postfix.example.com ESMTP Sendmail")
                    mta_section = re.search(r'(?:ESMTP|SMTP)\s+(.*)', first_line, re.IGNORECASE)
                    mta_str = mta_section.group(1) if mta_section else ''
                    for keyword, prodname in mta_map:
                        if keyword.lower() in mta_str.lower():
                            ver_match = re.search(
                                r'(?i)' + re.escape(keyword) + r'[^0-9]+([\d]+\.[\d]+[\.\d]*)',
                                mta_str
                            )
                            prodstr = (prodname + ' ' + ver_match.group(1)) if ver_match else prodname
                            if prodstr not in products:
                                products.append(prodstr)
                            break
            elif s.getAttribute('id') == 'smtp-ntlm-info':
                wpout = s.getAttribute('output')
                if wpout and 'Product_Version:' in wpout:
                    ver = wpout.split('Product_Version:')[1].strip().split('\n')[0].strip()
                    if ver:
                        prodstr = 'microsoft windows ' + ver
                        if prodstr not in products:
                            products.append(prodstr)
            elif s.getAttribute('id') == 'rdp-ntlm-info':
                wpout = s.getAttribute('output')
                if wpout and 'Product_Version:' in wpout:
                    ver = wpout.split('Product_Version:')[1].strip().split('\n')[0].strip()
                    if ver:
                        prodstr = 'microsoft windows ' + ver
                        if prodstr not in products:
                            products.append(prodstr)
                        if ostype == 'Other':
                            ostype = 'Windows'
            elif s.getAttribute('id') == 'vnc-info':
                wpout = s.getAttribute('output')
                if wpout and 'Protocol version:' in wpout:
                    ver = wpout.split('Protocol version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'vnc ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 's7-info':
                elems = s.getElementsByTagName('elem')
                module_type = ''
                version = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'Module Type' and e.firstChild:
                        module_type = e.firstChild.data.strip()
                    elif key == 'Version' and e.firstChild:
                        version = e.firstChild.data.strip()
                if module_type:
                    prodstr = 'siemens s7 ' + module_type
                    if version:
                        prodstr += ' ' + version
                    if prodstr not in products:
                        products.append(prodstr)
                    if ostype == 'Other':
                        ostype = 'Siemens'
            elif s.getAttribute('id') == 'enip-info':
                elems = s.getElementsByTagName('elem')
                product_name = ''
                vendor = ''
                revision = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'productName' and e.firstChild:
                        product_name = e.firstChild.data.strip()
                    elif key == 'vendor' and e.firstChild:
                        vendor = e.firstChild.data.strip()
                        # Strip trailing "(N)" vendor id suffix
                        vendor = vendor.split('(')[0].strip()
                    elif key == 'revision' and e.firstChild:
                        revision = e.firstChild.data.strip()
                if product_name:
                    prodstr = product_name
                    if revision:
                        prodstr += ' ' + revision
                    if prodstr not in products:
                        products.append(prodstr)
                if vendor:
                    prodstr = vendor
                    if prodstr not in products:
                        products.append(prodstr)
                    if ostype == 'Other':
                        ostype = vendor
            elif s.getAttribute('id') == 'bacnet-info':
                elems = s.getElementsByTagName('elem')
                vendor_name = ''
                firmware = ''
                model_name = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'Vendor Name' and e.firstChild:
                        vendor_name = e.firstChild.data.strip()
                    elif key == 'Firmware' and e.firstChild:
                        firmware = e.firstChild.data.strip()
                    elif key == 'Model Name' and e.firstChild:
                        model_name = e.firstChild.data.strip()
                if vendor_name:
                    prodstr = vendor_name
                    if firmware:
                        prodstr += ' ' + firmware
                    if prodstr not in products:
                        products.append(prodstr)
                    if model_name and model_name not in products:
                        products.append(model_name)
            elif s.getAttribute('id') == 'pcworx-info':
                elems = s.getElementsByTagName('elem')
                plc_type = ''
                fw_version = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'PLC Type' and e.firstChild:
                        plc_type = e.firstChild.data.strip()
                    elif key == 'Firmware Version' and e.firstChild:
                        fw_version = e.firstChild.data.strip()
                if plc_type:
                    prodstr = 'phoenix contact ' + plc_type
                    if fw_version:
                        prodstr += ' ' + fw_version
                    if prodstr not in products:
                        products.append(prodstr)
                    if ostype == 'Other':
                        ostype = 'Phoenix Contact'
            # --- web / HTTP detection ---
            elif s.getAttribute('id') == 'http-title':
                elems = s.getElementsByTagName('elem')
                title = None
                for e in elems:
                    if e.getAttribute('key') == 'title' and e.firstChild:
                        title = e.firstChild.data.strip()
                        break
                if title:
                    title_lower = title.lower()
                    title_map = [
                        ('gitlab',       'gitlab'),
                        ('gitea',        'gitea'),
                        ('forgejo',      'forgejo'),
                        ('jenkins',      'jenkins'),
                        ('portainer',    'portainer'),
                        ('traefik',      'traefik'),
                        ('grafana',      'grafana'),
                        ('keycloak',     'keycloak'),
                        ('sonarqube',    'sonarqube'),
                        ('nexus',        'sonatype nexus repository manager'),
                        ('jira',         'atlassian jira'),
                        ('confluence',   'atlassian confluence'),
                        ('bitbucket',    'atlassian bitbucket'),
                        ('harbor',       'harbor'),
                        ('rancher',      'rancher'),
                        ('argo cd',      'argo cd'),
                        ('argocd',       'argo cd'),
                        ('jupyterlab',   'jupyterlab'),
                        ('jupyter',      'jupyter notebook'),
                        ('weblogic',     'oracle weblogic server'),
                        ('glassfish',    'glassfish'),
                        ('jboss',        'jboss'),
                        ('wildfly',      'wildfly'),
                        ('tomcat',       'apache tomcat'),
                        ('iis windows',  'microsoft internet information services'),
                        ('exchange',     'microsoft exchange'),
                        ('sharepoint',   'microsoft sharepoint'),
                        ('mirth connect','mirth connect'),
                        ('rabbitmq',     'rabbitmq'),
                        ('activemq',     'apache activemq'),
                        ('zookeeper',    'apache zookeeper'),
                        ('kibana',       'kibana'),
                        ('elastic',      'elasticsearch'),
                        ('prometheus',   'prometheus'),
                        ('alertmanager', 'prometheus alertmanager'),
                        ('vault',        'hashicorp vault'),
                        ('consul',       'hashicorp consul'),
                        ('mattermost',   'mattermost'),
                        ('rocket.chat',  'rocket.chat'),
                        ('cockroachdb',  'cockroachdb'),
                        ('clickhouse',   'clickhouse'),
                        ('minio',        'minio'),
                        ('teamcity',     'jetbrains teamcity'),
                        ('artifactory',  'jfrog artifactory'),
                        ('victoria metrics', 'victoria metrics'),
                        ('loki',         'grafana loki'),
                        ('jaeger',       'jaeger'),
                        ('zipkin',       'zipkin'),
                        ('kong',         'kong gateway'),
                        ('arangodb',     'arangodb'),
                        ('drone',        'drone ci'),
                        ('flower',       'celery flower'),
                        ('haproxy',      'haproxy'),
                        ('envoy',        'envoy proxy'),
                        ('nats',         'nats'),
                        ('bamboo',       'atlassian bamboo'),
                        ('nextcloud',    'nextcloud'),
                        ('nagios',       'nagios'),
                        ('zabbix',       'zabbix'),
                        ('pulsar',       'apache pulsar'),
                    ]
                    for keyword, prodname in title_map:
                        if keyword in title_lower:
                            if prodname not in products:
                                products.append(prodname)
                            break
            elif s.getAttribute('id') == 'http-ntlm-info':
                elems = s.getElementsByTagName('elem')
                for e in elems:
                    if e.getAttribute('key') == 'Product_Version' and e.firstChild:
                        ver = e.firstChild.data.strip()
                        prodstr = 'microsoft windows ' + ver
                        if prodstr not in products:
                            products.append(prodstr)
                        if ostype == 'Other':
                            ostype = 'Windows'
                        break
            elif s.getAttribute('id') == 'http-favicon':
                wpout = s.getAttribute('output')
                if wpout and 'unknown' not in wpout.lower() and len(wpout.strip()) > 2:
                    prodstr = wpout.strip()
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'http-qnap-nas-info':
                elems = s.getElementsByTagName('elem')
                model = ''
                firmware = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'Device Model' and e.firstChild:
                        model = e.firstChild.data.strip()
                    elif key == 'Firmware Version' and e.firstChild:
                        firmware = e.firstChild.data.strip()
                if model:
                    prodstr = 'qnap ' + model
                    if firmware:
                        prodstr += ' ' + firmware
                    if prodstr not in products:
                        products.append(prodstr)
                    if ostype == 'Other':
                        ostype = 'QNAP'
            elif s.getAttribute('id') == 'http-hp-ilo-info':
                elems = s.getElementsByTagName('elem')
                ilo_type = ''
                ilo_fw = ''
                server_type = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'ILOType' and e.firstChild:
                        ilo_type = e.firstChild.data.strip()
                    elif key == 'ILOFirmware' and e.firstChild:
                        ilo_fw = e.firstChild.data.strip()
                    elif key == 'ServerType' and e.firstChild:
                        server_type = e.firstChild.data.strip()
                if ilo_type:
                    prodstr = 'hp ' + ilo_type.lower()
                    if ilo_fw:
                        prodstr += ' ' + ilo_fw
                    if prodstr not in products:
                        products.append(prodstr)
                if server_type and server_type not in products:
                    products.append('hp ' + server_type)
            elif s.getAttribute('id') == 'http-trane-info':
                elems = s.getElementsByTagName('elem')
                product_name = ''
                product_ver = ''
                for e in elems:
                    key = e.getAttribute('key')
                    if key == 'productName' and e.firstChild:
                        product_name = e.firstChild.data.strip()
                    elif key == 'productVersion' and e.firstChild:
                        product_ver = e.firstChild.data.strip().lstrip('v').split(' ')[0]
                if product_name:
                    prodstr = 'trane ' + product_name.lower()
                    if product_ver:
                        prodstr += ' ' + product_ver
                    if prodstr not in products:
                        products.append(prodstr)
                    if ostype == 'Other':
                        ostype = 'Trane'
            elif s.getAttribute('id') == 'spring-boot-version':
                wpout = s.getAttribute('output')
                if wpout:
                    if 'spring boot version:' in wpout:
                        ver = wpout.split('spring boot version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'spring boot ' + ver
                        if prodstr not in products:
                            products.append(prodstr)
                    elif 'spring boot application:' in wpout:
                        prodstr = 'spring boot'
                        if prodstr not in products:
                            products.append(prodstr)
                    elif 'spring boot detected:' in wpout:
                        prodstr = 'spring boot'
                        if prodstr not in products:
                            products.append(prodstr)
            elif s.getAttribute('id') == 'gitlab-version':
                wpout = s.getAttribute('output')
                if wpout:
                    if 'gitlab version:' in wpout:
                        ver = wpout.split('gitlab version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'gitlab ' + ver
                    else:
                        prodstr = 'gitlab'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'gitea-version':
                wpout = s.getAttribute('output')
                if wpout:
                    if 'gitea version:' in wpout:
                        ver = wpout.split('gitea version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'gitea ' + ver
                    elif 'forgejo version:' in wpout:
                        ver = wpout.split('forgejo version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'forgejo ' + ver
                    else:
                        prodstr = 'gitea'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'keycloak-version':
                wpout = s.getAttribute('output')
                if wpout:
                    if 'keycloak version:' in wpout:
                        ver = wpout.split('keycloak version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'keycloak ' + ver
                    else:
                        prodstr = 'keycloak'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'traefik-version':
                wpout = s.getAttribute('output')
                if wpout and 'traefik version:' in wpout:
                    ver = wpout.split('traefik version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'traefik ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'portainer-version':
                wpout = s.getAttribute('output')
                if wpout and 'portainer version:' in wpout:
                    ver = wpout.split('portainer version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'portainer ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'jupyter-version':
                wpout = s.getAttribute('output')
                if wpout:
                    if 'jupyter version:' in wpout:
                        ver = wpout.split('jupyter version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'jupyter notebook ' + ver
                    elif 'jupyterhub version:' in wpout:
                        ver = wpout.split('jupyterhub version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'jupyterhub ' + ver
                    else:
                        prodstr = 'jupyter notebook'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'weblogic-version':
                wpout = s.getAttribute('output')
                if wpout:
                    if 'weblogic version:' in wpout:
                        ver = wpout.split('weblogic version:')[1].strip().split('\n')[0].strip()
                        prodstr = 'oracle weblogic server ' + ver
                    else:
                        prodstr = 'oracle weblogic server'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'waf-detect':
                wpout = s.getAttribute('output')
                if wpout:
                    for line in wpout.splitlines():
                        line = line.strip()
                        if line.startswith('waf:'):
                            waf_name = line[4:].strip()
                            if waf_name and waf_name not in products:
                                products.append(waf_name)
            # --- previously-scanned-but-unhandled built-in scripts ---
            elif s.getAttribute('id') == 'kubernetes-version':
                elems = s.getElementsByTagName('elem')
                ver = None
                for e in elems:
                    if e.getAttribute('key') == 'gitVersion' and e.firstChild:
                        ver = e.firstChild.data.strip().lstrip('v')
                        break
                if not ver:
                    wpout = s.getAttribute('output')
                    if wpout:
                        m = re.search(r'v?(\d+\.\d+\.\d+)', wpout)
                        if m:
                            ver = m.group(1)
                if ver:
                    prodstr = 'kubernetes ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                else:
                    if 'kubernetes' not in products:
                        products.append('kubernetes')
            elif s.getAttribute('id') == 'cassandra-info':
                wpout = s.getAttribute('output')
                if wpout:
                    prodstr = 'apache cassandra'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'db2-das-info':
                elems = s.getElementsByTagName('elem')
                ver = None
                for e in elems:
                    if e.getAttribute('key') == 'server_level' and e.firstChild:
                        ver = e.firstChild.data.strip()
                        break
                if not ver:
                    wpout = s.getAttribute('output')
                    if wpout:
                        for line in wpout.splitlines():
                            if 'server_level' in line and ':' in line:
                                ver = line.split(':', 1)[1].strip()
                                break
                prodstr = ('ibm db2 ' + ver) if ver else 'ibm db2'
                if prodstr not in products:
                    products.append(prodstr)
            elif s.getAttribute('id') == 'oracle-tns-version':
                wpout = s.getAttribute('output')
                if wpout:
                    m = re.search(r'Version\s+([\d\.]+)', wpout)
                    prodstr = ('oracle database ' + m.group(1)) if m else 'oracle'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'postgresql-info':
                wpout = s.getAttribute('output')
                if wpout and 'postgresql' in wpout.lower():
                    elems = s.getElementsByTagName('elem')
                    ver = None
                    for e in elems:
                        if e.getAttribute('key') == 'version' and e.firstChild:
                            ver = e.firstChild.data.strip()
                            break
                    prodstr = ('postgresql ' + ver) if ver else 'postgresql'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'ldap-rootdse':
                elems = s.getElementsByTagName('elem')
                is_ad = False
                for e in elems:
                    if e.getAttribute('key') in ('serverName', 'defaultNamingContext') and e.firstChild:
                        val = e.firstChild.data.strip()
                        if 'DC=' in val or 'CN=' in val:
                            is_ad = True
                            break
                wpout = s.getAttribute('output')
                if wpout or len(elems) > 0:
                    prodstr = 'microsoft active directory' if is_ad else 'openldap'
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'dnp3-info':
                wpout = s.getAttribute('output')
                if wpout:
                    prodstr = 'dnp3'
                    if prodstr not in products:
                        products.append(prodstr)
            # --- new service detection ---
            elif s.getAttribute('id') == 'neo4j-version':
                wpout = s.getAttribute('output')
                if wpout and 'neo4j version:' in wpout:
                    ver = wpout.split('neo4j version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'neo4j ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                elif wpout and 'neo4j' not in [p.split()[0].lower() for p in products]:
                    products.append('neo4j')
            elif s.getAttribute('id') == 'nats-version':
                wpout = s.getAttribute('output')
                if wpout and 'nats version:' in wpout:
                    ver = wpout.split('nats version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'nats ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'alertmanager-version':
                wpout = s.getAttribute('output')
                if wpout and 'alertmanager version:' in wpout:
                    ver = wpout.split('alertmanager version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'prometheus alertmanager ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'loki-version':
                wpout = s.getAttribute('output')
                if wpout and 'loki version:' in wpout:
                    ver = wpout.split('loki version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'grafana loki ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'jaeger-version':
                wpout = s.getAttribute('output')
                if wpout and 'jaeger version:' in wpout:
                    ver = wpout.split('jaeger version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'jaeger ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                elif wpout and 'jaeger detected' in wpout:
                    if 'jaeger' not in products:
                        products.append('jaeger')
            elif s.getAttribute('id') == 'zipkin-version':
                wpout = s.getAttribute('output')
                if wpout and 'zipkin version:' in wpout:
                    ver = wpout.split('zipkin version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'zipkin ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'mattermost-version':
                wpout = s.getAttribute('output')
                if wpout and 'mattermost version:' in wpout:
                    ver = wpout.split('mattermost version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'mattermost ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'rocketchat-version':
                wpout = s.getAttribute('output')
                if wpout and 'rocketchat version:' in wpout:
                    ver = wpout.split('rocketchat version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'rocket.chat ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'kong-version':
                wpout = s.getAttribute('output')
                if wpout and 'kong version:' in wpout:
                    ver = wpout.split('kong version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'kong gateway ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'artifactory-version':
                wpout = s.getAttribute('output')
                if wpout and 'artifactory version:' in wpout:
                    ver = wpout.split('artifactory version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'jfrog artifactory ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'flower-version':
                wpout = s.getAttribute('output')
                if wpout and 'flower version:' in wpout:
                    ver = wpout.split('flower version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'celery flower ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                elif wpout and 'flower detected' in wpout:
                    if 'celery flower' not in products:
                        products.append('celery flower')
            elif s.getAttribute('id') == 'clickhouse-version':
                wpout = s.getAttribute('output')
                if wpout and 'clickhouse version:' in wpout:
                    ver = wpout.split('clickhouse version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'clickhouse ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'minio-version':
                wpout = s.getAttribute('output')
                if wpout and 'minio version:' in wpout:
                    ver = wpout.split('minio version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'minio ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                elif wpout and 'minio detected' in wpout:
                    if 'minio' not in products:
                        products.append('minio')
            elif s.getAttribute('id') == 'teamcity-version':
                wpout = s.getAttribute('output')
                if wpout and 'teamcity version:' in wpout:
                    ver = wpout.split('teamcity version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'jetbrains teamcity ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'envoy-version':
                wpout = s.getAttribute('output')
                if wpout and 'envoy version:' in wpout:
                    ver = wpout.split('envoy version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'envoy proxy ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'haproxy-stats':
                wpout = s.getAttribute('output')
                if wpout and 'haproxy version:' in wpout:
                    ver = wpout.split('haproxy version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'haproxy ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                elif wpout and 'haproxy detected' in wpout:
                    if 'haproxy' not in products:
                        products.append('haproxy')
            elif s.getAttribute('id') == 'victoria-metrics-version':
                wpout = s.getAttribute('output')
                if wpout and 'victoria metrics version:' in wpout:
                    ver = wpout.split('victoria metrics version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'victoria metrics ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'bamboo-version':
                wpout = s.getAttribute('output')
                if wpout and 'bamboo version:' in wpout:
                    ver = wpout.split('bamboo version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'atlassian bamboo ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'cockroachdb-version':
                wpout = s.getAttribute('output')
                if wpout and 'cockroachdb version:' in wpout:
                    ver = wpout.split('cockroachdb version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'cockroachdb ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
                elif wpout and 'cockroachdb detected' in wpout:
                    if 'cockroachdb' not in products:
                        products.append('cockroachdb')
            elif s.getAttribute('id') == 'nextcloud-version':
                wpout = s.getAttribute('output')
                if wpout and 'nextcloud version:' in wpout:
                    ver = wpout.split('nextcloud version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'nextcloud ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'arangodb-version':
                wpout = s.getAttribute('output')
                if wpout and 'arangodb version:' in wpout:
                    ver = wpout.split('arangodb version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'arangodb ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'pulsar-version':
                wpout = s.getAttribute('output')
                if wpout and 'pulsar version:' in wpout:
                    ver = wpout.split('pulsar version:')[1].strip().split('\n')[0].strip()
                    prodstr = 'apache pulsar ' + ver
                    if prodstr not in products:
                        products.append(prodstr)
            elif s.getAttribute('id') == 'kafka-version':
                wpout = s.getAttribute('output')
                if wpout and 'kafka' in wpout.lower():
                    if 'apache kafka' not in products:
                        products.append('apache kafka')
            elif s.getAttribute('id') == 'mosquitto-version':
                wpout = s.getAttribute('output')
                if wpout and 'mqtt broker' in wpout:
                    if 'eclipse mosquitto' not in products:
                        products.append('eclipse mosquitto')

        os_name_tag = None
        smb_os_name = get_smb_os(h)
        # get the product name associated with the best os class
        best_os_class = get_best_os_class(h) 
        if best_os_class:
            if ostype == "Linux":
                cpe = best_os_class.getElementsByTagName("cpe")[0]
                cstr = cpe.firstChild.data
                carr = cstr.split(':')
                prodstr = carr[2] + ' ' + carr[3] + ' '
                if len(carr) >= 5:
                    prodstr += carr[4]
                prodstr = prodstr.strip()
                prodstr = prodstr.replace('_',' ')
                if "." not in prodstr:
                    # At times version is incomplete i.e. like a single digit like "linux linux kernel 4" and this does not lend itself nicely for matching. Hence add the ".0" to complete it.
                    prodstr = prodstr + ".0"
                if prodstr not in products:
                    products.append(prodstr)
            elif ostype == "Windows":
                if smb_os_name:
                    products.append(smb_os_name)
                    os_name_tag = smb_os_name
                else:
                    os_name = best_os_class.parentNode.getAttribute("name")
                    # At times there can be multiple os_names like "Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1", then take the first one
                    if "," in os_name and " or " in os_name:
                        comma_position = os_name.find(",")
                        or_position = os_name.find(" or ")
                        if comma_position < or_position:
                            os_name = os_name.split(',')[0]
                        else:
                            os_name = os_name.split(" or ")[0]
                    elif "," in os_name:
                        os_name = os_name.split(",")[0]
                    elif " or " in os_name:
                        os_name = os_name.split(' or ')[0]
                    products.append(os_name)
                    os_name_tag = os_name

        # clean up the list of products
        clean_products = []
        for p in products:
            # remove bare references to windows and linux kernels without versions
            if p.lower() == 'microsoft windows' or p.lower() == 'linux linux kernel':
                continue
            if ostype == "Windows":
                # if smb os name is present then remove all references to other microsoft windows
                if smb_os_name and p.lower().startswith('microsoft windows'):
                    continue
                # remove references to linux kernel in windows asset 
                if p.lower().startswith('linux linux kernel'):
                    continue
            if ostype == "Linux":
                # remove references to linux kernel in windows asset 
                if p.lower().startswith('microsoft windows'):
                    continue
            clean_products.append(p)
        products = clean_products

        asset_data = {}
        asset_data['id'] = addr 
        asset_data['name'] = hostname 
        asset_data['type'] = ostype
        asset_data['owner'] = args.handle
        asset_data['products'] = products
        asset_tags = ["DISCOVERY_TYPE:Unauthenticated"]
        if os_name_tag:
            asset_tags.append("OS_RELEASE:" + os_name_tag)
            asset_tags.append(os_name_tag)
        asset_data['tags'] = asset_tags

        if 'printers' not in args.services and 'cctv' not in args.services and 'snmp' not in args.services:
            if len(ports_in_use_dict) > 0:
                asset_data['config_issues'] = create_open_ports_issues(ports_in_use_dict, addr)
            if args.no_ssh_audit == False and ssh_port_is_open:
                ssh_issues = linux.run_ssh_audit(args, addr, addr)
                if len(ssh_issues) != 0:
                    asset_data['tags'].append('SSH Audit')
                asset_data['config_issues'] = asset_data['config_issues'] + ssh_issues if 'config_issues' in asset_data else ssh_issues

        if asset_data['type'] == "Other" and len(asset_data['products']) == 0 and ('config_issues' not in asset_data or len(asset_data['config_issues'])==0):
            # skip any discovered assets which have asset type as "Other" and no products and no config_issues
            logging.info("Fingerprinting did not yield any results")
            continue
        asset_data_list.append(asset_data)

    return asset_data_list

def get_inventory(args):
    if not nmap_exists():
        logging.error('nmap CLI not found')
        return None

    if args.hosts is None:
        args.hosts = get_private_ip_cidrs()
    else:
        args.hosts = args.hosts.split(',')

    assets = []
    max_workers = min(len(args.hosts), 5)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(nmap_scan, args, host): host for host in args.hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                assets.extend(future.result())
            except Exception as exc:
                logging.error("Scan failed for host %s: %s", host, exc)
    return assets
