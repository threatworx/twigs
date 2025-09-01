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
NMAP_default = "/usr/bin/nmap"
NMAP = shutil.which("nmap")
if NMAP is None:
    NMAP = NMAP_default
NSE_PATH = os.path.dirname(os.path.realpath(__file__)) + '/nse/'

NMAP_HTTP_PORTS = ['80','443','6443','8080','8443','2181'] 
NSE_APACHE_PATH  = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/apache/'
NSE_HTTP_PATH = "+/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/http/'
NSE_HTTP_SCRIPTS = ['+http-generator','+http-wordpress-enum','+http-apache-server-status','+http-server-header','http-php-version',NSE_HTTP_PATH,NSE_APACHE_PATH]

NMAP_DB_PORTS = ['9200','9300','27017','27018','27019','3306','7000','7001','9042','7199','523','445','1443','6379','1521']
NSE_DB_PATH  = "/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/database/'
NSE_DB_SCRIPTS = [NSE_DB_PATH,'mongodb-info','mysql-info','cassandra-info','db2-das-info','ms-sql-info','redis-info','oracle-tns-version']

NMAP_PRINTERS_PORTS = ['80','161','443','9100','U:161']
NSE_PRINTERS_PATH  = "/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/printers/'
NSE_PRINTERS_SCRIPTS = [NSE_PRINTERS_PATH]

NMAP_CCTV_PORTS = ['21','80','161','443','8080','8443','4321', '37777', '9000', '10554', '5985','9100','5060']
NSE_CCTV_PATH  = "/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/cctv/'
NSE_CCTV_SCRIPTS = [NSE_CCTV_PATH]

NSE_OTHER_PATH =  "/"+os.path.dirname(os.path.realpath(__file__)) + '/nse/other/' 

def nmap_exists():
    return NMAP and os.access(NMAP, os.X_OK)

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
            return 'Windows', os_name
        if 'linux linux kernel' in product:
            logging.debug("Found os_type [Linux] from products")
            return 'Linux', os_name

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

def create_nmap_cmd (args):
    ports = [] 
    scripts = [] 
    os = ""
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
        os = " -O "
        scripts += ['smb-os-discovery']
        ports += ['1-100'] 
    if "vmware" in args.services:
        scripts += ['vmware-version']
        ports += ['443'] 
    if "printers" in args.services:
        ports += NMAP_PRINTERS_PORTS
        scripts += NSE_PRINTERS_SCRIPTS
    if "cctv" in args.services:
        ports += NMAP_CCTV_PORTS
        scripts += NSE_CCTV_SCRIPTS
 
    cmd = NMAP + vflag + ' -Pn -oX - -T ' + args.timing + os
    if len(ports) != 0:
        cmd += ' -p' + ','.join(list(set(ports)))
    if args.extra_ports:
        cmd += ','+args.extra_ports
    if len(scripts) != 0:
        cmd += ' --script '+','.join(list(set(scripts)))
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
                prod = s.getAttribute('product')
                if not prod:
                    continue
                ver = s.getAttribute('version')
                if not ver:
                    continue
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
                        prodstr = 'mongodb '+e.firstChild.data
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
        asset_data['tags'] = asset_tags

        if 'printers' not in args.services and 'cctv' not in args.services:
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

    if args.hosts == None:
        args.hosts = get_private_ip_cidrs()
    else:
        args.hosts = args.hosts.split(',')
    assets = []
    for host in args.hosts:
        assets.extend(nmap_scan(args, host))
    return assets 
