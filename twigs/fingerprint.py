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
import csv
from . import linux

NMAP = "/usr/bin/nmap"
NSE_PATH = os.path.dirname(os.path.realpath(__file__)) + '/nse/'

def nmap_exists():
    return os.path.isfile(NMAP) and os.access(NMAP, os.X_OK)

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

def get_os_type(host, products):
    os_family = None
    host_os_classes = host.getElementsByTagName("osclass")
    if host_os_classes is not None:
        accuracy = -1
        for host_os_class in host_os_classes:
            host_acc = host_os_class.getAttribute("accuracy")
            if host_acc == "":
                continue
            host_acc = int(host_acc)
            if host_acc > accuracy:
                os_family = host_os_class.getAttribute("osfamily")
                accuracy = host_acc

    if os_family is not None and os_family != "":
        logging.debug("Found os_type [%s] from <osclass>", os_family)
        return os_family

    conf = -1
    services = host.getElementsByTagName("service")
    for service in services:
        ostype = service.getAttribute("ostype")
        if ostype != "":
            if int(service.getAttribute("conf")) > conf:
                os_family = ostype
                conf = int(service.getAttribute("conf"))

    if os_family is not None and os_family != "":
        logging.debug("Found os_type [%s] from <service>", os_family)
        return os_family

    if 'microsoft windows' in products:
        logging.debug("Found os_type [Windows] from products")
        return 'Windows'
    for product in products:
        if 'linux linux kernel' in product:
            logging.debug("Found os_type [Linux] from products")
            return 'Linux'
    logging.debug("Unable to determine os_type...assuming [Other]")
    return 'Other'

def nmap_scan(args, host):
    logging.info("Fingerprinting "+host)
    cmdarr = [NMAP + ' -oX - -A --script '+NSE_PATH+'/tomcat-version.nse,http-wordpress-enum,mysql-info -PN -T5 '+host]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Error running nmap command")
        return None

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

        # SSH Port in use?
        ssh_port_is_open = False
        ports = h.getElementsByTagName("port")
        for port in ports:
            if port.getAttribute('portid') == "22":
                port_state = port.getElementsByTagName("state")[0]
                if port_state is not None and port_state.getAttribute('state') == "open":
                    ssh_port_is_open = True

        # check for cpes
        cpes = h.getElementsByTagName("cpe")
        products = []
        for c in cpes:
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
            if s.getAttribute('id') == 'tomcat-version':
                wpout = s.getAttribute('output')
                if wpout != None and wpout != '':
                    prodstr = 'apache tomcat ' + wpout.split('Version:')[1].strip()
                    if prodstr not in products:
                        products.append(prodstr)
            if s.getAttribute('id') == 'mysql-info':
                wpout = s.getAttribute('output')
                if wpout != None:
                    prodstr = wpout.split('Version:')[1].split('#')[0].strip()
                    if prodstr not in products:
                        products.append(prodstr)
        if ostype == "Other" and len(products) == 0:
            # skip any discovered assets which have asset type as "Other" and no products
            continue
        asset_data = {}
        asset_data['id'] = addr 
        asset_data['name'] = hostname 
        asset_data['type'] = ostype
        asset_data['owner'] = args.handle
        asset_data['products'] = products
        asset_tags = ["DISCOVERY_TYPE:Unauthenticated"]
        asset_data['tags'] = asset_tags
        if args.no_ssh_audit == False and ssh_port_is_open:
            ssh_issues = linux.run_ssh_audit(args, addr, addr)
            if len(ssh_issues) != 0:
                asset_data['tags'].append('SSH Audit')
            asset_data['config_issues'] = ssh_issues

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
    nmap_cmd = NMAP + ' -oX - -A --script http-wordpress-enum,mysql-info -T' + args.timing
    if args.discovery_scan_type is not None:
        nmap_cmd = nmap_cmd + ' -P' + args.discovery_scan_type
        if args.discovery_scan_type not in ['N', 'E', 'P', 'M'] and args.discovery_port_list is not None:
            nmap_cmd = nmap_cmd + args.discovery_port_list
    assets = []
    for host in args.hosts:
        assets = nmap_scan(args, host)
    return assets
