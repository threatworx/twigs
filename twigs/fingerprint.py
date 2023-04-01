import sys
import platform
import os
import subprocess
import logging
import psutil
import ipaddress
import socket
import json
from xml.dom.minidom import parse, parseString
import csv
from . import linux

NMAP = "/usr/bin/nmap"

def nmap_exists():
    return os.path.isfile(NMAP) and os.access(NMAP, os.X_OK)

def discover(args):
    handle = args.handle
    token = args.token
    instance = args.instance

    hosts = args.hosts

def get_wordpress(args):
    if not nmap_exists():
        logging.error('nmap CLI not found')
        return None
    logging.info("Discovering wordpress website on "+args.host)
    assets = []
    word = [NMAP + ' --script http-wordpress-enum '+ args.host]
    try:
        word_out = subprocess.check_output(word, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error running nmap discovery for wordpress")
        return None 
    plugins = str(word_out).split('plugins')[-1]
    plugins = plugins.split('_http')[0]
    plugins = plugins.split('|')
    products = []
    for p in plugins:
        p = p.strip()
        if p == '':
            continue
        if p == 'themes':
            continue
        if p.startswith('_'):
            p = p.replace('_','')
            p = p.strip()
        if 'Nmap done:' in p:
            p = p.split('\n')[0]
        products.append(p)
    asset_data = {}
    if args.assetid != None:
        asset_data['id'] = args.assetid
    else:
        asset_data['id'] = args.host
    asset_data['name'] = args.host 
    asset_data['type'] = 'WordPress'
    asset_data['owner'] = args.handle
    asset_data['products'] = products
    asset_data['tags'] = ['wordpress']
    assets.append(asset_data)
    return assets

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

def get_inventory(args):
    if not nmap_exists():
        logging.error('nmap CLI not found')
        return None

    if args.hosts == None:
        args.hosts = get_private_ip_cidrs()
    else:
        args.hosts = args.hosts.split()
    assets = []
    for host in args.hosts:
        logging.info("Fingerprinting "+host)
        cmdarr = [NMAP + ' -oX - -sV --script http-wordpress-enum -A -PN -T4 -F '+host]
        try:
            out = subprocess.check_output(cmdarr, shell=True)
            out = out.decode(args.encoding)
        except subprocess.CalledProcessError:
            logging.error("Error running nmap command")
            return None 

        dom = parseString(out)
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
            if 'linux linux kernel' in products:
                ostype = 'Generic Linux'
            elif 'microsoft windows' in products:
                ostype = 'Generic Windows'
            else:
                ostype = 'Unknown'

            # check for wordpress output
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
                            products.append(prodstr)
            asset_data = {}
            asset_data['id'] = addr 
            asset_data['name'] = hostname 
            asset_data['type'] = 'Other' 
            asset_data['owner'] = args.handle
            asset_data['products'] = products 
            asset_tags = ["DISCOVERY_TYPE:Unauthenticated"]
            asset_data['tags'] = asset_tags
            if args.no_ssh_audit == False:
                ssh_issues = linux.run_ssh_audit(args, addr, addr)
                if len(ssh_issues) != 0:
                    asset_data['tags'].append('SSH Audit')
                asset_data['config_issues'] = ssh_issues
            assets.append(asset_data)        
    return assets

