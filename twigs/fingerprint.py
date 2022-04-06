import sys
import platform
import os
import subprocess
import logging
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

def get_inventory(args):
    if not nmap_exists():
        logging.error('nmap CLI not found')
        return None

    logging.info("Fingerprinting "+args.hosts)
    cmdarr = [NMAP + ' -oX - -sV -PN -T4 -F '+args.hosts]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Error determining OS release")
        return None 

    assets = []
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
