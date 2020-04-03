import sys
import platform
import os
import subprocess
import logging
import socket
import csv
import ipaddress
import getpass
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import utils

def check_host_up(host):
    if not host['remote']:
        return True
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        result = sock.connect_ex((host['hostname'], 22))
        if result == 0:
            return True
        else:
            return False
    except socket.timeout:
        logging.error("Socket timeout")
        return False

def discover_openbsd(args, host):
    plist = []
    cmdarr = ["/usr/sbin/pkg_info -A"]
    logging.info("Retrieving product details")
    pkgout = utils.run_cmd_on_host(args, host, cmdarr)

    begin = False
    for l in pkgout.splitlines():
        lsplit = l.split()
        pkgline = lsplit[0]
        ldash = pkgline.rfind('-')
        pkg = pkgline[:ldash] + ' ' + pkgline[ldash + 1:]
        logging.debug("Found product [%s]", pkg)
        plist.append(pkg)
    logging.info("Completed retrieval of product details")
    return plist


def discover_freebsd(args, host):
    plist = []
    cmdarr = ["/usr/sbin/pkg info"]
    logging.info("Retrieving product details")
    pkgout = utils.run_cmd_on_host(args, host, cmdarr)

    begin = False
    for l in pkgout.splitlines():
        lsplit = l.split()
        pkgline = lsplit[0]
        ldash = pkgline.rfind('-')
        pkg = pkgline[:ldash] + ' ' + pkgline[ldash + 1:]
        logging.debug("Found product [%s]", pkg)
        plist.append(pkg)
    logging.info("Completed retrieval of product details")
    return plist

def discover_rh(args, host):
    plist = []
    cmdarr = ["/usr/bin/yum list installed"]
    logging.info("Retrieving product details")
    yumout = utils.run_cmd_on_host(args, host, cmdarr)

    begin = False
    for l in yumout.splitlines():
        if 'Installed Packages' in l:
            begin = True
            continue
        if not begin:
            continue
        lsplit = l.split()
        pkg = lsplit[0]
        if len(lsplit) > 1:
            ver = lsplit[1]
        else:
            ver = ''
        pkgsp = pkg.split(".")
        if len(pkgsp) > 1:
            pkg = pkgsp[0]
            arch = pkgsp[1]
        else:
            pkg = pkgsp[0]
            arch = "noarch"

        if ':' in ver:
            ver = ver.split(':')[1]
        ver = ver + "." + arch
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details")
    return plist

def discover_ubuntu(args, host):
    plist = []
    cmdarr = ["/usr/bin/apt list --installed"]
    logging.info("Retrieving product details")
    yumout = utils.run_cmd_on_host(args, host, cmdarr)

    begin = False
    for l in yumout.splitlines():
        if 'Listing...' in l:
            begin = True
            continue
        if not begin:
            continue
        if l.strip() == '':
            continue
        lsplit = l.split()
        pkg = lsplit[0].split('/')[0]
        ver = lsplit[1]
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details")
    return plist

def discover(args):
    handle = args.handle
    token = args.token
    instance = args.instance

    host_list_file = args.remote_hosts_csv
    if host_list_file == None:
        host_list_file = args.host_list

    if host_list_file is not None:
        with open(host_list_file, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file, quoting=csv.QUOTE_NONE, escapechar='\\')
            password = None
            remote_hosts = []
            for row in csv_reader:
                if not args.secure and row['userpwd'].startswith('__SECURE__:'):
                    if args.password is None:
                        if password is None:
                            password = getpass.getpass(prompt="Enter password: ")
                    else:
                        password = args.password
                    password = password.encode()
                    salt = base64.b64encode(password)
                    kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                            backend=default_backend())
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    f = Fernet(key)
                    try:
                        epass = row['userpwd'].replace('__SECURE__:','')
                        row['userpwd'] = f.decrypt(epass)
                    except:
                        logging.error("Failed to decrypt login details for "+row['hostname'])
                        return None 
                elif row['userpwd'] != '' and not args.secure:
                    logging.warning('Unsecure login information in file. Use --secure to encrypt.')
                if '-' in row['hostname'] or '/' in row['hostname']: # IP range or CIDR is specified, then expand it
                    if '-' in row['hostname']:
                        iprange = row['hostname']
                        iprange = iprange.replace(' ','')
                        tokens = iprange.split('-')
                        if len(tokens) != 2 or len(tokens[0])==0 or len(tokens[1])==0:
                            logging.error("Skipping invalid range [%s]", row['hostname'])
                            continue
                        logging.info("Enumerating IPs based on specified range [%s]", iprange)
                        try:
                            startip = ipaddress.IPv4Address(unicode(tokens[0]))
                            endip = ipaddress.IPv4Address(unicode(tokens[1]))
                            cidrs = []
                            cidrs = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip,endip)]
                        except Exception as e:
                            logging.error("Encountered exception: %s",e)
                            logging.error("Error converting IP range [%s] to CIDRs. Skipping it...", iprange)
                            continue
                        logging.info("Converted IP range [%s] to CIDRs %s", iprange, cidrs)
                    if '/' in row['hostname']:
                        logging.info("Enumerating IPs based on specified CIDR [%s]", row['hostname'])
                        try:
                            cidrs = [ipaddress.ip_network(unicode(row['hostname'],"ascii"))]
                        except Exception as e:
                            logging.error("Encountered exception: %s",e)
                            logging.error("Invalid CIDR [%s] specified. Skipping it...", row['hostname'])
                            continue
                    for cidr in cidrs:
                        for a in cidr:
                            trow = row.copy()
                            trow['hostname'] = str(a)

                            # Remove hard-coded asset ID and name for CIDR, as it will overwrite same asset
                            # These will based on host IP address automatically
                            trow['assetid'] = None
                            trow['assetname'] = None
                        
                            remote_hosts.append(trow)
                            remote_hosts[-1]['remote'] = True
                            logging.info("Enumerated IP: %s", a)
                else:
                    remote_hosts.append(row)
                    remote_hosts[-1]['remote'] = True
        if args.secure:
            # secure the host list
            logging.info("Securing host list file")
            if args.password is None:
                pp1 = getpass.getpass(prompt="Enter password: ")
                pp2 = getpass.getpass(prompt="Re-enter password: ")
                if pp1 != pp2:
                    logging.info("Passwords don't match. Try again.")
                    return None
            else:
                pp1 = args.password
            password = pp1.encode()
            salt = base64.b64encode(password)
            kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            # verify the key if possible
            with open(host_list_file, mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file, quoting=csv.QUOTE_NONE, escapechar='\\')
                for row in csv_reader:
                    try:
                        if row['userpwd'] != '' and row['userpwd'].startswith('__SECURE__:'):
                            epass = row['userpwd'].replace('__SECURE__:','')
                            epass  = f.decrypt(epass)
                    except:
                        logging.error("Invalid password")
                        logging.error("Please use the same password as was used previously to secure the file")
                        return None
            # secure the new rows in the file
            with open(host_list_file, mode='w') as csvfile:
                fieldnames = ['hostname','userlogin','userpwd','privatekey','assetid','assetname']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_NONE, escapechar='\\')
                writer.writeheader()
                for h in remote_hosts:
                    if h['userpwd'] != '' and not h['userpwd'].startswith('__SECURE__:'):
                        h['userpwd'] = '__SECURE__:'+f.encrypt(h['userpwd'])
                    del h['remote']
                    writer.writerow(h)
            logging.info("Host list file secured")
            return None
        else:
            return discover_hosts(args, remote_hosts)
    else:
        host = { }
        host['assetid'] = utils.get_ip() if args.assetid is None else args.assetid
        host['assetname'] = host['assetid'] if args.assetname is None else args.assetname
        host['remote'] = False
        hosts = [ host ]
        return discover_hosts(args, hosts)

def discover_hosts(args, hosts):

    assets = []
    for host in hosts:
        asset = discover_host(args, host)
        if asset is not None:
            assets.append(asset)
    return assets

def discover_host(args, host):

    asset_id = host['assetid'] if host.get('assetid') is not None and len(host['assetid']) > 0 else host['hostname']
    asset_name = host['assetname'] if host.get('assetname') is not None and len(host['assetname']) > 0 else asset_id

    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')

    logging.info("Checking if host [%s] is reachable", asset_id)
    if not check_host_up(host):
        logging.error("Host is not reachable [%s]", asset_id)
        return None

    logging.info("Started inventory discovery for asset [%s]", asset_id)

    os = utils.get_os_release(args, host)
    if os is None:
        logging.error("Failed to identify OS for asset [%s]", asset_id)
        return None

    atype = utils.get_asset_type(os)
    if atype is None:
        logging.error("Could not determine asset type for asset [%s]", asset_id)
        return None

    plist = None
    if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux' or atype == 'Oracle Linux':
        plist = discover_rh(args, host)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args, host)
    elif atype == 'FreeBSD':
        plist = discover_freebsd(args, host)
    elif atype == 'OpenBSD':
        plist = discover_openbsd(args, host)

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory asset [%s]", asset_id)
        return None

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = plist
    asset_tags = []
    asset_tags.append('OS_RELEASE:' + os)
    asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags

    logging.info("Completed inventory discovery for asset [%s]", asset_id)

    return asset_data

def get_inventory(args):
    return discover(args)
