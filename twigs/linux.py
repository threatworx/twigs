import sys
import platform
import os
import subprocess
import logging
import socket
import csv
import ipaddress
import paramiko
import getpass
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_asset_type(os):
    if "CentOS" in os:
        return "CentOS"
    elif "Red Hat" in os:
        return "Red Hat"
    elif "Ubuntu" in os:
        return "Ubuntu"
    elif "Debian" in os:
        return "Debian"
    elif "Amazon Linux AMI" in os:
        return "Amazon Linux"
    else:
        logging.error('Not a supported OS type')
        return None

def run_remote_ssh_command(args, host, command):
    assetid = host['assetid'] if host.get('assetid') is not None else host['hostname']
    output = ''
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
        if host.get('userpwd') is not None and len(host['userpwd']) > 0:
            client.connect(host['hostname'],username=host['userlogin'],password=host['userpwd'])
        elif host.get('privatekey') is not None and len(host['privatekey']) > 0:
            client.connect(host['hostname'],username=host['userlogin'],key_filename=host['privatekey'])
        else:
            client.connect(host['hostname'],username=host['userlogin'])
        stdin, stdout, stderr = client.exec_command(command)
        for line in stdout:
            output = output + line
        client.close()
    except paramiko.ssh_exception.AuthenticationException as e:
        logging.info("Authentication failed for asset [%s], host [%s]", assetid, host['hostname'])
        logging.info("Exception: %s", e)
        output = None
    except paramiko.ssh_exception.SSHException as e:
        logging.info("SSHException while connecting to asset [%s], host [%s]", assetid, host['hostname'])
        logging.info("Exception: %s", e)
        output = None
    except socket.error as e:
        logging.info("Socket error while connection to asset [%s], host [%s]", assetid, host['hostname'])
        logging.info("Exception: %s", e)
        output = None
    except:
        logging.info("Unknown error running remote discovery for asset [%s], host [%s]: [%s]", assetid, host['hostname'], sys.exc_info()[0])
        output = None
    finally:
        return output

def get_os_release(args, host):
    cmdarr = ["/bin/cat /etc/os-release"]
    if host['remote']:
        out = run_remote_ssh_command(args, host, cmdarr[0])
        if out is None:
            return None
    else:
        try:
            out = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error determining OS release")
            return None 

    output_lines = out.splitlines()
    for l in output_lines:
        if 'PRETTY_NAME' in l:
            return l.split('=')[1].replace('"','')
    return None

def discover_rh(args, host):
    plist = []
    cmdarr = ["/usr/bin/yum list installed"]
    logging.info("Retrieving product details")
    if host['remote']:
        yumout = run_remote_ssh_command(args, host, cmdarr[0])
        if yumout is None:
            return None
    else:
        try:
            yumout = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error running inventory")
            return None 

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
    if host['remote']:
        yumout = run_remote_ssh_command(args, host, cmdarr[0])
        if yumout is None:
            return None
    else:
        try:
            yumout = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error running inventory")
            return None 

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
                if '/' in row['hostname']: # CIDR is specified, then expand it
                    logging.info("Enumerating IPs based on specified CIDR [%s]", row['hostname'])
                    net = ipaddress.ip_network(unicode(row['hostname'],"ascii"))
                    for a in net:
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
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
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
        host['assetid'] = get_ip() if args.assetid is None else args.assetid
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

    logging.info("Started inventory discovery for asset [%s]", asset_id)

    os = get_os_release(args, host)
    if os is None:
        logging.error("Failed to identify OS for asset [%s]", asset_id)
        return None

    atype = get_asset_type(os)
    if atype is None:
        logging.error("Could not determine asset type for asset [%s]", asset_id)
        return None

    plist = None
    if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux':
        plist = discover_rh(args, host)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args, host)

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
