import sys
import platform
import os
import tempfile
import shutil
import uuid
import subprocess
import logging
import socket
import csv
import ipaddress
import getpass
import base64
import json
import pkg_resources
import importlib
import traceback
import warnings
with warnings.catch_warnings():
   warnings.simplefilter("ignore", category=Warning)
   from cryptography.hazmat.backends import default_backend
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   from cryptography.fernet import Fernet
from . import utils
from . import plugin_processor

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

def discover_alpine(args, host):
    plist = []
    cmdarr = ["/sbin/apk list"]
    logging.info("Retrieving product details")
    pkgout = utils.run_cmd_on_host(args, host, cmdarr)

    begin = False
    for l in pkgout.splitlines():
        if l.startswith('WARNING:'):
            continue
        pkg = l.split()[0]
        ps = pkg.split('-')
        ver = ps[-2] + '-' + ps[-1]
        pkg = pkg.replace('-'+ver, '')
        pkg = pkg + ' ' + ver
        logging.debug("Found product [%s]", pkg)
        plist.append(pkg)
    logging.info("Completed retrieval of product details")
    return plist

def discover_macos(args, host):
    plist = []
    cmdarr = ["ls -la /Applications/"]
    logging.info("Retrieving product details")
    pkgout = utils.run_cmd_on_host(args, host, cmdarr)
    for l in pkgout.splitlines():
        l = l.strip()
        if l.startswith("d") and l.endswith(".") == False:
            tokens = l.split()
            app_name_tokens = tokens[8:] # there are 8 other fields apart from directory name
            app_name = " ".join(app_name_tokens)
            cmd = "defaults read \"/Applications/%s/Contents/Info.plist\" CFBundleShortVersionString" % app_name
            cmdarr = [cmd]
            out = utils.run_cmd_on_host(args, host, cmdarr, False)
            app_name = app_name[:-4]
            if out is not None:
                out = out.strip()
                app_name = app_name + " " + out
            plist.append(app_name)

    # Look for packages from any package manager
    
    # Home brew
    cmdarr = ["which brew"]
    out = utils.run_cmd_on_host(args, host, cmdarr, False)
    if out is not None and len(out.strip()) > 0:
        # Home brew is present
        cmdarr = ["brew list --versions"]
        pkgout = utils.run_cmd_on_host(args, host, cmdarr)
        if pkgout is not None:
            for l in pkgout.splitlines():
                plist.append(l.strip())
        
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

def discover_suse(args, host):
    plist = []
    cmdarr = ["/bin/rpm -qa"]
    logging.info("Retrieving product details")
    rpmout = utils.run_cmd_on_host(args, host, cmdarr)

    for l in rpmout.splitlines():
        l = l.strip()
        l_tokens = l.split('-')
        tokens_len = len(l_tokens)
        pkg = "-".join(l_tokens[:-2])
        plist.append(pkg+' '+l_tokens[-2]+'-'+l_tokens[-1])
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
                            password = password.encode()
                    else:
                        password = args.password
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
                        row['userpwd'] = f.decrypt(epass.encode('utf-8'))
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
                            if sys.version_info[0] < 3:
                                startip = ipaddress.IPv4Address(unicode(tokens[0]))
                                endip = ipaddress.IPv4Address(unicode(tokens[1]))
                            else:
                                startip = ipaddress.IPv4Address(tokens[0])
                                endip = ipaddress.IPv4Address(tokens[1])
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
                            if sys.version_info[0] < 3:
                                cidrs = [ipaddress.ip_network(unicode(row['hostname'],"ascii"))]
                            else:
                                cidrs = [ipaddress.ip_network(row['hostname'])]
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
            # create new file with secured information. This will be renamed subsequently
            new_csv_file = uuid.uuid4().hex
            new_csv_file = tempfile.gettempdir() + os.path.sep + new_csv_file + ".csv"
            if os.path.isfile(new_csv_file):
                os.remove(new_csv_file)
            try:
                # secure the new rows in the file
                with open(new_csv_file, mode='w') as csvfile:
                    fieldnames = ['hostname','userlogin','userpwd','privatekey','assetname']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_NONE, escapechar='\\')
                    writer.writeheader()
                    for h in remote_hosts:
                        if h['userpwd'] != '' and not h['userpwd'].startswith('__SECURE__:'):
                            h['userpwd'] = '__SECURE__:'+f.encrypt(h['userpwd'].encode('utf-8')).decode('utf-8')
                        del h['remote']
                        writer.writerow(h)
            except Exception as err:
                logging.error("Unable to save secured CSV file")
                logging.error("%s", err)
                os.remove(new_csv_file)
                return None
            os.remove(host_list_file)
            shutil.copyfile(new_csv_file, host_list_file)
            os.remove(new_csv_file)
            logging.info("Host list file secured")
            return None
        else:
            return discover_hosts(args, remote_hosts)
    else:
        host = { }
        host['assetid'] = utils.get_ip() if args.assetid is None or args.assetid.strip() == "" else args.assetid
        host['assetname'] = host['assetid'] if args.assetname is None or args.assetname.strip() == "" else args.assetname
        host['hostname'] = utils.get_ip()
        host['remote'] = False
        hosts = [ host ]
        return discover_hosts(args, hosts)

def discover_hosts(args, hosts):
    assets = []
    host_bm_pkg_missing = False
    host_bm_pn = "twigs_host_benchmark"
    try:
        pkg_resources.get_distribution(host_bm_pn)
    except pkg_resources.DistributionNotFound:
        logging.warning("[twigs_host_benchmark] package is not installed. Unable to run host benchmark assessment")
        logging.warning("Please install using command [sudo (pip|pip3) install twigs_host_benchmark]")
        host_bm_pkg_missing = True
    for host in hosts:
        asset = discover_host(args, host)
        if asset is not None:
            if args.no_ssh_audit == False:
                ssh_config_issues = []
                try:
                    ssh_config_issues = run_ssh_audit(args, asset['id'], host['hostname'])
                except Exception as e:
                    logging.error("Error parsing ssh audit: %s" % str(e))
                    logging.error(traceback.format_exc())
                asset['config_issues'] = ssh_config_issues
                if len(ssh_config_issues) != 0:
                    asset['tags'].append('SSH Audit')

            if args.no_host_benchmark == False and host_bm_pkg_missing == False:
                # Run host benchmark
                host_bm_module = importlib.import_module("%s.%s" % (host_bm_pn, host_bm_pn))
                run_host_benchmark = getattr(host_bm_module, "run_host_benchmark")
                host_bm_issues = run_host_benchmark(host, asset['id'], args)
                if len(host_bm_issues) > 0:
                    asset['tags'].append('Host Benchmark')
                    if asset.get('config_issues') is None:
                        asset['config_issues'] = host_bm_issues
                    else:
                        asset['config_issues'].extend(host_bm_issues)

            assets.append(asset)
    return assets

def discover_host(args, host):

    logging.info("Checking if host [%s] is reachable", host['hostname'])
    if not check_host_up(host):
        logging.error("Host is not reachable [%s]", host['hostname'])
        return None

    logging.info("Started inventory discovery for asset [%s]", host['hostname'])

    os = utils.get_os_release(args, host)
    if os is None:
        logging.error("Failed to identify OS for asset [%s]", host['hostname'])
        return None

    atype = utils.get_asset_type(os)
    if atype is None:
        logging.error("Could not determine asset type for asset [%s]", host['hostname'])
        return None

    asset_id = utils.get_unique_asset_id(args, host, atype)
    if asset_id is None:
        logging.warning("Could not get Identifier for Asset [%s]", host['hostname'])
        # Fallback to IP
        asset_id = host['hostname']
        logging.warning("Using Hostname/IP [%s] for Asset [%s] as Identifier", asset_id, host['hostname'])

    asset_name = host['assetname'] if host.get('assetname') is not None and len(host['assetname']) > 0 else asset_id

    asset_id = asset_id.replace(':','')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')

    plist = None
    if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux' or atype == 'Oracle Linux':
        plist = discover_rh(args, host)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args, host)
    elif atype == 'FreeBSD':
        plist = discover_freebsd(args, host)
    elif atype == 'OpenBSD':
        plist = discover_openbsd(args, host)
    elif atype == "Mac OS":
        plist = discover_macos(args, host)
    elif atype == "Alpine Linux":
        plist = discover_alpine(args, host)
    elif atype == "Suse":
        plist = discover_suse(args, host)

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
    if atype != "Mac OS":
        asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags

    plugin_processor.process_plugins(asset_data, host, args, '/')

    logging.info("Completed inventory discovery for asset [%s]", asset_id)

    return asset_data

def run_ssh_audit(args, assetid, ip):
    logging.info("Running ssh audit for "+ip)
    issue_list = []
    python_cmd = "python3"
    if sys.version_info.major < 3:
        python_cmd = "python"
    SSH_AUDIT_PATH = python_cmd + " " + os.path.dirname(os.path.realpath(__file__)) + '/ssh-audit.py'
    audit_out = ''
    try:
        cmd = SSH_AUDIT_PATH + ' -nv ' +ip
        cmdarr = [cmd]
        dev_null_device = open(os.devnull, "w")
        audit_out = subprocess.check_output(cmdarr, stderr=dev_null_device, shell=True)
        audit_out = audit_out.decode(args.encoding)
        dev_null_device.close()
    except subprocess.CalledProcessError as e:
        logging.error("Error running ssh audit: %s" % str(e))
        logging.error(traceback.format_exc())
        return issue_list
    key_issues = {}
    recs = {}
    for l in audit_out.splitlines():
        if l.strip() == '':
            continue
        larr = l.split()
        rtype = larr[0].strip()
        if rtype not in ['(cve)','(kex)','(key)','(enc)','(mac)','(rec)']:
            continue
        if ' [info] ' in l:
            continue
        if rtype == '(cve)':
            issue = { }
            issue['twc_id'] = 'ssh-audit: '+larr[1]
            title = l.split('CVSSv2:')[1].split(')')[1]
            cvss_score = l.split('CVSSv2:')[1].split(')')[0]
            issue['twc_title'] = 'ssh-audit: '+ larr[1]
            issue['details'] = larr[1]+'\n'+title+'\nCVSS Score '+cvss_score 
            issue['rating'] = utils.get_rating(cvss_score)
            issue['asset_id'] = assetid
            issue['object_id'] = ip
            issue['object_meta'] = ''
            issue['type'] = 'SSH'
            issue_list.append(issue)
        elif rtype in ['(kex)','(key)','(enc)','(mac)']:
            algo = larr[1]
            if algo not in key_issues:
                key_issues[algo] = {}
                key_issues[algo]['type'] = larr[0].replace('(','').replace(')','')
                rating = l.split('--')[1].split()[0]
                if rating == '[fail]':
                    rating = '4'
                else:
                    rating = '3'
                key_issues[algo]['rating'] = rating 
                detail = l.split('--')[1].split(']')[1].strip()
                title = ""
                if rtype == '(kex)':
                    title = 'ssh-audit: Unsafe key exchange - '+algo
                elif rtype == '(key)':
                    title = 'ssh-audit: Unsafe key - '+algo
                elif rtype == '(mac)':
                    title = 'ssh-audit: Unsafe mac algorithm - '+algo
                elif rtype == '(enc)':
                    title = 'ssh-audit: Unsafe encryption - '+algo
                key_issues[algo]['title'] = title 
                key_issues[algo]['details'] = detail 
            else:
                detail = l.split('--')[1].split(']')[1].strip()
                if 'details' in key_issues[algo]:
                    key_issues[algo]['details'] = key_issues[algo]['details'] + '\n'+ detail
                else:
                    key_issues[algo]['details'] = detail
        elif rtype == '(rec)':
            algo = larr[1][1:]
            if algo not in key_issues:
                key_issues[algo] = {}
                key_issues[algo]['details'] = ''
            reco = 'Recommentation: '+l.split('--')[1].strip()
            key_issues[algo]['details'] = key_issues[algo]['details'] + '\n'+ reco 
    for k in key_issues:
        if 'type' not in key_issues[k]:
            continue
        issue = {}
        issue['twc_id'] = 'ssh-audit-'+key_issues[k]['type'] + '-' + k 
        issue['twc_title'] = key_issues[k]['title']
        issue['details'] = key_issues[k]['details']
        issue['rating'] = key_issues[k]['rating']
        issue['object_id'] = k
        issue['asset_id'] = assetid
        issue['object_meta'] = '' 
        issue['type'] = 'SSH'
        issue_list.append(issue)

    logging.info("ssh audit completed "+ip)
    return issue_list

def get_inventory(args):
    return discover(args)
