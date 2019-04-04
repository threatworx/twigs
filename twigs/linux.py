import sys
import platform
import os
import subprocess
import argparse
import logging
import requests
import json
import socket

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

def get_asset_type():
    os_type = platform.dist()[0]
    os_release = get_os_release()
    if "centos" in os_type:
        return "CentOS"
    elif "redhat" in os_type:
        return "Red Hat"
    elif "Ubuntu" in os_type:
        return "Ubuntu"
    elif "Amazon Linux AMI" in os_release:
        return "Amazon Linux"
    else:
        logging.error('Not a supported os type')
        return None

def get_os_release():
    cmdarr = ["/bin/cat /etc/os-release"]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error determining os release")
        return None 
    for l in out.splitlines():
        if 'PRETTY_NAME' in l:
            return l.split('=')[1].replace('"','')
    return None

def discover_rh(args):
    plist = []
    cmdarr = ["/usr/bin/yum list installed"]
    logging.info("Retrieving product details")
    yumout = ''
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
        pkg = pkgsp[0]
        arch = pkgsp[1]
        if ':' in ver:
            ver = ver.split(':')[1]
        ver = ver + "." + arch
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details")
    return plist

def discover_ubuntu(args):
    plist = []
    cmdarr = ["/usr/bin/apt list --installed"]
    logging.info("Retrieving product details")
    yumout = ''
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

def discover(args, atype):
    handle = args.handle
    token = args.token
    instance = args.instance

    asset_id = None
    if args.assetid == None:
        asset_id = get_ip()
    else:
        asset_id = args.assetid

    asset_name = None
    if args.assetname == None:
        asset_name = asset_id
    else:
        asset_name = args.assetname

    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')
    asset_url = "https://" + instance + "/api/v2/assets/"
    auth_data = "?handle=" + handle + "&token=" + token + "&format=json"

    plist = None
    if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux':
        plist = discover_rh(args)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args)

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory")
        sys.exit(1) 

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = handle
    asset_data['products'] = plist
    asset_tags = []
    os = get_os_release()
    asset_tags.append('OS_RELEASE:' + os)
    asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags

    resp = requests.get(asset_url + asset_id + "/" + auth_data)
    if args.impact_refresh_days is not None:
        auth_data = auth_data + "&impact_refresh_days=" + args.impact_refresh_days
    if resp.status_code != 200:
        # Asset does not exist so create one with POST
        resp = requests.post(asset_url + auth_data, json=asset_data)
        if resp.status_code == 200:
            logging.info("Successfully created new asset [%s]", asset_id)
            logging.info("Response content: %s", resp.content)
        else:
            logging.error("Failed to create new asset [%s]", asset_id)
            logging.error("Response details: %s", resp.content)
            return
    else:
        # asset exists so update it with PUT
        resp = requests.put(asset_url + asset_id + "/" + auth_data, json=asset_data)
        if resp.status_code == 200:
            logging.info("Successfully updated asset [%s]", asset_id)
            logging.info("Response content: %s", resp.content)
        else:
            logging.error("Failed to update existing asset [%s]", asset_id)
            logging.error("Response details: %s", resp.content)

def inventory(args):
    atype = get_asset_type()
    if not atype:
        sys.exit(1)

    discover(args, atype)
