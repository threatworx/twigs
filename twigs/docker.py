import sys
import re
import os
import subprocess
import argparse
import logging
import requests
import json

docker_cli = ""

def docker_available():
    if os.path.isfile("/usr/bin/docker"):
        return "/usr/bin/docker"
    elif os.path.isfile("/usr/local/bin/docker"):
        return "/usr/local/bin/docker"
    return None 

def get_asset_type(args):
    cmdarr = [docker_cli+' run -i -t '+args.image+' /bin/sh -c "/bin/cat /etc/os-release"']
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error determining os type: "+args.image)
        return None 
    if 'CentOS' in out:
        return "CentOS"
    elif 'Ubuntu' in out:
        return "Ubuntu"
    elif 'Debian' in out:
        return "Debian"
    else:
        logging.error('Not a supported os type')
        return None

def get_os_release(args):
    cmdarr = [docker_cli+' run -i -t '+args.image+' /bin/sh -c "/bin/cat /etc/os-release"']
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error determining os type: "+args.image)
        return None 
    for l in out.splitlines():
        if 'PRETTY_NAME' in l:
            return l.split('=')[1].replace('"','')
    return None

def apply_tag(url, asset_id, auth_data, tag):
    url = url + "/assets/tags"
    if tag == None or tag == '':
        return None
    resp = requests.post(url + '?' + auth_data + '&tagname='+tag+'&assetid='+asset_id)
    return None

def pull_image(args):
    cmdarr = [docker_cli, "pull", args.image]
    try:
        out = subprocess.check_output(cmdarr)
    except subprocess.CalledProcessError:
        logging.error("Error pulling docker image: "+args.image)
        return False
    return True

def get_image_id(args):
    cmdarr = [docker_cli, "images", args.image]
    out = ''
    try:
        out = subprocess.check_output(cmdarr)
    except subprocess.CalledProcessError:
        logging.error("Error getting image details: "+args.image)
        return None 
    imageid = None
    for l in out.splitlines():
        if 'REPOSITORY' in l:
            continue
        imageid = l.split()[2]
        break
    return imageid

def discover_rh(args):
    plist = []
    cmdarr = [docker_cli+' run -i -t '+args.image+' /bin/sh -c "/usr/bin/yum list installed"']
    logging.info("Retrieving product details from image")
    yumout = ''
    try:
        yumout = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error running inventory for image: "+args.image)
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
        pkg = pkg.replace('.noarch','')
        pkg = pkg.replace('.i686','')
        pkg = pkg.replace('.x86_64','')
        ver = ver.replace('_','-')
        pkg = pkg.replace('\x1b[1m','')
        pkg = pkg.replace('\x1b[1','')
        pkg = pkg.replace('\x1b(B','')
        pkg = pkg.replace('\x1b(m','')
        pkg = pkg.replace('\x1b[m','')
        if ':' in ver:
            ver = ver.split(':')[1]
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details from image")
    return plist

def discover_ubuntu(args):
    plist = []
    cmdarr = [docker_cli+' run -i -t '+args.image+' /bin/sh -c "/usr/bin/apt list --installed"']
    logging.info("Retrieving product details from image")
    yumout = ''
    try:
        yumout = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error running inventory for image: "+args.image)
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
        pkg = pkg.replace('\x1b[32m','')
        pkg = pkg.replace('\x1b[0m','')
        ver = lsplit[1]
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details from image")
    return plist

def discover(args, atype):
    handle = args.handle
    token = args.token
    instance = args.instance
    asset_id = None
    if args.assetid == None:
        asset_id = args.image
    else:
        asset_id = args.assetid
    asset_name = None
    if args.assetname == None:
        asset_name = args.image
    else:
        asset_name = args.assetname
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')
    url = "https://" + instance + "/api/v1"
    asset_url = url + '/assets/' + asset_id
    auth_data = "handle=" + handle + "&token=" + token + "&format=json"

    plist = None
    if atype == 'CentOS':
        plist = discover_rh(args)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args)

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory image: "+args.image)
        sys.exit(1) 

    resp = requests.get(asset_url + '/type?' + auth_data)
    if resp.status_code != 200:
        # Asset does not exist so create one
        asset_data = "?name=" + asset_name + "&os=" + atype + "&" + auth_data
        resp = requests.post(asset_url + asset_data)
        if resp.status_code == 200:
            # Asset created successfully, so try to set the type for this asset
            logging.info("Successfully created new asset [%s]", asset_id)
            if (atype is not None):
                resp = requests.post(asset_url + '/type/' + atype + '?' + auth_data)
                if resp.status_code == 200:
                    logging.info("Successfully set the type ["+atype+"] for asset [%s]", asset_id)
                else:
                    logging.error("Failed to set type ["+atype+"] for asset [%s]", asset_id)
                    logging.error("Response details: %s", resp.content)
            else:
                logging.error("Unable to detect type of asset...")
                logging.error("Not setting asset type...")
            os = get_os_release(args)
            apply_tag(url, asset_id, auth_data, 'OS_RELEASE:'+os)
            apply_tag(url, asset_id, auth_data, 'Docker')
            apply_tag(url, asset_id, auth_data, 'Container')
            apply_tag(url, asset_id, auth_data, 'Linux')
            apply_tag(url, asset_id, auth_data, atype)
        else:
            logging.error("Failed to create new asset [%s]", asset_id)
            logging.error("Response details: %s", resp.content)
            return
    else:
        # Delete existing products for the asset
        logging.info("Atempting to remove existing products for asset [%s]", asset_id)
        resp = requests.delete(asset_url + "/products?" + auth_data)
        if resp.status_code == 200:
            logging.info("Removed existing products for asset [%s]", asset_id)
        else:
            logging.error("Failed to remove existing products for asset [%s]", asset_id)

    # Set the products for the asset
    logging.info("Atempting to set products for asset [%s]", asset_id)
    products_dict = {}
    products_dict["products"] = plist
    resp = requests.post(asset_url + '/products?' + auth_data, json=products_dict)
    if resp.status_code == 200:
        logging.info("Successfully updated products for asset [%s]", asset_id)
        logging.debug("New products: %s", json.dumps(products_dict["products"]))
    else:
        logging.error("Failed to set products for asset [%s]", asset_id)


def inventory(args):
    docker_cli = docker_available()
    if not docker_cli:
        sys.exit(1)

    if not get_image_id(args):
        if not pull_image(args):
            sys.exit(1)

    atype = get_asset_type(args)
    if not atype:
        sys.exit(1)

    discover(args, atype)
