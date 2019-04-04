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

def start_docker_container(args):
    cmdarr = [docker_cli+' run -d -i -t '+args.image]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error starting docker container: "+args.image)
        sys.exit(1)
    container_id = out[:12]
    logging.info("Started container with ID ["+container_id+"] from image ["+args.image+"] for discovery")
    return container_id

def stop_docker_container(args, container_id):
    cmdarr = [docker_cli+' stop '+container_id]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error stopping docker container with image ["+args.image+"] and ID ["+container_id+"]")
        sys.exit(1)
    logging.info("Stopped container with ID ["+container_id+"]")

def get_asset_type(args, container_id):
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/bin/cat /etc/os-release"']
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

def get_os_release(args, container_id):
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/bin/cat /etc/os-release"']
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

def discover_rh(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/bin/yum list installed"']
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
        pkgsp = pkg.split(".")
        pkg = pkgsp[0]
        arch = pkgsp[1]
        pkg = pkg.replace('\x1b[1m','')
        pkg = pkg.replace('\x1b[1','')
        pkg = pkg.replace('\x1b(B','')
        pkg = pkg.replace('\x1b(m','')
        pkg = pkg.replace('\x1b[m','')
        if ':' in ver:
            ver = ver.split(':')[1]
        ver = ver + "." + arch
        logging.debug("Found product [%s %s]", pkg, ver)
        plist.append(pkg+' '+ver)
    logging.info("Completed retrieval of product details from image")
    return plist

def discover_ubuntu(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/bin/apt list --installed"']
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

def discover(args, atype, container_id):
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
    asset_url = "https://" + instance + "/api/v2/assets/"
    auth_data = "?handle=" + handle + "&token=" + token + "&format=json"

    plist = None
    if atype == 'CentOS':
        plist = discover_rh(args, container_id)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args, container_id)

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory image: "+args.image)
        stop_docker_container(args, container_id)
        sys.exit(1) 

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = handle
    asset_data['products'] = plist
    asset_tags = []
    os = get_os_release(args, container_id)
    asset_tags.append('OS_RELEASE:' + os)
    asset_tags.append('Docker')
    asset_tags.append('Container')
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
    global docker_cli
    docker_cli = docker_available()
    if not docker_cli:
        sys.exit(1)

    if not get_image_id(args):
        if not pull_image(args):
            sys.exit(1)

    container_id = start_docker_container(args)
    atype = get_asset_type(args, container_id)
    if not atype:
        stop_docker_container(args, container_id)
        sys.exit(1)

    discover(args, atype, container_id)
    stop_docker_container(args, container_id)
