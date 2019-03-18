import sys
import re
import os
import shutil
import subprocess
import argparse
import logging
import requests
import json
import shutil
import tempfile
import glob
import traceback
import requirements
from xml.dom import minidom

GIT_PATH = '/usr/bin/git'

def apply_tag(url, asset_id, auth_data, tag):
    url = url + "/assets/tags"
    if tag == None or tag == '':
        return None
    resp = requests.post(url + '?' + auth_data + '&tagname='+tag+'&assetid='+asset_id)
    return None

def find_files(localpath, filename):
    ret_files = []
    for root, subdirs, files in os.walk(localpath):
        for fname in files:
            file_path = os.path.join(root, fname)
            if file_path.endswith(filename):
                ret_files.append(file_path)
    return ret_files

def discover_package_json(f):
    plist = []
    files = find_files(localpath, 'package.json')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        contents = contents.strip()
        cjson = ''
        try:
            cjson = json.loads(contents)
        except Exception:
            print "Error parsing package.json contents"
            return None
        if 'dependencies' in cjson:
            ddict = cjson['dependencies']
            for d in ddict:
                pname = d + ' ' + ddict[d]
                pname = pname.replace('^','')
                pname = pname.replace('~','')
                pname = pname.replace('<','')
                pname = pname.replace('>','')
                pname = pname.replace('=','')
                if pname not in assetinfo:
                    assetinfo.append(pname)
        if 'devDependencies' in cjson:
            ddict = cjson['devDependencies']
            for d in ddict:
                pname = d + ' ' + ddict[d]
                pname = pname.replace('^','')
                pname = pname.replace('~','')
                pname = pname.replace('<','')
                pname = pname.replace('>','')
                pname = pname.replace('=','')
                if pname not in assetinfo:
                    assetinfo.append(pname)
        if 'optionalDependencies' in cjson:
            ddict = cjson['optionalDependencies']
            for d in ddict:
                pname = pname.replace('^','')
                pname = pname.replace('~','')
                pname = pname.replace('<','')
                pname = pname.replace('>','')
                pname = pname.replace('=','')
                pname = d + ' ' + ddict[d]
                if pname not in assetinfo:
                    plist.append(pname)
        return plist 

def discover_packages_config(f):
    plist = []
    files = find_files(localpath, 'packages.config')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            print "Error parsing package config contents"
            return None
        plist = xmldoc.getElementsByTagName('package')
        for p in plist:
            libname = p.getAttribute('id')
            libver = p.getAttribute('version')
            pname = libname + ' ' + libver
            if pname not in assetinfo:
                plist.append(pname)
    return plist 

def discover_yarn(f):
    plist = []
    files = find_files(localpath, 'yarn.lock')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        cline = contents.splitlines()
        dparse = False
        for index, l in enumerate(cline):
            if l.endswith(':') and 'dependencies' not in l:
                dparse = False
                libname = l.split('@')[0]
                vline = cline[index+1]
                libver = vline.split()[1].replace('"','')
                pname = libname+' '+libver
                if pname not in assetinfo:
                    assetinfo.append(pname)
            if l.endswith(':') and 'dependencies' in l:
                dparse = True
                continue
            if dparse:
                pname = l.strip()
                pname = pname.replace('"','')
                pname = pname.replace('~','')
                if pname == '':
                    dparse = False
                    continue
                if pname not in assetinfo:
                    plist.append(pname)
    return plist 

def discover_ruby(f):
    plist = []
    files = find_files(localpath, 'gemfile.lock')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        cline = contents.splitlines()
        specsfound = False
        for index, l in enumerate(cline):
            l = l.strip()
            if l.startswith('specs:'):
                specsfound = True
                continue
            if l == '':
                break
            if specsfound:
                ls = l.split()
                gname = ls[0]
                gver = ''
                if len(ls) > 1:
                    gver = ls[1]
                    gver = re.findall(r'([0-9]+[0-9a-z]*(\.[0-9a-z]+)+)', gver)
                    if gver:
                        gver = gver[0][0]
                    else:
                        gver = ''
                pname = gname + ' ' + gver
                pname = pname.strip()
                if pname not in assetinfo:
                    plist.append(pname)
    return plist 

def discover_python(args, localpath):
    plist = []
    files = find_files(localpath, 'requirements.txt')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        req = requirements.parse(fp)
        for r in req:
            prod = r.name
            if len(r.specs) > 0:
                prod = prod + ' ' + r.specs[0][1]
                if prod not in plist:
                    plist.append(prod)
    return plist

def discover(args, localpath):
    handle = args.handle
    token = args.token
    instance = args.instance
    asset_id = None
    if args.assetid == None:
        asset_id = args.type
    else:
        asset_id = args.assetid
    asset_name = None
    if args.assetname == None:
        asset_name = args.type
    else:
        asset_name = args.assetname
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')
    url = "https://" + instance + "/api/v1"
    asset_url = url + '/assets/' + asset_id
    auth_data = "handle=" + handle + "&token=" + token + "&format=json"

    atype = 'Open Source' 
    plist = None
    if args.type == 'python':
        plist = discover_python(args, localpath)
    elif args.type == 'ruby':
        plist = discover_ruby(args, localpath)
    elif args.type == 'yarn':
        plist = discover_yarn(args, localpath)
    elif args.type == 'dotnet':
        plist = discover_packages_config(args, localpath)
    elif args.type == 'nodejs':
        plist = discover_package_json(args, localpath)
    else:
        logging.error("Type not supported")
        sys.exit(1) 

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory repo "+args.repo)
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
            apply_tag(url, asset_id, auth_data, args.type)
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
    path = None
    if args.repo.startswith('http'):
        path = tempfile.mkdtemp()
        try:
            cmdarr = [GIT_PATH, 'clone', args.repo, path+'/.']
            out = subprocess.check_output(cmdarr)
        except:
            print traceback.format_exc()
            logging.error('Error cloning repo locally')
            sys.exit(1) 
            os.remove(path)
    elif os.path.isdir(args.repo):
        path = args.repo
    else:
        logging.error('Not a valid repo')
        sys.exit(1) 

    discover(args, path)

    if args.repo.startswith('http'):
        shutil.rmtree(path)
