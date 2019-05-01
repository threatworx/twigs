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

def find_files(localpath, filename):
    ret_files = []
    for root, subdirs, files in os.walk(localpath):
        for fname in files:
            file_path = os.path.join(root, fname)
            if file_path.endswith(filename):
                ret_files.append(file_path)
    return ret_files

def discover_pom_xml(args, localpath):
    plist = []
    files = find_files(localpath, 'pom.xml')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            print "Error parsing pom.xml contents"
            return None
        dlist = xmldoc.getElementsByTagName('dependency')
        for d in dlist:
            aid = d.getElementsByTagName('artifactId')[0]
            ver = d.getElementsByTagName('version')[0]
            libname = aid.childNodes[0].data
            libver = ver.childNodes[0].data
            pname = libname + ' ' + libver
            if pname not in plist:
                plist.append(pname)
    return plist 

def discover_package_json(args, localpath):
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
                if pname not in plist:
                    plist.append(pname)
        if 'devDependencies' in cjson:
            ddict = cjson['devDependencies']
            for d in ddict:
                pname = d + ' ' + ddict[d]
                pname = pname.replace('^','')
                pname = pname.replace('~','')
                pname = pname.replace('<','')
                pname = pname.replace('>','')
                pname = pname.replace('=','')
                if pname not in plist:
                    plist.append(pname)
        if 'optionalDependencies' in cjson:
            ddict = cjson['optionalDependencies']
            for d in ddict:
                pname = pname.replace('^','')
                pname = pname.replace('~','')
                pname = pname.replace('<','')
                pname = pname.replace('>','')
                pname = pname.replace('=','')
                pname = d + ' ' + ddict[d]
                if pname not in plist:
                    plist.append(pname)
        return plist 

def discover_packages_config(args, localpath):
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
            if pname not in plist:
                plist.append(pname)
    return plist 

def discover_yarn(args, localpath):
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
                if pname not in plist:
                    plist.append(pname)
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
                if pname not in plist:
                    plist.append(pname)
    return plist 

def discover_ruby(args, localpath):
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
                if pname not in plist:
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
    asset_url = "https://" + instance + "/api/v2/assets/"
    auth_data = "?handle=" + handle + "&token=" + token + "&format=json"

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
    elif args.type == 'pom':
        plist = discover_pom_xml(args, localpath)
    else:
        logging.error("Type not supported")
        sys.exit(1) 

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory repo "+args.repo)
        sys.exit(1)

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = handle
    asset_data['products'] = plist
    asset_tags = []
    asset_tags.append(args.type)
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
