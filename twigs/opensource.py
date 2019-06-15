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
SUPPORTED_TYPES = ['python', 'ruby', 'yarn', 'dotnet', 'nodejs', 'pom']

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

def discover_specified_type(opensource_type, args, localpath):
    if opensource_type not in SUPPORTED_TYPES:
        logging.error("Type not supported")
        sys.exit(1) 

    plist = []
    if opensource_type == 'python':
        plist = discover_python(args, localpath)
    elif opensource_type == 'ruby':
        plist = discover_ruby(args, localpath)
    elif opensource_type == 'yarn':
        plist = discover_yarn(args, localpath)
    elif opensource_type == 'dotnet':
        plist = discover_packages_config(args, localpath)
    elif opensource_type == 'nodejs':
        plist = discover_package_json(args, localpath)
    elif opensource_type == 'pom':
        plist = discover_pom_xml(args, localpath)

    return plist

def get_last_component(repo_path):
    if repo_path.startswith('http:') or repo_path.startswith('https:'):
        return repo_path.rsplit('/',1)[-1]
    else:
        return os.path.basename(os.path.normpath(repo_path))

def discover_inventory(args, localpath):
    default_id_name = get_last_component(args.repo)
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
    if asset_id is None:
        asset_id = default_id_name
    if asset_name is None:
        asset_name = default_id_name
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')

    atype = 'Open Source' 
    plist = []
    asset_tags = []
    if args.type is None:
        # If no type is specified, then process all supported types
        for opensource_type in SUPPORTED_TYPES:
            temp_list = discover_specified_type(opensource_type, args, localpath)
            if temp_list is not None and len(temp_list) > 0:
                plist.extend(temp_list)
                asset_tags.append(opensource_type)
    else:
        plist = discover_specified_type(args.type, args, localpath)
        asset_tags.append(args.type)

    if plist == None or len(plist) == 0:
        logging.error("Could not inventory repo "+args.repo)
        sys.exit(1)

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = plist
    asset_data['tags'] = asset_tags
    
    return [ asset_data ]

def get_inventory(args):
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

    assets = discover_inventory(args, path)

    if args.repo.startswith('http'):
        shutil.rmtree(path)

    return assets
