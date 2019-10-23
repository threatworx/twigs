import sys
import re
import os
import shutil
import stat
import subprocess
import logging
import json
import tempfile
import pefile
import glob
import traceback
import requirements
from xml.dom import minidom
from pygit2 import clone_repository

SUPPORTED_TYPES = ['pip', 'ruby', 'yarn', 'nuget', 'npm', 'maven', 'gradle', 'dll']

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
    prop_dict = None
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
        if prop_dict is None:
            prop_dict = { }
            curr_prop_dict = prop_dict
        else:
            curr_prop_dict = prop_dict.copy()

        version_elements = xmldoc.getElementsByTagName('version')
        for ve in version_elements:
            if ve.parentNode.nodeName == 'project':
                curr_prop_dict['project.version'] = ve.childNodes[0].data
                break

        prop_list = xmldoc.getElementsByTagName('properties')
        if len(prop_list) > 0:
            for p in prop_list:
                for item in p.childNodes:
                    if item.nodeType == item.TEXT_NODE or item.nodeType == item.COMMENT_NODE:
                        continue
                    prop_name = item.nodeName
                    prop_value = item.childNodes[0].data
                    if prop_value.startswith('${'):
                        # Try to look-up value from prop_dict
                        lookup_prop = prop_value[2:-1]
                        prop_value = prop_dict.get(lookup_prop)
                    if prop_value is not None:
                        curr_prop_dict[prop_name] = prop_value

        dlist = xmldoc.getElementsByTagName('dependency')
        for d in dlist:
            gid = d.getElementsByTagName('groupId')
            if len(gid) == 0:
                gid = None
            else:
                gid = gid[0]
            aid = d.getElementsByTagName('artifactId')
            if len(aid) == 0:
                continue
            else:
                aid = aid[0]
            ver = d.getElementsByTagName('version')
            if len(ver) == 0:
                ver = None 
            else:
                ver = ver[0]
            libgname = ''
            if gid != None:
                libgname = gid.childNodes[0].data
            libname = aid.childNodes[0].data
            libver = ''
            if ver != None:
                libver = ver.childNodes[0].data
                if libver.startswith('${'):
                    prop_value = curr_prop_dict.get(libver[2:-1])
                    if prop_value is not None:
                        libver = prop_value
            if libgname == '':
                pname = libname + ' ' + libver
            else:
                pname = libgname + ':' + libname + ' ' + libver
            pname = pname.strip()
            if pname not in plist:
                plist.append(pname)
    return plist 

def discover_gradle(args, localpath):
    plist = []
    files = find_files(localpath, 'dependencies.gradle')
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        for l in contents.splitlines():
            if 'group:' in l and 'name:' in l and 'version:' in l:
                arr = l.split(',')
                gname = arr[0].split('group:')[1].strip()
                lname = arr[1].split('name:')[1].strip()
                ver = arr[2].split('version:')[1].strip()
                pname = gname + ':' + lname + ' ' + ver
                pname = pname.replace("'","")
                if pname not in plist:
                    plist.append(pname)
    return plist 

def discover_package_json(args, localpath):
    plist = []
    files = find_files(localpath, 'package.json')
    more_files = find_files(localpath, 'package-lock.json')
    files.extend(more_files)
    for file_path in files:
        fp = open(file_path, 'r')
        if fp == None:
            continue
        contents = fp.read()
        contents = contents.strip()
        if len(contents) == 0:
            logging.error("Error empty file [%s]...skipping it!", file_path)
            continue
        cjson = ''
        try:
            cjson = json.loads(contents)
        except Exception:
            logging.error("Error parsing package.json contents - %s", file_path)
            continue
        if 'name' in cjson and 'version' in cjson:
            pname = cjson['name'] + ' ' + cjson['version']
            if pname not in plist:
                plist.append(pname)
        if 'dependencies' in cjson:
            ddict = cjson['dependencies']
            for d in ddict:
                content = ddict[d]
                if isinstance(content, dict):
                    ver = content['version']
                    pname = d + ' ' + ver
                    if pname not in plist:
                        plist.append(pname)
                    req_dict = content.get('requires')
                    if req_dict is None:
                        continue
                    for req_pname in req_dict:
                        pname = req_pname + ' ' + req_dict[req_pname]
                        if pname not in plist:
                            plist.append(pname)
                else:
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
        temp_plist = xmldoc.getElementsByTagName('package')
        for p in temp_plist:
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
                if l.startswith('"'):
                    l = l[1:]
                if l.startswith('@'):
                    libname = '@' + l.split('@')[1]
                else:
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

def LOWORD(dword):
    return dword & 0x0000ffff

def HIWORD(dword): 
    return dword >> 16

def get_dll_version(path):

    pe = pefile.PE(path)
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        ms = pe.VS_FIXEDFILEINFO[0].FileVersionMS
        ls = pe.VS_FIXEDFILEINFO[0].FileVersionLS
        return "%d.%d.%d.%d" % (HIWORD (ms), LOWORD (ms), HIWORD (ls), LOWORD (ls))
    else:
        return None

def discover_dll(args, localpath):
    plist = []
    files = find_files(localpath, '.dll')
    for file_path in files:
        dll_version = get_dll_version(file_path)
        if dll_version is None:
            continue
        dll_details = os.path.basename(file_path) + " " + dll_version
        plist.append(dll_details)
    return plist

def discover_specified_type(repo_type, args, localpath):
    if repo_type not in SUPPORTED_TYPES:
        logging.error("Type not supported")
        sys.exit(1) 

    plist = []
    if repo_type == 'pip':
        plist = discover_python(args, localpath)
    elif repo_type == 'ruby':
        plist = discover_ruby(args, localpath)
    elif repo_type == 'yarn':
        plist = discover_yarn(args, localpath)
    elif repo_type == 'nuget':
        plist = discover_packages_config(args, localpath)
    elif repo_type == 'npm':
        plist = discover_package_json(args, localpath)
    elif repo_type == 'maven':
        plist = discover_pom_xml(args, localpath)
    elif repo_type == 'gradle':
        plist = discover_gradle(args, localpath)
    elif repo_type == 'dll':
        plist = discover_dll(args, localpath)

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
    asset_id = asset_id.replace(' ','-')
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace(' ','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')

    atype = 'Source Repository'
    plist = []
    asset_tags = []
    tech2prod_dict = { }
    if args.type is None:
        # If no type is specified, then process all supported types
        for repo_type in SUPPORTED_TYPES:
            temp_list = discover_specified_type(repo_type, args, localpath)
            if temp_list is not None and len(temp_list) > 0:
                tech2prod_dict[repo_type] = temp_list
                plist.extend(temp_list)
                asset_tags.append(repo_type)
    else:
        plist = discover_specified_type(args.type, args, localpath)
        if plist is not None and len(plist) > 0:
            tech2prod_dict[args.type] = plist
        asset_tags.append(args.type)

    if plist == None or len(plist) == 0:
        if args.type is not None:
            logging.error("Unable to identify any dependencies of [%s] type in specified repo [%s]", args.type, args.repo)
        else:
            logging.error("Unable to identify any dependencies of all supported types in specified repo [%s]", args.repo)
        sys.exit(1)

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = plist
    asset_data['tags'] = asset_tags
    if len(tech2prod_dict) > 0:
        asset_data['compliance_metadata'] = {"source_metadata": {"technology_products":tech2prod_dict}}
    
    return [ asset_data ]

# Note this error routine assumes that the file was read-only and hence could not be deleted
def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

def get_inventory(args):
    path = None
    if args.repo.startswith('http'):
        path = tempfile.mkdtemp()
        new_repo = None
        try:
            logging.info("Cloning repo to temporary local directory...")
            new_repo = clone_repository(args.repo, path)
            new_repo.free()
        except:
            print traceback.format_exc()
        if new_repo is None:
            logging.error('Error cloning repo locally')
            shutil.rmtree(path, onerror = on_rm_error)
            sys.exit(1)
    elif os.path.isdir(args.repo):
        path = args.repo
    else:
        logging.error('Not a valid repo')
        sys.exit(1) 

    logging.info("Performing asset discovery...")
    assets = discover_inventory(args, path)

    if args.repo.startswith('http'):
        shutil.rmtree(path, onerror = on_rm_error)

    return assets
