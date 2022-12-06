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
import re
import zipfile
from xml.dom import minidom
import toml
import re
import ast
import textwrap

from . import utils as lib_utils
from . import code_secrets as lib_code_secrets
from . import sast
from . import iac

GIT_PATH = os.environ.get('GIT_PATH')
if GIT_PATH is None:
    if os.name == 'nt':
        GIT_PATH = 'C:\\Program Files\\Git\\cmd\\git.exe'
    else:
        GIT_PATH = '/usr/bin/git'

SUPPORTED_TYPES = ['pip', 'ruby', 'yarn', 'nuget', 'npm', 'maven', 'gradle', 'dll', 'jar', 'cargo', 'go', 'composer']

def cleanse_semver_version(pv):
    pv = pv.replace('"','')
    pv = pv.replace('~','')
    pv = pv.replace('^','')
    pv = pv.replace('<','')
    pv = pv.replace('>','')
    pv = pv.replace('=','')
    temp_tokens = pv.split()
    if len(temp_tokens) >= 2:
        version = temp_tokens[1]
        version = version.replace('X','0')
        version = version.replace('x','0')
        version = version.replace('*','0')
        pv = temp_tokens[0] + ' ' + version
        # Add any remaining tokens following version (like source)
        for token_index in range(2, len(temp_tokens)):
            pv = pv + " " + temp_tokens[token_index]
    return pv

def discover_composer(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, 'composer.lock')
    if len(files) <= 0:
        files = lib_utils.find_files(localpath, 'composer.json')
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        fp.close()
        composer_json = json.loads(contents)
        if file_path.endswith('composer.json'):
            requires = composer_json['require']
            for pname in requires.keys():
                pver = requires[pname]
                prod = pname + " " + pver + " source:"+file_path
                plist.append(prod)
        else:
            packages = composer_json['packages']
            for p in packages:
                prod = p['name'] + ' ' + p['version'] + ' source:'+file_path
                plist.append(prod)
    return plist, None

def discover_go_mod(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, 'go.mod')
    prop_dict = None
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        fp.close()
        if localpath.startswith('/tmp/'):
            file_path = file_path.replace(localpath+'/','')
        for line in contents.splitlines():
            line = line.strip()
            if line == '' or line.startswith('module ') or line.startswith('go ') or line.startswith('require (') or line.startswith(')') or line.startswith('replace') or line.startswith('exclude'):
                continue
            sp = line.split()
            if len(sp) < 2:
                continue
            ver = sp[1]
            if ver.startswith('v'):
                ver = ver[1:]
            prod = sp[0] + " " + ver + " source:"+file_path
            plist.append(prod)
    return plist, None

def discover_cargo_toml(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, 'Cargo.toml')
    prop_dict = None
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        tdict = toml.loads(contents)
        fp.close()
        if localpath.startswith('/tmp/'):
            file_path = file_path.replace(localpath+'/','')
        if 'dependencies' in tdict:
            for d in tdict['dependencies']:
                vers = str(tdict['dependencies'][d])
                if vers.startswith('{'):
                    if 'version' in tdict['dependencies'][d]:
                        ver = tdict['dependencies'][d]['version']
                    else:
                        continue
                else:
                    ver = tdict['dependencies'][d]
                prod = d + " " + ver
                prod = cleanse_semver_version(prod)
                prod = prod + " source:"+file_path
                plist.append(prod)
    return plist, None

def discover_pom_xml(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, 'pom.xml')
    prop_dict = None
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            logging.error("Unable to parse pom.xml "+file_path)
            continue
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
                    if item.nodeType == item.TEXT_NODE or item.nodeType == item.COMMENT_NODE or len(item.childNodes) == 0:
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
            if localpath.startswith('/tmp/'):
                file_path = file_path.replace(localpath+'/','')
            pname = pname.strip() + " source:"+file_path
            if pname not in plist:
                plist.append(pname)
    return plist, None

def discover_gradle(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, 'dependencies.gradle')
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        for l in contents.splitlines():
            if 'group:' in l and 'name:' in l and 'version:' in l:
                arr = l.split(',')
                gname = arr[0].split('group:')[1].strip()
                lname = arr[1].split('name:')[1].strip()
                ver = arr[2].split('version:')[1].strip()
                if localpath.startswith('/tmp/'):
                    file_path = file_path.replace(localpath+'/','')
                pname = gname + ':' + lname + ' ' + ver + " source:"+file_path
                pname = pname.replace("'","")
                if pname not in plist:
                    plist.append(pname)
    return plist, None

def process_package_json_files(files, args, localpath):
    level = args.level
    encoding = args.encoding
    plist = []
    p1list = [] # 1st level dependencies
    for file_path in files:
        fp = lib_utils.tw_open(file_path, encoding)
        if fp == None:
            continue
        contents = fp.read()
        contents = contents.strip()
        if len(contents) == 0:
            continue
        cjson = ''
        try:
            cjson = json.loads(contents)
        except Exception:
            logging.error("Unable to parse package.json contents")
            continue
        if 'name' in cjson and 'version' in cjson:
            if localpath.startswith('/tmp/'):
                file_path = file_path.replace(localpath+'/','')
            pname = cjson['name'] + ' ' + cjson['version'] + " source:"+file_path
            if pname not in plist:
                plist.append(pname)
                p1list.append(pname)
        if 'dependencies' in cjson:
            ddict = cjson['dependencies']
            for d in ddict:
                content = ddict[d]
                if isinstance(content, dict):
                    ver = content['version']
                    if localpath.startswith('/tmp/'):
                        file_path = file_path.replace(localpath+'/','')
                    pname = d + ' ' + ver + " source:"+file_path
                    if pname not in plist:
                        plist.append(pname)
                        p1list.append(pname)
                    req_dict = content.get('requires')
                    if req_dict is None or level == 'shallow':
                        continue
                    for req_pname in req_dict:
                        if localpath.startswith('/tmp/'):
                            file_path = file_path.replace(localpath+'/','')
                        pname = req_pname + ' ' + req_dict[req_pname]
                        pname = cleanse_semver_version(pname) + " source:"+file_path
                        if pname not in plist:
                            plist.append(pname)
                else:
                    if localpath.startswith('/tmp/'):
                        file_path = file_path.replace(localpath+'/','')
                    pname = d + ' ' + ddict[d] + " source:"+file_path
                    pname = cleanse_semver_version(pname)
                    if pname not in plist:
                        plist.append(pname)
                        p1list.append(pname)
        if 'devDependencies' in cjson:
            ddict = cjson['devDependencies']
            for d in ddict:
                pname = d + ' ' + ddict[d]
                if localpath.startswith('/tmp/'):
                    file_path = file_path.replace(localpath+'/','')
                pname = cleanse_semver_version(pname) + " source:"+file_path
                if pname not in plist:
                    plist.append(pname)
                    p1list.append(pname)
        if 'optionalDependencies' in cjson:
            ddict = cjson['optionalDependencies']
            for d in ddict:
                pname = d + ' ' + ddict[d]
                if localpath.startswith('/tmp/'):
                    file_path = file_path.replace(localpath+'/','')
                pname = cleanse_semver_version(pname) + " source:"+file_path
                if pname not in plist:
                    plist.append(pname)
                    p1list.append(pname)
    return plist, p1list 

def filter_used_npm_dependencies(args, deplist, localpath):
    logging.debug("Number of dependencies before used filter: "+str(len(deplist)))
    dev_null_device = open(os.devnull, "w")
    fdlist = []
    f_handle, f_path = tempfile.mkstemp('.txt', 'tw-find-output-')
    find_cmd = "find "+localpath+" -type f -name '*.js' -or -name '*.ts' > " + f_path
    try:
        out = subprocess.check_output([find_cmd], stderr=dev_null_device, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        if logging_enabled:
            logging.debug("Error running command...unable to filter used npm depdencies")
        return deplist
    for d in deplist:
        dname = d.split()[0].strip()
        if dname in fdlist:
            continue
        #print("Checking dependency for "+d)
        cmd = "cat %s | xargs -r egrep -ni '(import|require|loader|plugins|%s).*['\"](%s|.?\d+)[\"']' -m 1 | wc -l " % (f_path, dname, dname)
        #print(cmd)
        try:
            out = subprocess.check_output([cmd], stderr=dev_null_device, shell=True)
            out = out.decode(args.encoding)
        except subprocess.CalledProcessError:
            if logging_enabled:
                logging.debug("Error running command")
            dev_null_device.close()
            continue
        if out.strip() != '0':
            #print(dname+" is used")
            fdlist.append(d)
    dev_null_device.close()
    os.remove(f_path)
    logging.debug("Number of dependencies after used filter: "+str(len(fdlist)))
    return fdlist

def filter_used_dotnet_dependencies(args, deplist, localpath):
    logging.debug("Number of dependencies before used filter: "+str(len(deplist)))
    dev_null_device = open(os.devnull, "w")
    fdlist = []
    f_handle, f_path = tempfile.mkstemp('.txt', 'tw-find-output-')
    find_cmd = "find "+localpath+" -type f -name '*.cs' > " + f_path
    try:
        out = subprocess.check_output([find_cmd], stderr=dev_null_device, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        if logging_enabled:
            logging.debug("Error running command...unable to filter used npm depdencies")
        return deplist
    for d in deplist:
        dname = d.split()[0].strip()
        if dname in fdlist:
            continue
        #logging.debug("Checking dependency for "+d)
        cmd = "cat %s | xargs -r egrep -ni 'using.*%s' -m 1 | wc -l " % (f_path, dname)
        try:
            out = subprocess.check_output([cmd], stderr=dev_null_device, shell=True)
            out = out.decode(args.encoding)
        except subprocess.CalledProcessError:
            if logging_enabled:
                logging.debug("Error running command")
            dev_null_device.close()
            continue
        if out.strip() != '0':
            #logging.debug(dname+" is used")
            fdlist.append(d)
    dev_null_device.close()
    os.remove(f_path)
    logging.debug("Number of dependencies after used filter: "+str(len(fdlist)))
    return fdlist

def discover_package_json(args, localpath):
    files = lib_utils.find_files(localpath, 'package-lock.json')
    if len(files) > 0:
        plist, p1list = process_package_json_files(files, args, localpath)
    else:
        files = lib_utils.find_files(localpath, 'package.json')
        plist, p1list = process_package_json_files(files, args, localpath)
    if len(plist) > 0:
        if args.include_unused_dependencies == False:
            logging.debug("Filtering out unused npm dependencies. This may take some time...")
            plist = filter_used_npm_dependencies(args, plist, localpath)
        else:
            logging.warn("Including unused dependencies")
            logging.warn("May increase false positives")
    return plist, p1list

def discover_packages_config(args, localpath):
    plist = []
    # Give first preference for dependencies from .csproj files
    verprops = {}
    propfiles = lib_utils.find_files(localpath, '.props')
    for propfile in propfiles:
        fp = open(propfile, mode='r')
        if fp == None:
            continue
        contents = fp.read()
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            traceback.print_exc()
            logging.error("Unable to parse propfile file: %s", propfile)
            continue
        pglist = xmldoc.getElementsByTagName('PropertyGroup')
        for pg in pglist:
            props = pg.childNodes
            for p in props:
                if p.nodeType != p.TEXT_NODE: 
                    if p.childNodes and len(p.childNodes) == 1 and p.tagName.endswith('Version'):
                        verprops[p.tagName] = p.childNodes[0].data
    files = lib_utils.find_files(localpath, '.csproj')
    for file_path in files:
        fp = open(file_path, mode='r')
        if fp == None:
            continue
        contents = fp.read()
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            traceback.print_exc()
            logging.error("Unable to parse csproj file: %s", file_path)
            continue
        temp_plist = xmldoc.getElementsByTagName('PackageReference')
        for p in temp_plist:
            libname = p.getAttribute('Include')
            if libname is None or len(libname.strip()) == 0:
                continue
            libver = p.getAttribute('Version')
            if localpath.startswith('/tmp/'):
                file_path = file_path.replace(localpath+'/','')
            if libver is not None and len(libver.strip()) > 0 and not libver.startswith('$('):
                if '*' in libver:
                    libver = libver.replace('.*', '.0')
                if ',' in libver:
                    libver = libver.replace('(', '')
                    libver = libver.replace(')', '')
                    libver = libver.replace('[', '')
                    libver = libver.replace(']', '')
                    tokens = libver.split(',')
                    if len(tokens[0].strip()) > 0:
                        libver = tokens[0].strip()
                    elif len(tokens[1].strip()) > 0:
                        libver = tokens[1].strip()
                    else:
                        libver = '' # this case should never occur
                pname = libname + ' ' + libver + " source:"+file_path
            elif libver is not None and libver.startswith('$('):
                verlabel = libver.replace('$(','').replace(')','')
                if verlabel in verprops:
                    libver = verprops[verlabel]
                    pname = libname + ' ' + libver + " source:"+file_path
                else:
                    pname = libname + " source:"+file_path
            else:
                pname = libname + " source:"+file_path
            if pname not in plist:
                plist.append(pname)

    if len(plist) > 0:
        if args.include_unused_dependencies == False:
            logging.debug("Filtering out unused dotnet dependencies. This may take some time...")
            plist = filter_used_dotnet_dependencies(args, plist, localpath)
        else:
            logging.warn("Including unused dependencies")
            logging.warn("May increase false positives")

    if len(plist) > 0:
        return plist, plist

    # Fallback to packages.config file if no dependencies found from .csproj files
    files = lib_utils.find_files(localpath, 'packages.config')
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            logging.error("Unable to parse package config: %s", file_path)
            continue
        temp_plist = xmldoc.getElementsByTagName('package')
        for p in temp_plist:
            libname = p.getAttribute('id')
            libver = p.getAttribute('version')
            if localpath.startswith('/tmp/'):
                file_path = file_path.replace(localpath+'/','')
            pname = libname + ' ' + libver + " source:"+file_path
            if pname not in plist:
                plist.append(pname)

    if len(plist) > 0:
        if args.include_unused_dependencies == False:
            logging.debug("Filtering out unused nuget dependencies. This may take some time...")
            plist = filter_used_dotnet_dependencies(args, plist, localpath)
        else:
            logging.warn("Including unused dependencies")
            logging.warn("May increase false positives")

    return plist, plist

def discover_yarn(args, localpath):
    plist = []
    p1list = []
    files = lib_utils.find_files(localpath, 'yarn.lock')
    if len(files) == 0 and args.type is not None:
        files = lib_utils.find_files(localpath, 'package.json')
        plist = process_package_json_files(files, args, localpath)
        return plist

    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        cline = contents.splitlines()
        dparse = False
        for index, l in enumerate(cline):
            if l.endswith(':') and 'dependencies' not in l.lower():
                dparse = False
                if l.startswith('"'):
                    l = l[1:]
                if l.startswith('@'):
                    libname = '@' + l.split('@')[1]
                else:
                    libname = l.split('@')[0]
                vline = cline[index+1]
                libver = vline.split()[1].replace('"','')
                if localpath.startswith('/tmp/'):
                    file_path = file_path.replace(localpath+'/','')
                pname = libname+' '+libver
                pname = cleanse_semver_version(pname) + " source:"+file_path
                if pname not in plist:
                    plist.append(pname)
                    p1list.append(pname)
            if l.endswith(':') and 'dependencies' in l.lower():
                dparse = True
                continue
            if dparse:
                pname = l.strip()
                if pname == '':
                    dparse = False
                    continue
                if localpath.startswith('/tmp/'):
                    file_path = file_path.replace(localpath+'/','')
                pname = cleanse_semver_version(pname) + " source:"+file_path
                if pname not in plist and args.type == 'deep':
                    plist.append(pname)
    return plist, p1list

def discover_ruby(args, localpath):
    pset = set() 
    p1list = [] # 1st level dependencies
    files = lib_utils.find_files(localpath, 'gemfile.lock')
    if len(files) == 0:
        files = lib_utils.find_files(localpath, 'Gemfile.lock')
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        cline = contents.splitlines()
        specsfound = False
        for index, l in enumerate(cline):
            raw_line = l
            l = l.strip()
            if l.startswith('specs:'):
                specsfound = True
                first_line_indent = -1
                continue
            if l == '':
                specsfound = False
                continue
            if specsfound:
                current_line_indent = lib_utils.get_indent(raw_line)
                if first_line_indent == -1:
                    first_line_indent = current_line_indent
                elif current_line_indent > first_line_indent and args.level == 'shallow':
                    # skip 2nd level dependencies
                    continue
                ls = l.split()
                gname = ls[0]
                gver = ''
                if len(ls) > 1:
                    for i in range(1,len(ls)):
                        gver = ls[i]
                        gver = re.findall(r'([0-9]+[0-9a-z]*(\.[0-9a-z]+)+)', gver)
                        if gver:
                            gver = gver[0][0]
                            break
                        else:
                            gver = ''
                pname = gname + ' ' + gver
                if localpath.startswith('/tmp/'):
                    file_path = file_path.replace(localpath+'/','')
                pname = pname.strip() + " source:"+file_path
                if pname not in pset:
                    pset.add(pname)
                    p1list.append(pname)
    return list(pset) , p1list

def discover_python(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, 'requirements.txt')
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        req = requirements.parse(fp)
        try:
            for r in req:
                prod = r.name
                if len(r.specs) > 0:
                    if localpath.startswith('/tmp/'):
                        file_path = file_path.replace(localpath+'/','')
                    prod = prod + ' ' + r.specs[0][1] + " source:"+file_path
                    if prod not in plist:
                        plist.append(prod)
        except:
            logging.error("Unable to parse python dependencies")
            continue

    files = lib_utils.find_files(localpath, 'setup.py')
    for file_path in files:
        """Parse setup.py and return args and keywords args to its setup
        function call

        """
        mock_setup = textwrap.dedent('''\
        def setup(*args, **kwargs):
            __setup_calls__.append((args, kwargs))
        ''')
        parsed_mock_setup = ast.parse(mock_setup, filename=file_path)
        with open(file_path, 'rt') as setup_file:
            parsed = ast.parse(setup_file.read())
            for index, node in enumerate(parsed.body[:]):
                if (
                    not isinstance(node, ast.Expr) or
                    not isinstance(node.value, ast.Call) or
                    node.value.func.id != 'setup'
                ):
                    continue
                parsed.body[index:index] = parsed_mock_setup.body
                break

        fixed = ast.fix_missing_locations(parsed)
        codeobj = compile(fixed, file_path, 'exec')
        local_vars = {}
        global_vars = {'__setup_calls__': []}
        cwd = os.getcwd()
        os.chdir(os.path.dirname(file_path))
        try:
            exec(codeobj, global_vars, local_vars)
        except Exception:
            # move on
            logging.warn("Unable to parse python dependencies %s", file_path)
            os.chdir(cwd)
            continue
        os.chdir(cwd)
        reqs = global_vars['__setup_calls__'][0][1]['install_requires']
        for r in reqs:
            prod = r
            prod = prod.replace("==", " ")
            prod = prod.replace(">=", " ")
            prod = prod.replace("<=", " ")
            prod = prod.replace("~=", " ")
            prod = prod.replace(">", " ")
            prod = prod.replace("<", " ")
            prod = prod + " source:" + file_path
            if prod not in plist:
                plist.append(prod)

    files = lib_utils.find_files(localpath, 'pyproject.toml')
    for file_path in files:
        fp = lib_utils.tw_open(file_path, args.encoding)
        if fp == None:
            continue
        contents = fp.read()
        tdict = toml.loads(contents)
        fp.close()
        if localpath.startswith('/tmp/'):
            file_path = file_path.replace(localpath+'/','')
        if 'tool' in tdict and 'poetry' in tdict['tool'] and 'dependencies' in tdict['tool']['poetry']:
            for d in tdict['tool']['poetry']['dependencies']:
                ver = cleanse_semver_version(tdict['tool']['poetry']['dependencies'][d])
                prod = d + " " + ver + " source:" + file_path
                if prod not in plist:
                    plist.append(prod)
        if 'project' in tdict and 'dependencies' in tdict['project']: 
            for d in tdict['project']['dependencies']:
                prod = d 
                prod = prod.replace("==", " ")
                prod = prod.replace(">=", " ")
                prod = prod.replace("<=", " ")
                prod = prod.replace("~=", " ")
                prod = prod.replace(">", " ")
                prod = prod.replace("<", " ")
                prod = prod + " source:" + file_path
                if prod not in plist:
                    plist.append(prod)
    return plist, None

def LOWORD(dword):
    return dword & 0x0000ffff

def HIWORD(dword): 
    return dword >> 16

def get_dll_version(path):
    try:
        pe = pefile.PE(path)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            ms = pe.VS_FIXEDFILEINFO[0].FileVersionMS
            ls = pe.VS_FIXEDFILEINFO[0].FileVersionLS
            return "%d.%d.%d.%d" % (HIWORD (ms), LOWORD (ms), HIWORD (ls), LOWORD (ls))
        else:
            return None
    except Exception as e:
        logging.error("Unable to parse DLL file. Skipping.")
        return None

def discover_dll(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, '.dll')
    for file_path in files:
        dll_version = get_dll_version(file_path)
        if dll_version is None:
            continue
        if localpath.startswith('/tmp/'):
            file_path = file_path.replace(localpath+'/','')
        dll_details = os.path.basename(file_path) + " " + dll_version + " source:"+file_path

        plist.append(dll_details)
    return plist, None

def discover_jar(args, localpath):
    plist = []
    files = lib_utils.find_files(localpath, '.jar')
    for file_path in files:
        prod = ''
        ver = ''
        #print "Checking "+file_path
        try:
            zf = zipfile.ZipFile(file_path, 'r')
            try:
                metafile = zf.read('META-INF/MANIFEST.MF')
                if metafile:
                    for l in metafile.splitlines():
                        if l.startswith(b"Bundle-Version:"):
                            ver = l.split(b':')[1].strip()
                        if l.startswith(b"Bundle-Name:"):
                            prod = l.split(b':')[1].strip().lower().replace(b' ',b'-')
            except KeyError:
                #print "Error: No manifest found"
                pass
        except zipfile.BadZipfile:
            logging.warn("Unable to inspect file: %s", os.path.basename(file_path))

        if prod == '' or ver == '':
            jfile = os.path.basename(file_path)
            jfile = jfile.replace('.jar','')
            pattern = r'(?:(\d+\.(?:\d+\.)*\d+))'
            match = re.findall(pattern, jfile)
            if len(match) == 0:
                continue
            else:
                ver = match[0]
                prod = jfile.split(ver)[0][:-1]
        prod = str(prod) + ' ' + str(ver)
        if localpath.startswith('/tmp/'):
            file_path = file_path.replace(localpath+'/','')
        prod = prod.strip() + " source:"+file_path
        prod = prod.replace("b'","")
        prod = prod.replace("'","")
        prod = prod.replace('b"','')
        prod = prod.replace('"','')
        if prod != '':
            plist.append(prod)
    return plist, None

def discover_specified_type(repo_type, args, localpath):
    if repo_type not in SUPPORTED_TYPES:
        logging.error("Type not supported")
        return [], None

    plist = []
    p1list = []
    if repo_type == 'pip':
        plist, p1list = discover_python(args, localpath)
    elif repo_type == 'ruby':
        plist, p1list = discover_ruby(args, localpath)
    elif repo_type == 'yarn':
        plist, p1list = discover_yarn(args, localpath)
    elif repo_type == 'nuget':
        plist, p1list = discover_packages_config(args, localpath)
    elif repo_type == 'npm':
        plist, p1list = discover_package_json(args, localpath)
    elif repo_type == 'maven':
        plist, p1list = discover_pom_xml(args, localpath)
    elif repo_type == 'gradle':
        plist, p1list = discover_gradle(args, localpath)
    elif repo_type == 'dll':
        plist, p1list = discover_dll(args, localpath)
    elif repo_type == 'jar':
        plist, p1list = discover_jar(args, localpath)
    elif repo_type == 'cargo':
        plist, p1list = discover_cargo_toml(args, localpath)
    elif repo_type == 'go':
        plist, p1list = discover_go_mod(args, localpath)
    elif repo_type == 'composer':
        plist, p1list = discover_composer(args, localpath)

    return plist, p1list

def get_last_component(repo_path):
    if repo_path.startswith('http:') or repo_path.startswith('https:'):
        return repo_path.rsplit('/',1)[-1]
    else:
        return os.path.basename(os.path.normpath(repo_path))

def strip_source(plist):
    ret_list = []
    for pname in plist:
        index = pname.find(" source:")
        if index != -1:
            ret_list.append(pname[:index])
        else:
            ret_list.append(pname)
    return ret_list

def get_asset_id(args):
    asset_id = None
    if args.assetid == None or args.assetid.strip() == "":
        tokens = [args.handle.split('@')[0]]
        repo_path = args.repo
        if repo_path.startswith('http:') or repo_path.startswith('https:'):
            tokens.extend(repo_path.split('/')[3:])
            if args.branch is not None and args.branch.strip() != "":
                tokens.append(args.branch)
        else:
            tokens.append(os.path.basename(os.path.normpath(repo_path)))
        asset_id = "-".join(tokens)
    else:
        asset_id = args.assetid
    asset_id = asset_id.replace(' ','-')
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    return asset_id

def discover_inventory(args, localpath):
    asset_name = None
    if args.assetname == None or args.assetname.strip() == "":
        asset_name = get_last_component(args.repo)
    else:
        asset_name = args.assetname

    atype = 'Source Repository'
    plist = []
    asset_tags = []
    tech2prod_dict = { }
    shallow_tech2prod_dict = { }
    if args.type is None:
        # If no type is specified, then process all supported types
        for repo_type in SUPPORTED_TYPES:
            temp_list, temp1list = discover_specified_type(repo_type, args, localpath)
            temp_list = list(set(temp_list))
            if temp_list is not None and len(temp_list) > 0:
                tech2prod_dict[repo_type] = strip_source(temp_list)
                if temp1list is not None and len(temp1list) > 0:
                    shallow_tech2prod_dict[repo_type] = strip_source(temp1list)
                plist.extend(temp_list)
                asset_tags.append(repo_type)
    else:
        plist, p1list = discover_specified_type(args.type, args, localpath)
        plist = list(set(plist))
        if plist is not None and len(plist) > 0:
            tech2prod_dict[args.type] = strip_source(plist)
            if p1list is not None and len(p1list) > 0:
                shallow_tech2prod_dict[args.type] = strip_source(p1list)
        asset_tags.append(args.type)

    if plist == None or len(plist) == 0:
        logging.info("Unable to identify any source code dependencies")

    asset_data = {}
    asset_data['id'] = get_asset_id(args)
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = plist
    asset_data['tags'] = asset_tags
    if len(tech2prod_dict) > 0:
        asset_data['compliance_metadata'] = {"source_metadata": {"technology_products":tech2prod_dict, "shallow_technology_products":shallow_tech2prod_dict}}
   
    lib_utils.update_tool_run_record()
    return [ asset_data ]

# Note this error routine assumes that the file was read-only and hence could not be deleted
def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

# note this only handles actual repos and not orgs (i.e. all repos in an org)
def get_inventory_helper(args):
    path = None
    if args.repo.startswith('http'):
        if os.path.isfile(GIT_PATH) == False:
            logging.error("git executable does not exist at [%s]", GIT_PATH)
            return None
        dev_null_device = open(os.devnull, "w")
        path = tempfile.mkdtemp()
        base_path = path
        new_repo = None
        logging.info("Cloning repo locally...")
        try:
            if args.branch and args.branch != '':
                cmdarr = [GIT_PATH, 'clone', '--branch', args.branch, args.repo, path+'/.']
            else:
                cmdarr = [GIT_PATH, 'clone', args.repo, path+'/.']
            out = subprocess.check_output(cmdarr, stderr=dev_null_device)
        except:
            logging.error(traceback.format_exc())
            logging.error('Error cloning repo locally')
            shutil.rmtree(path, onerror = on_rm_error)
            return None
    elif os.path.isdir(args.repo):
        path = args.repo
        base_path = os.path.abspath(path)
        if base_path == os.path.dirname(base_path):
            base_path = "" # handle directory contained in root directory
    else:
        logging.error('Not a valid repo')
        return None

    assets = discover_inventory(args, path)
    if args.secrets_scan:
        logging.info("Discovering secrets/sensitive information. This may take some time.")
        secret_records = lib_code_secrets.scan_for_secrets(args, path, base_path)
        assets[0]['secrets'] = secret_records
    lib_utils.update_tool_run_record()

    code_issues = []
    if args.sast:
        logging.info("Performing static analysis. This may take some time.")
        sast_records = sast.run_sast(args, path, base_path)
        code_issues.extend(sast_records)
    lib_utils.update_tool_run_record()

    if args.iac_checks:
        logging.info("Identifying infrastructure as code (IaC) issues. This may take some time.")
        iac_records = iac.run_iac_checks(args, path, base_path)
        code_issues.extend(iac_records)
    lib_utils.update_tool_run_record()

    if len(code_issues) > 0:
        assets[0]['sast'] = code_issues

    if args.repo.startswith('http'):
        shutil.rmtree(path, onerror = on_rm_error)

    if len(assets[0]['products']) == 0 and (assets[0].get('secrets') is None or len(assets[0]['secrets']) == 0) and (assets[0].get('sast') is None or len(assets[0]['sast']) == 0):
        logging.warning("Nothing to report")
        if args.create_empty_asset is None or not args.create_empty_asset:
            return [] # if there are no products nor secrets then no assets to report
    return assets

def get_inventory(args):
    if args.gh_user:
        owner = args.gh_user
        dev_null_device = open(os.devnull, "w")
        # check if 'gh' command is available
        try:
            cmdarr = ['which', 'gh']
            out = subprocess.check_output(cmdarr, stderr=dev_null_device)
        except subprocess.CalledProcessError as e:
            logging.error("[gh] command not found")
            return None
        # check if user is logged in 'gh'
        try:
            cmdarr = ['gh', 'auth', 'status']
            out = subprocess.check_output(cmdarr, stderr=dev_null_device)
        except subprocess.CalledProcessError as e:
            logging.error("Please login using [gh auth login] command to list repositories")
            logging.debug("[gh auth status] command returned exit code [%s]", e.returncode)
            return None
        # list repo for org/user
        try:
            cmdarr = ['gh', 'repo', 'list', owner, '--json', 'name,url', '--limit', '65535']
            out = subprocess.check_output(cmdarr, stderr=dev_null_device)
        except subprocess.CalledProcessError as e:
            logging.error("Unable to list repos for [%s]", owner)
            logging.debug("[gh repo list %s --json name,url] command returned %s", owner, e.output)
            logging.debug("[gh repo list %s --json name,url] command returned exit code [%s]", owner, e.returncode)
            return None
        repos = json.loads(out.strip())
        assets = []
        for repo in repos:
            logging.info("Discovering repo [%s] as an asset", repo['name'])
            args.repo = repo['url']
            logging.info("Repo URL: %s", args.repo)
            temp_assets = get_inventory_helper(args)
            assets.extend(temp_assets)
        return assets
    else:
        return get_inventory_helper(args)
