import sys
import os
import subprocess
import logging
import tempfile
import shutil
import stat
import tarfile
import re
import traceback
import json
import pkg_resources
import importlib
import io

from . import utils
from . import repo
from . import plugin_processor

docker_cli = ""

def make_temp_directory(tmp_dir):
    if tmp_dir is None:
        temp_dir = tempfile.mkdtemp()
    else:
        temp_dir = tempfile.mkdtemp(dir=tmp_dir)
    return temp_dir

def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

# Note this routine only handles direct symbolic links and not nested ones
def fix_symbolic_links_helper(container_fs):
    for root, subdirs, files in os.walk(container_fs):
        for fname in files:
            file_path = os.path.join(root, fname)
            if os.path.islink(file_path):
                symlink_path = os.readlink(file_path)
                # Typically absolute links should point within container_fs
                if os.path.isabs(symlink_path) and not symlink_path.startswith(container_fs):
                    nested_path = container_fs + symlink_path
                    if os.path.exists(nested_path):
                        # Fix symbolic link to point within container_fs
                        os.remove(file_path)
                        os.symlink(nested_path, file_path)

def fix_symbolic_links(container_fs):
    # This is a two phase operation as there could be symbolic links that could not be processed
    # due to a symbolic that will be processed later...
    fix_symbolic_links_helper(container_fs)
    fix_symbolic_links_helper(container_fs)

def tar_available():
    if os.path.isfile("/bin/tar"):
        return "/bin/tar"
    elif os.path.isfile("/usr/bin/tar"):
        return "/usr/bin/tar"
    return None

def untar(tar_file, untar_directory):
    tar_cmd = tar_available()
    if tar_cmd is not None:
        tar_failed = False
        cmdarr = [tar_cmd + ' -C ' + untar_directory + ' -xvf ' + tar_file]
        out = ''
        try:
            out = subprocess.check_output(cmdarr, shell=True)
            return
        except subprocess.CalledProcessError:
            logging.error("Unable to untar container image tar file")
            tar_failed = True

    if tar_cmd is None or tar_failed:
        with tarfile.open(tar_file, 'r', format=tarfile.PAX_FORMAT) as tf:
            tf.extractall(path=untar_directory)

def get_container_fs(container_tar):
    if container_tar is None:
        return None
    working_dir = os.path.dirname(container_tar)
    container_dir = working_dir + os.path.sep + 'container'
    os.mkdir(container_dir)
    untar(container_tar, container_dir)
    container_fs = working_dir + os.path.sep + 'container_fs'
    os.mkdir(container_fs)
    layers = []
    with open(container_dir + os.path.sep + 'manifest.json', 'r') as fd:
        manifest_json = json.load(fd)
        layers = manifest_json[0]['Layers']
    for layer in layers:
        layer_tar = container_dir + os.path.sep + layer
        untar(layer_tar, container_fs)
    os.remove(container_tar)
    shutil.rmtree(container_dir, onerror = on_rm_error)
    return container_fs

def unpack_container_fs(container_tar):
    if container_tar is None:
        return None
    working_dir = os.path.dirname(container_tar)
    container_fs = working_dir + os.path.sep + 'container_fs'
    os.mkdir(container_fs)
    untar(container_tar, container_fs)
    os.remove(container_tar)
    return container_fs

def docker_available():
    if os.path.isfile("/usr/bin/docker"):
        return "/usr/bin/docker"
    elif os.path.isfile("/usr/local/bin/docker"):
        return "/usr/local/bin/docker"
    return None 

def save_image(args, working_dir):
    image = args.image
    container_tar = working_dir + os.path.sep + 'container.tar'
    cmdarr = [docker_cli + ' save -o ' + container_tar + ' ' + image]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to save container image as tar archive")
        return None
    return container_tar

def export_container(args, working_dir):
    containerid = args.containerid
    container_tar = working_dir + os.path.sep + 'container.tar'
    cmdarr = [docker_cli + ' export -o ' + container_tar + ' ' + containerid]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to export container file system as tar archive")
        return None
    return container_tar

def start_docker_container(args):
    if args.image is None:
        return args.containerid
    cmdarr = [docker_cli+' run -d --rm -i -t '+args.image + ' /bin/sh']
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to start container: "+args.image)
        return None
    container_id = out[:12]
    logging.info("Started container with ID ["+container_id+"] from image ["+args.image+"] for discovery")
    return container_id

def stop_docker_container(args, container_id):
    if args.image is None:
        return
    cmdarr = [docker_cli+' stop '+container_id]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error stopping docker container with container ID ["+container_id+"]")
        return
    logging.info("Stopped container with ID ["+container_id+"]")

def remove_image(args):
    cmdarr = [docker_cli, "image", "rm", "-f", args.image]
    try:
        out = subprocess.check_output(cmdarr)
    except subprocess.CalledProcessError:
        logging.error("Error removing docker image: "+args.image)
        return False
    return True

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
        out = out.decode(args.encoding)
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

def get_image_digest(args):
    # During kubernetes discovery, we get container image names as "docker.io/bitnami/wordpress"
    # and we need to strip out the "docker.io" part
    image_tokens = args.image.split('/')
    temp_image = "/".join(image_tokens[-2:]) if len(image_tokens) > 2 else args.image 

    image_tokens = temp_image.split(':')
    image = image_tokens[0]
    image_tag = "latest" if len(image_tokens) == 1 else image_tokens[1]

    cmdarr = [docker_cli, "images", image, "--digests"]
    out = ''
    try:
        out = subprocess.check_output(cmdarr)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Error getting image digest: "+args.image)
        return None
    image_digest = None
    for l in out.splitlines():
        if 'REPOSITORY' in l:
            continue
        l_tokens = l.split()
        if l_tokens[0] == image and l_tokens[1] == image_tag:
            image_digest = l_tokens[2]
            break
    image_digest = None if image_digest is None or image_digest.strip() == "<none>" else image_digest
    return image_digest

def get_asset_id(args):
    asset_id = None
    if args.assetid is None or args.assetid.strip() == "":
        asset_id = args.image if args.image is not None else args.containerid
    else:
        asset_id = args.assetid
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    return asset_id

def create_asset(args, os_release, atype, plist, digest, container_fs):
    asset_id = get_asset_id(args)
    asset_name = None
    if args.assetname is None or args.assetname.strip() == "":
        asset_name = args.image if args.image is not None else args.containerid
    else:
        asset_name = args.assetname

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = plist
    asset_tags = []
    asset_tags.append('OS_RELEASE:' + os_release)
    if args.image is not None:
        asset_tags.append('IMAGE_NAME:' + args.image)
    if args.image is not None and digest is not None:
        asset_tags.append('IMAGE_DIGEST:' + digest)
    asset_tags.append('Docker')
    asset_tags.append('Container')
    asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags

    if container_fs is not None:
        host = {'remote' : False}
        plugin_processor.process_plugins(asset_data, host, args, container_fs)

    return [ asset_data ]

def get_os_release_from_container_image(args, container_fs):
    for root, dirs, files in os.walk(container_fs):
        for f in files:
            tfn = root + os.path.sep + f
            if tfn.endswith('etc/os-release') or tfn.endswith('etc/redhat-release'):
                with open(tfn, 'r') as fd:
                    for line in fd.readlines():
                        if 'PRETTY_NAME' in line:
                            return line.split('=')[1].replace('"','').strip()

    return None

def discover_rh_from_container_image(container_fs):
    # Load rpm module programmatically to avoid display warning message if distro package
    # is not installed in other discovery modes
    try:
        pkg_resources.get_distribution('rpm')
    except pkg_resources.DistributionNotFound as err:
        logging.warning("%s", err)
        logging.warning("python-rpm module not found. Please install [python2-rpm] or [python3-rpm] from your distro package manager")
        return []
    try:
        rpm_module = importlib.import_module('rpm')
    except ImportError as err:
        logging.warning("%s", err)
        return []

    if hasattr(rpm_module, 'addMacro') == False:
            logging.warning('Please install [python2-rpm] or [python3-rpm] from your distro package manager')
            return []
    plist = []
    rpm_addMacro = getattr(rpm_module, 'addMacro')
    rpm_addMacro("_dbpath", container_fs + os.path.sep + os.path.sep.join(["var","lib","rpm"]))
    rpm_TS = getattr(rpm_module, 'TransactionSet')
    ts = rpm_TS()
    packages = ts.dbMatch()
    for ph in packages:
        pkg_name = ph.sprintf("%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}").strip()
        plist.append(pkg_name)
    return plist

def discover_ubuntu_from_container_image(container_fs):
    dpkg_status_file = container_fs + os.path.sep + os.path.sep.join(["var","lib","dpkg","status"])
    plist = []
    pkg = ''
    ver = ''
    with io.open(dpkg_status_file, 'r', errors='ignore') as fd:
        while True:
            line = fd.readline()
            if not line:
                if pkg != '':
                    pkg_ver = pkg + ' ' + ver
                    if pkg_ver not in plist:
                        plist.append(pkg_ver)
                break
            line = line.strip()
            if line == '':
                plist.append(pkg + ' ' + ver)
                pkg = ''
                ver = ''
            if line.startswith('Package:'):
                pkg = line.split(':')[1].strip()
            if line.startswith('Version:'):
                ver = ':'.join(line.split(':')[1:]).strip()
    return plist

def discover_alpine_from_container_image(container_fs):
    apkg_status_file = container_fs + os.path.sep + os.path.sep.join(["lib","apk","db","installed"])
    plist = []
    pkg = ''
    ver = ''
    with io.open(apkg_status_file, 'r', errors='ignore') as fd:
        while True:
            line = fd.readline()
            if not line:
                if pkg != '':
                    pkg_ver = pkg + ' ' + ver
                    if pkg_ver not in plist:
                        plist.append(pkg_ver)
                break
            line = line.strip()
            if line == '':
                plist.append(pkg + ' ' + ver)
                pkg = ''
                ver = ''
            if line.startswith('P:'):
                pkg = line.split(':')[1].strip()
            if line.startswith('V:'):
                ver = line.split(':')[1].strip()
    return plist

def get_opensource_asset_id(args):
    if args.assetid == None:
        args.assetid = args.image
    os_asset_id = repo.get_asset_id(args)
    os_asset_id = os_asset_id + '-opensource'
    return os_asset_id

def create_open_source_asset(args, container_fs, digest):
    args.repo = container_fs
    os_asset_id = get_opensource_asset_id(args)
    oa = repo.discover_inventory(args, container_fs)
    if oa != None and len(oa[0]['products']) != 0:
        oa[0]['name'] = args.assetname+'-container-app'
        oa[0]['id'] = os_asset_id
        oa[0]['type'] = 'Container App'
        oa[0]['tags'].append('IMAGE_NAME:'+args.image)
        if digest is not None:
            oa[0]['tags'].append('IMAGE_DIGEST:'+digest)
    else:
        return None
    return oa

def discover_container_from_image(args, digest):
    casset = None
    temp_dir = None
    try:
        temp_dir = make_temp_directory(args.tmp_dir)
        logging.info("Retrieving container filesystem")
        if args.image is not None:
            container_tar = save_image(args, temp_dir)
            container_fs = get_container_fs(container_tar)
        else:
            container_tar = export_container(args, temp_dir)
            container_fs = unpack_container_fs(container_tar)

        if container_fs is None:
            logging.warning("Unable to analyze container filesystem")
            shutil.rmtree(temp_dir, onerror = on_rm_error)
            return None

        fix_symbolic_links(container_fs)

        oa = create_open_source_asset(args, container_fs, digest)
        if oa != None:
            casset = [] + oa

        logging.info("Analyzing container filesystem")
        os_release = get_os_release_from_container_image(args, container_fs)
        if os_release is None:
            shutil.rmtree(temp_dir, onerror = on_rm_error)
            return casset 

        atype = utils.get_asset_type(os_release)
        if atype is None:
            shutil.rmtree(temp_dir, onerror = on_rm_error)
            return casset 

        plist = None
        if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux' or atype == 'Oracle Linux':
            plist = discover_rh_from_container_image(container_fs)
        elif atype == 'Ubuntu' or atype == 'Debian':
            plist = discover_ubuntu_from_container_image(container_fs)
        elif atype == 'Alpine Linux':
            plist = discover_alpine_from_container_image(container_fs)

        shutil.rmtree(temp_dir, onerror = on_rm_error)
        if plist is None or len(plist) == 0:
            return casset 

        basset = create_asset(args, os_release, atype, plist, digest, container_fs)
        if casset:
            casset = casset + basset 
        else:
            casset = basset

        return casset

    except Exception:
        logging.warning("Unable to discover container from image")
        print(traceback.format_exc())
        if args.containerid is not None:
            logging.error(traceback.format_exc())
        if temp_dir is not None:
            shutil.rmtree(temp_dir, onerror = on_rm_error)
        return None

def get_os_release_from_container_instance(args, container_id):
    base_cmd = docker_cli+' exec -i -t '+container_id+' /bin/sh -c '
    freebsd = False
    out = None
    cmd = '"/bin/cat /etc/os-release"'
    cmdarr = [base_cmd + cmd]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to determine os type for container ID: %s", container_id)

    if out is None or out.strip() == '':
        # try FreeBSD
        cmd = '"/usr/bin/uname -v -p"'
        cmdarr = [base_cmd + cmd]
        try:
            out = subprocess.check_output(cmdarr, shell=True)
            out = out.decode(args.encoding)
        except subprocess.CalledProcessError:
            logging.error("Unable to determine os type for container ID: %s", container_id)

        if out is not None and 'FreeBSD' not in out:
            # try OpenBSD
            cmd = '"/usr/bin/uname -srvm"'
            cmdarr = [base_cmd + cmd]
            try:
                out = subprocess.check_output(cmdarr, shell=True)
                out = out.decode(args.encoding)
            except subprocess.CalledProcessError:
                logging.error("Unable to determine os type for container ID: %s", container_id)

    if out is None:
        logging.error("Failed to get os type for container")
        return None

    if 'FreeBSD' in out or 'OpenBSD' in out:
        return out
    else:
        output_lines = out.splitlines()
        for l in output_lines:
            if 'PRETTY_NAME' in l:
                return l.split('=')[1].replace('"','')
    return None

def discover_rh_from_container_instance(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/bin/yum list installed"']
    yumout = ''
    try:
        yumout = subprocess.check_output(cmdarr, shell=True)
        yumout = yumout.decode(args.encoding)
    except subprocess.CalledProcessError:
        cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/bin/rpm -qa"']
        rpmout = ''
        try:
            rpmout = subprocess.check_output(cmdarr, shell=True)
            rpmout = rpmout.decode(args.encoding)
        except subprocess.CalledProcessError:
            logging.error("Unable to run inventory for container ID [%s]", container_id)
            return None
        for l in rpmout.splitlines():
            tokens = l.split('-')
            length = len(tokens)
            if length <= 2:
                pname = tokens[0]
                version = tokens[1]
            else:
                version = tokens[length-2]+'-'+tokens[length-1]
                pname = "-".join(tokens[:-2])
            plist.append(pname+' '+version)
        return plist

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
        pkg_ver = pkg+' '+ver
        pkg_ver = pkg_ver.replace('\x1b[1m','')
        pkg_ver = pkg_ver.replace('\x1b[1','')
        pkg_ver = pkg_ver.replace('\x1b(B','')
        pkg_ver = pkg_ver.replace('\x1b(m','')
        pkg_ver = pkg_ver.replace('\x1b[m','')
        pkg_ver = pkg_ver.replace('\u001b(B','')
        pkg_ver = pkg_ver.replace('\u001b[m','')
        pkg_ver = pkg_ver.replace('\u001b[31m','')
        plist.append(pkg_ver)
    return plist

def discover_ubuntu_from_container_instance(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/bin/apt list --installed"']
    yumout = ''
    try:
        yumout = subprocess.check_output(cmdarr, shell=True)
        yumout = yumout.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to run inventory for container ID: "+container_id)
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
        plist.append(pkg+' '+ver)
    return plist

def discover_openbsd_from_container_instance(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/sbin/pkg_info -A"']
    try:
        pkgout = subprocess.check_output(cmdarr, shell=True)
        pkgout = pkgout.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to run inventory for container ID: %s",container_id)
        return None

    begin = False
    for l in pkgout.splitlines():
        lsplit = l.split()
        pkgline = lsplit[0]
        ldash = pkgline.rfind('-')
        pkg = pkgline[:ldash] + ' ' + pkgline[ldash + 1:]
        plist.append(pkg)
    return plist

def discover_alpine_from_container_instance(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/ash -c "/sbin/apk list"']
    try:
        pkgout = subprocess.check_output(cmdarr, shell=True)
        pkgout = pkgout.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to run inventory for container ID: %s",container_id)
        return None

    begin = False
    for l in pkgout.splitlines():
        if l.startswith('WARNING:'):
            continue
        pkg = l.split()[0]
        ps = pkg.split('-')
        ver = ps[-2] + '-' + ps[-1]
        pkg = pkg.replace('-'+ver, '')
        pkg = pkg + ' ' + ver
        plist.append(pkg)
    return plist

def discover_freebsd_from_container_instance(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/sbin/pkg info"']
    try:
        pkgout = subprocess.check_output(cmdarr, shell=True)
        pkgout = pkgout.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Unable to run inventory for container ID: %s",container_id)
        return None

    begin = False
    for l in pkgout.splitlines():
        lsplit = l.split()
        pkgline = lsplit[0]
        ldash = pkgline.rfind('-')
        pkg = pkgline[:ldash] + ' ' + pkgline[ldash + 1:]
        plist.append(pkg)
    return plist

def discover_container_from_instance(args):
    container_id = start_docker_container(args)
    if container_id is None:
        return None

    os_release = get_os_release_from_container_instance(args, container_id)
    if os_release is None:
        stop_docker_container(args, container_id)
        return None
    atype = utils.get_asset_type(os_release)
    if atype is None:
        stop_docker_container(args, container_id)
        return None

    plist = None
    if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux' or atype == 'Oracle Linux':
        plist = discover_rh_from_container_instance(args, container_id)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu_from_container_instance(args, container_id)
    elif atype == 'FreeBSD':
        plist = discover_freebsd_from_container_instance(args, container_id)
    elif atype == 'OpenBSD':
        plist = discover_openbsd_from_container_instance(args, container_id)
    elif atype == 'Alpine Linux':
        plist = discover_alpine_from_container_instance(args, container_id)

    stop_docker_container(args, container_id)
    if plist == None or len(plist) == 0:
        return None

    return create_asset(args, os_release, atype, plist, None, None)

def run_docker_bench(args):
    DBENCH = "/docker-bench-security.sh"

    asset_id = utils.get_ip() if args.assetid is None or args.assetid.strip() == "" else args.assetid
    asset_name = asset_id if args.assetname is None or args.assetname.strip() == "" else args.assetname
    os_release = utils.get_os_release(args, None)
    if os_release == None:
        logging.error('Unsupported OS type for running docker bench')
        return None
    atype = utils.get_asset_type(os_release)

    dbench_path = args.docker_bench_home + DBENCH
    if not os.path.isfile(dbench_path) or not os.access(dbench_path, os.X_OK):
        logging.error('Docker bench script not found')
        return None
    logging.info('Running docker bench script: '+dbench_path)
    try:
        os.chdir(os.path.dirname(args.docker_bench_home))
        out = subprocess.check_output([dbench_path+" 2>/dev/null "], shell=True)
        out = out.decode(args.encoding)
        ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
        out = ansi_escape.sub('', out)
    except subprocess.CalledProcessError:
        logging.error("Unable to run docker bench script")
        return None 

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = [] 
    asset_tags = []
    asset_tags.append('OS_RELEASE:' + os_release)
    asset_tags.append('Docker')
    asset_tags.append('Container')
    asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags 

    findings = []
    details = ''
    issue = {}
    for l in out.splitlines():
        if not l.startswith('[WARN]'):
            continue
        spa = l.split()
        if spa[1] != '*':
            if 'asset_id' in issue:
                issue['details'] = details
                findings.append(issue)
                details = ''
                issue = {}
            issue['twc_id'] = 'docker-bench-check-'+spa[1].strip()
            issue['asset_id'] = asset_id 
            issue['twc_title'] = l.split('-')[1].strip()
            issue['rating'] = '4'
            issue['object_id'] = '' 
            issue['object_meta'] = ''
            details = ''
        else:
            details = details + l.split('*')[1] + '\n'
    # add the final issue
    if 'asset_id' in issue:
        issue['details'] = details
        findings.append(issue)
    asset_data['config_issues'] = findings
    # disable scan
    args.no_scan = True
    return [ asset_data ]

# digest = None --> get digest using docker
def get_inventory(args, digest=None):


    global docker_cli

    if os.geteuid() != 0:
        logging.error("Docker operations need root privilege. Please run as 'sudo' or 'root'")
        return None

    docker_cli = docker_available()
    if not docker_cli:
        logging.error("Docker CLI not available")
        return None

    if args.image is None and args.containerid is None:
        logging.error("Either docker image (--image) or running container id (--containerid) parameter needs to be specified")
        return None

    if args.tmp_dir is not None and os.path.isdir(args.tmp_dir) == False:
        logging.error("Specified temporary directory [%s] does not exist!", args.tmp_dir)
        return None

    # If digest is not specified, then try to pull image locally to obtain digest
    del_image = False
    if digest is None:
        if args.image is not None:
            if not get_image_id(args):
                if not pull_image(args):
                    logging.error("Failed to pull image: "+args.image)
                    return None
                else:
                    del_image = True
            digest = get_image_digest(args)

    # If image digest is available, then check if image has changed using digest
    if digest is not None and digest != -1:
        if (args.token is None or len(args.token) == 0):
            logging.warn("Unable to compare image digest as [token] argument is not specified")
        else:
            no_change = False
            digest_tag = "IMAGE_DIGEST:%s" % digest
            eos_asset_id = get_opensource_asset_id(args)
            eos_asset = utils.get_asset(eos_asset_id, args)
            if eos_asset is not None:
                for tag in eos_asset['tags']:
                    if digest_tag == tag:
                        no_change = True
            easset_id = get_asset_id(args)
            easset = utils.get_asset(easset_id, args)
            if easset is not None:
                for tag in easset['tags']:
                    if digest_tag == tag:
                        no_change = True
            if no_change:
                logging.info("No change in image digest for container image [%s]...skipping it", args.image)
                if del_image:
                    remove_image(args)
                return None
    digest = None if digest == -1 else digest

    if args.image is not None:
        # Note if digest was passed, then image may not be available locally
        if not get_image_id(args):
            if not pull_image(args):
                logging.error("Failed to pull image: "+args.image)
                return None
            else:
                del_image = True
        assets = discover_container_from_image(args, digest)
        if assets is None and args.start_instance:
            assets = discover_container_from_instance(args)
    elif args.containerid is not None:
        assets = discover_container_from_instance(args)
        if assets is None:
            assets = discover_container_from_image(args, digest)

    # if image was downloaded by twigs then remove it
    if del_image:
        remove_image(args)

    if assets is None:
        logging.error("Unable to inventory container")
        return None

    return assets
