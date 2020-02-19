import sys
import os
import subprocess
import logging

docker_cli = ""

def docker_available():
    if os.path.isfile("/usr/bin/docker"):
        return "/usr/bin/docker"
    elif os.path.isfile("/usr/local/bin/docker"):
        return "/usr/local/bin/docker"
    return None 

def start_docker_container(args):
    if args.image is None:
        return None
    cmdarr = [docker_cli+' run -d --rm -i -t '+args.image]
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
    if args.image is None:
        return
    cmdarr = [docker_cli+' stop '+container_id]
    out = ''
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error stopping docker container with image ["+args.image+"] and ID ["+container_id+"]")
        sys.exit(1)
    logging.info("Stopped container with ID ["+container_id+"]")

def get_asset_type(os):
    if "CentOS" in os:
        return "CentOS"
    elif "Red Hat" in os:
        return "Red Hat"
    elif "Ubuntu" in os:
        return "Ubuntu"
    elif "Debian" in os:
        return "Debian"
    elif "Amazon Linux" in os:
        return "Amazon Linux"
    elif "Oracle Linux" in os:
        return "Oracle Linux"
    elif "FreeBSD" in os:
        return "FreeBSD"
    elif "OpenBSD" in os:
        return "OpenBSD"
    else:
        logging.error('Not a supported OS type')
        return None

def get_os_release(args, container_id):
    base_cmd = docker_cli+' exec -i -t '+container_id+' /bin/sh -c '
    freebsd = False
    out = None
    cmd = '"/bin/cat /etc/os-release"'
    cmdarr = [base_cmd + cmd]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error determining os type: %s", args.image)

    if out is None or out.strip() == '':
        # try FreeBSD
        cmd = '"/usr/bin/uname -v -p"'
        cmdarr = [base_cmd + cmd]
        try:
            out = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error determining os type: %s", args.image)

        if out is not None and 'FreeBSD' not in out:
            # try OpenBSD
            cmd = '"/usr/bin/uname -srvm"'
            cmdarr = [base_cmd + cmd]
            try:
                out = subprocess.check_output(cmdarr, shell=True)
            except subprocess.CalledProcessError:
                logging.error("Error determining os type: %s", args.image)

    if out is None:
        logging.error("Failed to get os-release")
        return None

    if 'FreeBSD' in out or 'OpenBSD' in out:
        return out
    else:
        output_lines = out.splitlines()
        for l in output_lines:
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

def discover_openbsd(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/sbin/pkg_info -A"']
    logging.info("Retrieving product details from image")
    if host['remote']:
        pkgout = run_remote_ssh_command(args, host, cmdarr[0])
        if pkgout is None:
            return None
    else:
        try:
            pkgout = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error running inventory for image: %s",args.image)
            return None

    begin = False
    for l in pkgout.splitlines():
        lsplit = l.split()
        pkgline = lsplit[0]
        ldash = pkgline.rfind('-')
        pkg = pkgline[:ldash] + ' ' + pkgline[ldash + 1:]
        logging.debug("Found product [%s]", pkg)
        plist.append(pkg)
    logging.info("Completed retrieval of product details from image")
    return plist

def discover_freebsd(args, container_id):
    plist = []
    cmdarr = [docker_cli+' exec -i -t '+container_id+' /bin/sh -c "/usr/sbin/pkg info"']
    logging.info("Retrieving product details from image")
    if host['remote']:
        pkgout = run_remote_ssh_command(args, host, cmdarr[0])
        if pkgout is None:
            return None
    else:
        try:
            pkgout = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error running inventory for image: %s",args.image)
            return None

    begin = False
    for l in pkgout.splitlines():
        lsplit = l.split()
        pkgline = lsplit[0]
        ldash = pkgline.rfind('-')
        pkg = pkgline[:ldash] + ' ' + pkgline[ldash + 1:]
        logging.debug("Found product [%s]", pkg)
        plist.append(pkg)
    logging.info("Completed retrieval of product details from image")
    return plist

def discover(args, atype, os_release, container_id):
    handle = args.handle
    token = args.token
    instance = args.instance
    asset_id = None
    if args.assetid == None:
        asset_id = args.image if args.image is not None else args.containerid
    else:
        asset_id = args.assetid
    asset_name = None
    if args.assetname == None:
        asset_name = args.image if args.image is not None else args.containerid
    else:
        asset_name = args.assetname
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    asset_name = asset_name.replace('/','-')
    asset_name = asset_name.replace(':','-')

    plist = None
    if atype == 'CentOS' or atype == 'Red Hat' or atype == 'Amazon Linux' or atype == 'Oracle Linux':
        plist = discover_rh(args, container_id)
    elif atype == 'Ubuntu' or atype == 'Debian':
        plist = discover_ubuntu(args, container_id)
    elif atype == 'FreeBSD':
        plist = discover_freebsd(args, container_id)
    elif atype == 'OpenBSD':
        plist = discover_openbsd(args, container_id)

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
    asset_tags.append('OS_RELEASE:' + os_release)
    asset_tags.append('Docker')
    asset_tags.append('Container')
    asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags

    return [ asset_data ]

def get_inventory(args):
    global docker_cli
    docker_cli = docker_available()
    if not docker_cli:
        sys.exit(1)

    if args.image is None and args.containerid is None:
        logging.error("Error either docker image (--image) or running container id (--containerid) parameter needs to be specified")
        sys.exit(1)

    if args.image is not None:
        if not get_image_id(args):
            if not pull_image(args):
                sys.exit(1)
        container_id = start_docker_container(args)
    elif args.containerid is not None:
        container_id = args.containerid

    os_release = get_os_release(args, container_id)
    if os_release is None:
        stop_docker_container(args, container_id)
        sys.exit(1)
    atype = get_asset_type(os_release)
    if atype is None:
        stop_docker_container(args, container_id)
        sys.exit(1)

    assets = discover(args, atype, os_release, container_id)
    stop_docker_container(args, container_id)
    return assets
