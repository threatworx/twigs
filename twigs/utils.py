import sys
import os
import socket
import subprocess
import paramiko
import logging
import requests
import time

GoDaddyCABundle = True

SYSTEM_TAGS = ['IMAGE_NAME', 'OS_VERSION', 'OS_RELEASE', 'SOURCE', 'OS_RELEASE_ID', 'CRITICALITY', 'http', 'https', 'OS_ARCH', 'IMAGE_DIGEST']

def run_cmd_on_host(args, host, cmdarr, logging_enabled=True):
    if host and host['remote']:
        pkgout = run_remote_ssh_command(args, host, cmdarr[0])
        if pkgout is None:
            return None
    else:
        try:
            dev_null_device = open(os.devnull, "w")
            pkgout = subprocess.check_output(cmdarr, stderr=dev_null_device, shell=True)
            pkgout = pkgout.decode(args.encoding)
            dev_null_device.close()
        except subprocess.CalledProcessError:
            if logging_enabled:
                logging.error("Error running inventory")
            return None
    return pkgout

def run_remote_ssh_command(args, host, command):
    assetid = host['assetid'] if host.get('assetid') is not None else host['hostname']
    output = ''
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
        if host.get('userpwd') is not None and len(host['userpwd']) > 0 and (host.get('privatekey') is None or len(host['privatekey'])==0):
            client.connect(host['hostname'],username=host['userlogin'],password=host['userpwd'])
        elif host.get('privatekey') is not None and len(host['privatekey']) > 0:
            if host.get('userpwd') is not None and len(host['userpwd']) > 0:
                client.connect(host['hostname'],username=host['userlogin'],key_filename=host['privatekey'],passphrase=host['userpwd'])
            else:
                client.connect(host['hostname'],username=host['userlogin'],key_filename=host['privatekey'])
        else:
            client.connect(host['hostname'],username=host['userlogin'])
        stdin, stdout, stderr = client.exec_command(command)
        for line in stdout:
            output = output + line
        client.close()
    except paramiko.ssh_exception.AuthenticationException as e:
        logging.info("Authentication failed for asset [%s], host [%s]", assetid, host['hostname'])
        logging.info("Exception: %s", e)
        output = None
    except paramiko.ssh_exception.SSHException as e:
        logging.info("SSHException while connecting to asset [%s], host [%s]", assetid, host['hostname'])
        logging.info("Exception: %s", e)
        output = None
    except socket.error as e:
        logging.info("Socket error while connection to asset [%s], host [%s]", assetid, host['hostname'])
        logging.info("Exception: %s", e)
        output = None
    except:
        logging.info("Unknown error running remote discovery for asset [%s], host [%s]: [%s]", assetid, host['hostname'], sys.exc_info()[0])
        output = None
    finally:
        return output

def get_os_release(args, host=None):
    freebsd = False
    out = None
    cmdarr = ["/bin/cat /etc/os-release"]
    out = run_cmd_on_host(args, host, cmdarr, False)

    if out is None or out.strip() == '':

        # try redhat-release
        cmdarr = ["/bin/cat /etc/redhat-release"]
        out = run_cmd_on_host(args, host, cmdarr, False)
        if out is not None and out.strip() != '':
            return out.strip()
        else:
            # try FreeBSD
            cmdarr = ["/usr/bin/uname -v -p"]
            out = run_cmd_on_host(args, host, cmdarr, False)

            if out is not None and 'FreeBSD' not in out:
                # try OpenBSD
                cmdarr = ["/usr/bin/uname -srvm"]
                out = run_cmd_on_host(args, host, cmdarr, False)

    if out is None:
        logging.error("Failed to get os-release")
        return None

    if 'FreeBSD' in out or 'OpenBSD' in out:
        return out
    elif 'Darwin' in out:
        # Check for Mac OS
        cmdarr = ["sw_vers"]
        out = run_cmd_on_host(args, host, cmdarr, False)
        if out is not None and out.strip() != '':
            mac_os_version = ""
            for line in out.splitlines():
                value = line.split(':')[1].strip()
                mac_os_version = value if len(mac_os_version) == 0 else mac_os_version + " " + value
            return mac_os_version
    else:
        output_lines = out.splitlines()
        for l in output_lines:
            if 'PRETTY_NAME' in l:
                return l.split('=')[1].replace('"','')
    return None

def get_asset_type(os):
    os = os.lower()
    if "centos" in os:
        return "CentOS"
    elif "red hat" in os:
        return "Red Hat"
    elif "ubuntu" in os:
        return "Ubuntu"
    elif "debian" in os:
        return "Debian"
    elif "amazon linux" in os:
        return "Amazon Linux"
    elif "oracle linux" in os:
        return "Oracle Linux"
    elif "freebsd" in os:
        return "FreeBSD"
    elif "openbsd" in os:
        return "OpenBSD"
    elif "suse" in os:
        return "Suse"
    elif "mac os" in os or "macos" in os:
        return "Mac OS"
    elif "windows" in os:
        return "Windows"
    elif "alpine" in os:
        return "Alpine Linux"
    else:
        logging.error("Not a supported OS type [%s]" % os)
        return None

# reference: https://gist.github.com/bencord0/7690953
def get_unique_asset_id(args, host, asset_type):

    output = run_cmd_on_host(args, host, ["cat /var/lib/dbus/machine-id"], False)
    if output is not None and len(output.strip()) > 0:
        return output.strip()

    output = run_cmd_on_host(args, host, ["cat /sys/class/dmi/id/product_uuid"], False)
    if output is not None and len(output.strip()) > 0:
        return output.strip()

    # For FreeBSD
    output = run_cmd_on_host(args, host, ["sysctl kern.hostuuid"], False)
    if output is not None and len(output.strip()) > 0:
        return output.strip().split(' ')[1]

    # For Mac OS
    output = run_cmd_on_host(args, host, ["sysctl kern.uuid"], False)
    if output is not None and len(output.strip()) > 0:
        return output.strip().split(' ')[1]

    # If nothing worked, then try to get MAC Address
    return get_mac_address(args, host, asset_type)

def get_mac_address(args, host, asset_type):
    if asset_type in ['Ubuntu', 'CentOS', 'Red Hat', 'Suse', 'Debian']:
        interface = 'eth0:' if asset_type != 'Debian' else 'ens4'
        output = run_cmd_on_host(args, host, ["ip link"], True)
        lines = output.splitlines()
        for i in range(len(lines)):
            if 'eth0:' in lines[i]:
                return lines[i+1].split()[1]
    elif asset_type == 'Mac OS':
        return run_cmd_on_host(args, host, ["ifconfig en1 | awk '/ether/{print $2}'"], True)
    return None

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

def find_files(localpath, filename):
    ret_files = []
    for root, subdirs, files in os.walk(localpath):
        for fname in files:
            file_path = os.path.join(root, fname)
            if len(filename) == 0:
                ret_files.append(file_path)
            elif file_path.endswith(filename):
                ret_files.append(file_path)
    return ret_files

def ascii_string(in_str):
    ascii_str = ''.join([c if ord(c) < 128 else ' ' for c in in_str.strip()])
    return ascii_str

def get_indent(line):
    return len(line) - len(line.lstrip(' '))

def get_rating(cvss_score):
    rating = '1'
    if cvss_score is None or cvss_score == '':
        return rating
    s = float(cvss_score)
    if s <= 2:
        rating = '1'
    elif s <= 4:
        rating = '2'
    elif s <= 6:
        rating = '3'
    elif s <= 8:
        rating = '4'
    elif s <= 10:
        rating = '5'
    return rating

def set_requests_verify(verify):
    global GoDaddyCABundle
    GoDaddyCABundle = verify

def get_requests_verify():
    global GoDaddyCABundle
    return GoDaddyCABundle

def requests_get(url):
    rc = 0
    st = 1
    while True:
        try:
            resp = requests.get(url, verify=get_requests_verify())
            resp_status_code = resp.status_code
        except requests.exceptions.RequestException as e:
            logging.warn("Retry count [%s] got exception: [%s]", rc, str(e))
            if rc >= 10:
                logging.warn("Max retries exceeded....giving up...")
                return None
            else:
                logging.warn("Sleeping for [%s] seconds...", st)
                time.sleep(st)
                rc = rc + 1
                st = st * 2
                continue
        return resp

def requests_post(url, json):
    rc = 0
    st = 1
    while True:
        try:
            resp =  requests.post(url, json=json, verify=get_requests_verify())
            resp_status_code = resp.status_code
        except requests.exceptions.RequestException as e:
            logging.warn("Retry count [%s] got exception: [%s]", rc, str(e))
            if rc >= 10:
                logging.warn("Max retries exceeded....giving up...")
                return None
            else:
                logging.warn("Sleeping for [%s] seconds...", st)
                time.sleep(st)
                rc = rc + 1
                st = st * 2
                continue
        return resp

def requests_put(url, json):
    rc = 0
    st = 1
    while True:
        try:
            resp = requests.put(url, json=json, verify=get_requests_verify())
            resp_status_code = resp.status_code
        except requests.exceptions.RequestException as e:
            logging.warn("Retry count [%s] got exception: [%s]", rc, str(e))
            if rc >= 10:
                logging.warn("Max retries exceeded....giving up...")
                return None
            else:
                logging.warn("Sleeping for [%s] seconds...", st)
                time.sleep(st)
                rc = rc + 1
                st = st * 2
                continue
        return resp

def get_asset(asset_id, args):
    asset_url = "https://" + args.instance + "/api/v2/assets/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"

    resp = requests_get(asset_url + asset_id + "/" + auth_data)
    if resp is not None and resp.status_code == 200:
        return resp.json()
    else:
        return None

