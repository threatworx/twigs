import sys
import os
import socket
import subprocess
import paramiko
from scp import SCPClient
import logging
import requests
import time

try:
    from .__init__ import __version__
except (ImportError,ValueError):
    from twigs.__init__ import __version__

GoDaddyCABundle = True
run_args = None

SYSTEM_TAGS = ['IMAGE_NAME', 'OS_VERSION', 'OS_RELEASE', 'SOURCE', 'OS_RELEASE_ID', 'CRITICALITY', 'http', 'https', 'OS_ARCH', 'IMAGE_DIGEST', 'DISCOVERY_TYPE']

def get_ssh_client(host):
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
    return client

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
                logging.debug("Error running command")
            return None
    return pkgout

def run_remote_ssh_command_helper(client, command, args):
    output = ''
    stdin, stdout, stderr = client.exec_command(command)
    for line in stdout:
        output = output + line
    return output, stdout.channel.recv_exit_status()

def run_remote_ssh_command(args, host, command):
    assetid = host['assetid'] if host.get('assetid') is not None else host['hostname']
    try:
        client = get_ssh_client(host)
        output, exit_code = run_remote_ssh_command_helper(client, command, args)
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

def run_script_on_host(args, host, script_path, script_args):
    if host and host['remote']:
        pkgout, exit_code = run_remote_ssh_script(args, host, script_path, script_args)
    else:
        if not os.path.isfile(script_path):
            logging.error("Error script file not found at [%s]", script_path)
            return None
        if not os.access(script_path, os.X_OK):
            logging.error("Error script file at [%s] is not marked as executable", script_path)
            return None
        try:
            dev_null_device = open(os.devnull, "w")
            #cmdarr = [ "chroot '" + root_folder + "' && " + script_path ]
            cmd = script_path
            for sa in script_args:
                cmd = cmd + ' "' + sa + '"'
            cmdarr = [ cmd ]
            pkgout = subprocess.check_output(cmdarr, stderr=dev_null_device, shell=True)
            pkgout = pkgout.decode(args.encoding)
            dev_null_device.close()
            exit_code = 0
        except subprocess.CalledProcessError as excpt:
            logging.error("Error running script [%s]", script_path)
            pkgout = None
            exit_code = excpt.returncode
    return pkgout, exit_code

def scp_get_file(ssh_client, from_path, to_path):
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        scp_client.get(from_path, to_path)
        return True
    except:
        logging.info("Unknown error copying file [%s] from remote host", from_path)
        return False

def scp_put_file(ssh_client, from_path, to_path):
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        scp_client.put(from_path, recursive=True, remote_path=to_path)
        return True
    except:
        logging.info("Unknown error copying file [%s] to remote host", from_path)
        return False

# NOTE script_path is path of script file on remote host
def run_remote_ssh_script(args, host, script_path, script_args):
    assetid = host['assetid'] if host.get('assetid') is not None else host['hostname']
    output = ''
    exit_code = -1
    try:
        client = get_ssh_client(host)
        cmd = "test -x " + script_path
        temp_output, exit_code = run_remote_ssh_command_helper(client, cmd, args)
        if exit_code != 0:
            logging.error("Error executable script file not found on remote host at [%s]", script_path)
            output = None, exit_code
        cmd = script_path
        for sa in script_args:
            cmd = cmd + ' "' + sa + '"'
        output, exit_code = run_remote_ssh_command_helper(client, cmd, args)
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
        return output, exit_code

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
    elif "container-optimized os" in os:
        return "Google Container-Optimized OS"
    else:
        logging.error("Not a supported OS type [%s]" % os)
        return None

# reference: https://gist.github.com/bencord0/7690953
def get_unique_asset_id(args, host, asset_type):

    # Try to get MAC Address
    output = get_mac_address(args, host, asset_type)
    if output is not None and len(output.strip()) > 0:
        return output

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


def get_mac_address(args, host, asset_type):

    # get default interface
    cmd = "ip route show default | awk '/default/ {print $5}'"
    defif = run_cmd_on_host(args, host, [cmd], True)
    if defif == None or defif.strip() == '':
        return None
    defif = defif.strip()

    # now list mac address from /sys/class/net
    cmd = "cat /sys/class/net/"+defif+"/address"
    macid = run_cmd_on_host(args, host, [cmd], True)
    if macid == None or macid.strip() == '':
        return None
    macid = macid.strip().replace(':','')
    return macid 

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

def tw_open(in_file, in_encoding, in_mode='rt'):
    if sys.version_info[0] < 3:
        f = open(in_file, mode=in_mode)
    else:
        f = open(in_file, mode=in_mode, encoding=in_encoding)
    return f

def set_run_args(args):
    global run_args
    run_args = args

def get_run_args():
    global run_args
    return run_args

def create_new_tool_run_record():
    args = get_run_args()
    if args.token is None or len(args.token) == 0:
        return None
    run_id  = args.mode if args.run_id is None else args.run_id
    machine_id = get_ip()
    tool_name = 'twigs'
    tool_version = __version__
    email = args.handle
    url = "https://" + args.instance + "/api/v1/toolrun/new/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    post_payload = { "run_id": run_id, "machine_id": machine_id, "email": email, "name": tool_name, "version": tool_version }
    response = requests_post(url + auth_data, post_payload)
    if response.status_code == 200:
        args.run_record_id = response.json()['id']
    return response

def update_tool_run_record(status='RUNNING', observations=None):
    args = get_run_args()
    if args.token is None or len(args.token) == 0:
        return None
    run_record_id = args.run_record_id
    url = "https://" + args.instance + "/api/v1/toolrun/" + str(run_record_id) + "/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    if status != 'RUNNING':
        logging.shutdown()
        observations = { } if observations is None else observations
        observations['log_snippet'] = tail('twigs.log', args.encoding, 100)
    put_payload = { "status": status, "observations": observations }
    response = requests_put(url + auth_data, put_payload)
    return response

def tw_exit(exit_code, observations = None):
    status = 'SUCCESS' if exit_code == 0 else 'FAIL'
    update_tool_run_record(status, observations)
    sys.exit(exit_code)

def tail(fn, encoding, lines=20):
    with open(fn, 'rb') as f:
        total_lines_wanted = lines

        BLOCK_SIZE = 1024
        f.seek(0, 2)
        block_end_byte = f.tell()
        lines_to_go = total_lines_wanted
        block_number = -1
        blocks = [] # blocks of size BLOCK_SIZE, in reverse order starting
                    # from the end of the file
        while lines_to_go > 0 and block_end_byte > 0:
            if (block_end_byte - BLOCK_SIZE > 0):
                # read the last block we haven't yet read
                f.seek(block_number*BLOCK_SIZE, 2)
                blocks.append(f.read(BLOCK_SIZE).decode(encoding))
            else:
                # file too small, start from begining
                f.seek(0,0)
                # only read what was not read
                blocks.append(f.read(block_end_byte).decode(encoding))
            lines_found = blocks[-1].count('\n')
            lines_to_go -= lines_found
            block_end_byte -= BLOCK_SIZE
            block_number -= 1
        all_read_text = ''.join(reversed(blocks))
        return '\n'.join(all_read_text.splitlines()[-total_lines_wanted:])

