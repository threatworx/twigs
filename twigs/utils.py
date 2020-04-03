import os
import socket
import subprocess
import paramiko

def run_cmd_on_host(args, host, cmdarr):
    if host and host['remote']:
        pkgout = run_remote_ssh_command(args, host, cmdarr[0])
        if pkgout is None:
            return None
    else:
        try:
            pkgout = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
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
    out = run_cmd_on_host(args, host, cmdarr)

    if out is None or out.strip() == '':
        # try FreeBSD
        cmdarr = ["/usr/bin/uname -v -p"]
        out = run_cmd_on_host(args, host, cmdarr)

        if out is not None and 'FreeBSD' not in out:
            # try OpenBSD
            cmdarr = ["/usr/bin/uname -srvm"]
            out = run_cmd_on_host(args, host, cmdarr)

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
