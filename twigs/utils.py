import os
import socket
import subprocess

def get_os_release(args, host=None):
    freebsd = False
    out = None
    cmdarr = ["/bin/cat /etc/os-release"]
    if host and host['remote']:
        out = run_remote_ssh_command(args, host, cmdarr[0])
    else:
        try:
            out = subprocess.check_output(cmdarr, shell=True)
        except subprocess.CalledProcessError:
            logging.error("Error running local command")

    if out is None or out.strip() == '':
        # try FreeBSD
        cmdarr = ["/usr/bin/uname -v -p"]
        if host and host['remote']:
            out = run_remote_ssh_command(args, host, cmdarr[0])
        else:
            try:
                out = subprocess.check_output(cmdarr, shell=True)
            except subprocess.CalledProcessError:
                logging.error("Error running local command")

        if out is not None and 'FreeBSD' not in out:
            # try OpenBSD
            cmdarr = ["/usr/bin/uname -srvm"]
            if host and host['remote']:
                out = run_remote_ssh_command(args, host, cmdarr[0])
            else:
                try:
                    out = subprocess.check_output(cmdarr, shell=True)
                except subprocess.CalledProcessError:
                    logging.error("Error running local command")

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
