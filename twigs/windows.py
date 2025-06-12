import sys
import os
import winrm
import csv
import ipaddress
import getpass
import base64
import json
import logging
import uuid
import tempfile
import shutil
import warnings
with warnings.catch_warnings():
   warnings.simplefilter("ignore", category=Warning)
   from cryptography.hazmat.backends import default_backend
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   from cryptography.fernet import Fernet

def get_inventory(args):
    host_list_file = args.host_list
    if host_list_file is not None:
        with open(host_list_file, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file, quoting=csv.QUOTE_NONE, escapechar='\\')
            password = None
            remote_hosts = []
            for row in csv_reader:
                if not args.secure and row['userpwd'].startswith('__SECURE__:'):
                    if args.password is None:
                        if password is None:
                            password = getpass.getpass(prompt="Enter password: ")
                            password = password.encode()
                    else:
                        password = args.password.encode()
                    salt = base64.b64encode(password)
                    kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                            backend=default_backend())
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    f = Fernet(key)
                    try:
                        epass = row['userpwd'].replace('__SECURE__:','')
                        row['userpwd'] = f.decrypt(epass.encode('utf-8'))
                    except:
                        logging.error("Failed to decrypt login details for "+row['hostname'])
                        return None
                elif row['userpwd'] != '' and not args.secure:
                    logging.warning('Unsecure login information in file. Use --secure to encrypt.')
                if '-' in row['hostname'] or '/' in row['hostname']: # IP range or CIDR is specified, then expand it
                    if '-' in row['hostname']:
                        iprange = row['hostname']
                        iprange = iprange.replace(' ','')
                        tokens = iprange.split('-')
                        if len(tokens) != 2 or len(tokens[0])==0 or len(tokens[1])==0:
                            logging.error("Skipping invalid range [%s]", row['hostname'])
                            continue
                        logging.info("Enumerating IPs based on specified range [%s]", iprange)
                        try:
                            if sys.version_info[0] < 3:
                                startip = ipaddress.IPv4Address(unicode(tokens[0]))
                                endip = ipaddress.IPv4Address(unicode(tokens[1]))
                            else:
                                startip = ipaddress.IPv4Address(tokens[0])
                                endip = ipaddress.IPv4Address(tokens[1])
                            cidrs = []
                            cidrs = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip,endip)]
                        except Exception as e:
                            logging.error("Encountered exception: %s",e)
                            logging.error("Error converting IP range [%s] to CIDRs. Skipping it...", iprange)
                            continue
                        logging.info("Converted IP range [%s] to CIDRs %s", iprange, cidrs)
                    if '/' in row['hostname']:
                        logging.info("Enumerating IPs based on specified CIDR [%s]", row['hostname'])
                        try:
                            if sys.version_info[0] < 3:
                                cidrs = [ipaddress.ip_network(unicode(row['hostname'],"ascii"))]
                            else:
                                cidrs = [ipaddress.ip_network(row['hostname'])]
                        except Exception as e:
                            logging.error("Encountered exception: %s",e)
                            logging.error("Invalid CIDR [%s] specified. Skipping it...", row['hostname'])
                            continue
                    for cidr in cidrs:
                        for a in cidr:
                            trow = row.copy()
                            trow['hostname'] = str(a)

                            # Remove hard-coded asset ID and name for CIDR, as it will overwrite same asset
                            # These will based on host IP address automatically
                            trow['assetname'] = None

                            remote_hosts.append(trow)
                            remote_hosts[-1]['remote'] = True
                            logging.info("Enumerated IP: %s", a)
                else:
                    remote_hosts.append(row)
                    remote_hosts[-1]['remote'] = True

        if args.secure:
            # secure the host list
            logging.info("Securing host list file")
            if args.password is None:
                pp1 = getpass.getpass(prompt="Enter password: ")
                pp2 = getpass.getpass(prompt="Re-enter password: ")
                if pp1 != pp2:
                    logging.info("Passwords don't match. Try again.")
                    return None
            else:
                pp1 = args.password
            password = pp1.encode()
            salt = base64.b64encode(password)
            kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            # verify the key if possible
            with open(host_list_file, mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file, quoting=csv.QUOTE_NONE, escapechar='\\')
                for row in csv_reader:
                    try:
                        if row['userpwd'] != '' and row['userpwd'].startswith('__SECURE__:'):
                            epass = row['userpwd'].replace('__SECURE__:','')
                            epass  = f.decrypt(epass)
                    except:
                        logging.error("Invalid password")
                        logging.error("Please use the same password as was used previously to secure the file")
                        return None
            # create new file with secured information. This will be renamed subsequently
            new_csv_file = uuid.uuid4().hex
            new_csv_file = tempfile.gettempdir() + os.path.sep + new_csv_file + ".csv"
            if os.path.isfile(new_csv_file):
                os.remove(new_csv_file)
            try:
                # secure the new rows in the file
                with open(new_csv_file, mode='w') as csvfile:
                    fieldnames = ['hostname','userlogin','userpwd']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_NONE, escapechar='\\')
                    writer.writeheader()
                    for h in remote_hosts:
                        if h['userpwd'] != '' and not h['userpwd'].startswith('__SECURE__:'):
                            h['userpwd'] = '__SECURE__:'+f.encrypt(h['userpwd'].encode('utf-8')).decode('utf-8')
                        del h['remote']
                        writer.writerow(h)
            except Exception as err:
                logging.error("Unable to save secured CSV file")
                logging.error("%s", err)
                os.remove(new_csv_file)
                utils.tw_exit(1)
            os.remove(host_list_file)
            shutil.copyfile(new_csv_file, host_list_file)
            os.remove(new_csv_file)
            logging.info("Host list file secured")
            return None
        else:
            return discover_windows_hosts(args, remote_hosts)

def discover_windows_hosts(args, hosts):
    assets = []
    for host in hosts:
        asset = discover_windows_host(args, host)
        if asset is not None:
            assets.append(asset)
    return assets

def discover_windows_host(args, host):
    logging.info("Running discovery for host [%s]", host['hostname'])
    winrm_session, asset_id = open_winrm_session(host, args)
    if asset_id is None:
        return None
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace('/','-')
    asset_name = asset_id
    logging.info("Getting OS details")
    temp_out = run_ps_command(args, winrm_session,
     """$computer_info = Get-ComputerInfo
        Write-Host $computer_info.OsName
        Write-Host $computer_info.OsVersion
        Write-Host $computer_info.CsSystemType
        Write-Host $computer_info.OsArchitecture""")
    if temp_out is None:
        return None
    temp_out = temp_out.split('\n')
    if len(temp_out) != 4:
        return None
    os_name = temp_out[0]
    os_version = temp_out[1]
    mc_arch = temp_out[2]
    bit_arch = temp_out[3]
    os_arch = bit_arch + ' ' + mc_arch
    os_version_ubr = run_ps_command(args, winrm_session,"""$os_version_ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
        Write-Host $os_version_ubr""")
    if os_version_ubr is not None and os_version_ubr != "":
        os_version_tokens = os_version.split(' ')
        os_version = os_version_tokens[0] + '.' + os_version_ubr
        for index in range(1,len(os_version_tokens)):
            os_version = os_version + ' ' + os_version_tokens[index]
    os_release_id = run_ps_command(args, winrm_session,"""$os_release_id = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId
        Write-Host $os_release_id""")

    logging.info("Getting patch information")
    temp_out = run_ps_command(args, winrm_session,"""$hot_fixes = Get-HotFix
        $patch_json_array = New-Object System.Collections.Generic.List[System.Object]
        foreach ($hot_fix in $hot_fixes) { $patch_entry_json = @{id=$hot_fix.HotFixID}
        $patch_json_array.add($patch_entry_json)}
        $patch_json = $patch_json_array | ConvertTo-Json;$patch_json_str = $patch_json.ToString()
        Write-Host $patch_json_str""")
    try:
        patches = json.loads(temp_out)
    except Exception as e:
        logging.error("Error parsing patch JSON")
        return None

    logging.info("Getting product inventory")
    temp_out = run_ps_command(args, winrm_session,"""$unique_products = New-Object System.Collections.Generic.List[string]
        $product_json_array = New-Object System.Collections.Generic.List[string]
        $temp_array = Get-ItemProperty HKLM:\\Software\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object Publisher, DisplayName, DisplayVersion
        $temp_array | foreach { $var = $_ ; $product = $var.'DisplayName'; $vendor = $var.'Publisher'; $version = $var.'DisplayVersion'; if ($product -and $version) { $product_details = $product.Trim() + ' ' + $version.Trim(); $product_json_array.add($product_details); }}
        $temp_products_count = $temp_array.Length
        $temp_array = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object Publisher, DisplayName, DisplayVersion
        $temp_array | foreach { $var = $_ ; $product = $var.'DisplayName'; $vendor = $var.'Publisher'; $version = $var.'DisplayVersion'; if ($product -and $version) { $product_details = $product.Trim() + ' ' + $version.Trim(); $product_json_array.add($product_details); }}
        $ie_version = Get-ItemProperty 'HKLM:\Software\Microsoft\Internet Explorer' | Select-Object svcVersion, Version
        if ($ie_version.svcVersion -ne $null) {
            $product_json_array.add('Internet Explorer ' + $ie_version.svcVersion)
            $temp_products_count = $temp_products_count + 1
        }
        else {
            if ($ie_version.Version -ne $null) {
                $product_json_array.add('Internet Explorer ' + $ie_version.Version)
                $temp_products_count = $temp_products_count + 1
            }
        }
        $temp_products_count = $temp_products_count + $temp_array.Length
        $temp_array = Get-WMIObject -ClassName Win32_Product
        foreach ($row in $temp_array) { $product_details = $row.Name.Trim() + ' ' + $row.Version.Trim(); if  ($product_json_array -notcontains $product_details) { $product_json_array.Add($product_details)} }
        $product_json = $product_json_array | ConvertTo-Json
        $product_json_str = $product_json.ToString()
        Write-Host $product_json_str """)
    try:
        products = json.loads(temp_out)
    except Exception as e:
        logging.error("Error parsing product JSON")
        return None

    logging.info("Completed discovery of host")
    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = 'Windows'
    asset_data['owner'] = args.handle
    asset_data['products'] = products
    asset_data['patches'] = patches
    asset_tags = []
    asset_tags.append('OS_RELEASE:' + os_name)
    asset_tags.append('OS_VERSION:' + os_version)
    if os_release_id is not None and os_release_id.strip() != "":
        asset_tags.append('OS_RELEASE_ID:' + os_release_id)
    if os_arch.strip() != "":
        asset_tags.append('OS_ARCH:' + os_arch)
    asset_tags.append('Windows')
    asset_data['tags'] = asset_tags
    
    return asset_data

def open_winrm_session(host, args):
    winrm_session = None
    asset_id = None
    auth_modes = ['kerberos', 'ntlm', 'credssp', 'plaintext']
    for auth_mode in auth_modes:
        try:
            logging.debug("Attempting to authenticate using [%s]", auth_mode)
            winrm_session = winrm.Session(host['hostname'], auth=(host['userlogin'], host['userpwd']), transport=auth_mode)
        except Exception as e:
            logging.debug("Got exception. Unable to authenticate to host using [%s]", auth_mode)
            logging.debug(e)
            continue
        asset_id = run_ps_command(args, winrm_session, "Write-Host $env:ComputerName", True)
        if asset_id is None:
            logging.debug("Unable to authenticate to host using [%s]", auth_mode)
            continue
        else:
            logging.debug("Authenticated to host using [%s]", auth_mode)
            break
    if asset_id is None:
        logging.info("Unable to authenticate to host [%s]", host['hostname'])
        return None, None
    else:
        return winrm_session, asset_id

def run_ps_command(args, winrm_session, command, no_err_msg=False):
    try:
        cmd_out = winrm_session.run_ps(command)
        cmd_out = cmd_out.std_out.decode(args.encoding).strip()
        return cmd_out
    except Exception as e:
        if not no_err_msg:
            logging.error("Error running command on host: %s", str(e))
        logging.debug("Commmand: %s", command)
        return None
