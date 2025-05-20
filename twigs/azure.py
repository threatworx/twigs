import sys
import json
import os
import subprocess
import requests
import re
import logging

from . import utils

g_encoding = None
g_required_extensions = ["account", "log-analytics"]
gTenantId = None
gAllVMs = None

def set_encoding(encoding):
    global g_encoding
    g_encoding = encoding

def get_encoding():
    global g_encoding
    return g_encoding

def run_az_cmd(cmd):
    cmd = 'az ' + cmd + ' --output json --only-show-errors'
    try:
        logging.debug("Running cmd [%s]", cmd)
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
        ret_json = json.loads(cmd_output)
    except subprocess.CalledProcessError:
        logging.error("Error running az command [%s]", cmd)
        utils.tw_exit(1)
    except ValueError:
        logging.error("Error parsing JSON output for az command [%s]: %s", cmd, cmd_output)
        utils.tw_exit(1)
    return ret_json

def check_required_az_extensions():
    global g_required_extensions
    installed_extensions = []
    missing_extensions = []
    installed_extensions_json = run_az_cmd('extension list')
    for ie in installed_extensions_json:
        installed_extensions.append(ie['name'])
    for req_ext in g_required_extensions:
        if req_ext not in installed_extensions:
            missing_extensions.append(req_ext)
    if len(missing_extensions) > 0:
        logging.error("Please install following Azure CLI extensions for discovery: %s", str(missing_extensions))
        logging.error("Use [az extension add --name <extension_name>] command to install missing extensions")
        utils.tw_exit(1)

def get_tenant_id():
    global gTenantId
    if gTenantId is not None:
        return gTenantId
    rjson = run_az_cmd('account tenant list')
    gTenantId = rjson[0]['tenantId']
    return gTenantId

def get_all_vms():
    global gAllVMs
    if gAllVMs is not None:
        return gAllVMs
    gAllVMs = { }
    allsubs = get_all_subscriptions()
    for sub in allsubs:
        resourcegroups = get_all_resourcegroups_for_subscription(sub)
        for res_group in resourcegroups:
            vms = get_vms(sub, res_group)
            gAllVMs.update(vms)
    return gAllVMs

# Main entry point
def get_inventory(args):
    set_encoding(args.encoding)
    check_required_az_extensions()
    assets = retrieve_inventory(args)
    return assets

def parse_inventory(args,data):
    logging.info("Processing inventory retrieved from Azure...")
    hosts = []
    assets = []
    asset_map = {}
    not_running_vms = {}
    temp_assets = set()
    all_assets = { }
    for item in data:
        all_assets[item['Computer']] = item['VMUUID']
        if item['ConfigDataType'] == 'WindowsServices': #ConfigDataType
            #logging.warning("Logging WindowsServices data below:\n%s", json.dumps(item, indent=2))
            temp_assets.add(item['Computer'])
            continue
        #logging.debug("Parsing inventory from data below:\n%s", json.dumps(item, indent=2))
        host = item['Computer']
        vmuuid = item['VMUUID']
        publisher = item['Publisher']

        # If VM is known to be not running, then skip it
        if not_running_vms.get(vmuuid) == 1:
            continue

        if host not in hosts  and publisher != '0':
            logging.debug("Found new asset - host [%s] vmuuid [%s]", host, vmuuid)
            patches = []
            products = []
            asset_map = {}
            asset_map['owner'] = args.handle
            asset_map['host'] = host
            asset_map['id'] = vmuuid
            asset_map['name'] = host
            asset_map['tags'] = [ ]
            asset_map['patch_tracker'] = { } # To help remove duplicate patches
            asset_map['vmuuid'] = vmuuid
            if item['SoftwareType'] in ['Update', 'Patch']: #ApplicationType for MS patches
                patch = parse_patch(item)
                if patch is not None:
                    patches.append(patch)
                    asset_map['patch_tracker'][patch['id']] = patch['id']
            if item['SoftwareType'] == 'Package' or item['SoftwareType'] == 'Application': #ApplicationType for Linux packages
                pname = item['SoftwareName']
                pversion =  item['CurrentVersion']
                # Azure Monitoring Agent bug - version has "(none):1.4.6-1.el8" for Linux packages
                pversion = pversion[7:] if item['SoftwareType'] == 'Package' and pversion.startswith('(none):') else pversion
                products.append(pname+' ' + pversion)
            asset_map['products'] = products
            asset_map['patches'] = patches
            vm_running, os, os_version = get_os_details(host, vmuuid)
            if vm_running == False:
                # skip vm's which are not running
                not_running_vms[vmuuid] = 1
                continue
            asset_map['type'] = get_os_type(os)
            if len(asset_map['type']) > 0:
                asset_map['tags'].append(asset_map['type'])
            if asset_map['type'] == 'Windows':
                asset_map['tags'].append('OS_RELEASE:' + os)
                asset_map['tags'].append('OS_VERSION:' + os_version)
            else:
                asset_map['tags'].append('OS_RELEASE:%s %s' % (os, os_version))
            if args.enable_tracking_tags == True:
                asset_map['tags'].append("SOURCE:Azure:" + get_tenant_id())
            else:
                asset_map['tags'].append("SOURCE:Azure")
            assets.append(asset_map)
            hosts.append(host)
        else:
            for asset in assets:
                if asset['host'] == host:
                    products = asset['products']
                    patches = asset['patches']
                    if item['SoftwareType'] in ['Update', 'Patch']: #ApplicationType for MS patches
                        patch = parse_patch(item)
                        if patch is not None and asset['patch_tracker'].get(patch['id']) is None:
                            patches.append(patch)
                            asset['patches'] = patches
                            asset['patch_tracker'][patch['id']] = patch['id']
                    if item['SoftwareType'] == 'Package' or item['SoftwareType'] == 'Application': #ApplicationType for Linux packages
                        pname = item['SoftwareName']
                        pversion =  item['CurrentVersion']
                        # Azure Monitoring Agent bug - version has "(none):1.4.6-1.el8" for Linux packages
                        pversion = pversion[7:] if item['SoftwareType'] == 'Package' and pversion.startswith('(none):') else pversion
                        products.append(pname+' ' + pversion)
                        asset['products'] = products
    # Remove the additional fields 'patch_tracker' (added to avoid duplicate patches) & 'vmuuid'
    for asset in assets:
        asset.pop('patch_tracker', None)
        asset.pop('vmuuid', None)
        if asset['host'] in temp_assets:
            temp_assets.remove(asset['host'])
    """
    logging.warning("Total assets reported: %s", len(all_assets))
    logging.warning("Assets with s/w packages and patches: %s", len(assets))
    logging.warning("Assets with only Windows Service: %s", len(temp_assets))
    if (len(temp_assets)>0):
        logging.warning("Sample asset with only Windows Service: %s", list(temp_assets)[0])
    logging.warning("Not running VMs: %s", len(not_running_vms))
    """
    return assets

def parse_patch(item):
    patch_id = re.findall(r'(KB[0-9]+)', item['SoftwareName'])
    if len(patch_id) == 0:
        return None
    patch = {}
    patch['url'] = ''
    patch['id'] = patch_id[0]
    patch['product'] = ''
    patch['description'] = item['SoftwareName']
    return patch
            
def get_os_type(ostype):
    asset_type = ''
    if ostype is None:
        asset_type = ''
    elif 'Microsoft' in  ostype or 'Windows' in ostype:
        asset_type = 'Windows'
    elif 'Red Hat' in ostype or 'redhat' in ostype or 'rhel' in ostype or 'RHEL' in ostype:
        asset_type = 'Red Hat'
    elif 'Ubuntu' in ostype or 'ubuntu' in ostype:
        asset_type = 'Ubuntu'
    elif 'CentOS' in ostype or 'centos' in ostype:
        asset_type = 'CentOS'
    elif 'Oracle' in ostype or 'oracle' in ostype:
        asset_type = "Oracle Linux"
    logging.debug("Mapped OS [%s] to Asset Type [%s]", ostype, asset_type)
    return asset_type

def retrieve_inventory(args):
    email = args.handle
    workspace_id = args.azure_workspace
    rjson = run_az_cmd("monitor log-analytics query -w '%s' --analytics-query 'ConfigurationData | summarize by SoftwareName, SoftwareType, Publisher, CurrentVersion, ConfigDataType, Computer, VMUUID'" % workspace_id)
    return parse_inventory(args, rjson)

def is_vm_running(vm_json):
    statuses = vm_json.get('statuses')
    if statuses is None:
        return False
    for status in statuses:
        status_code = status.get('code')
        if status_code is not None and status_code.startswith('PowerState/'):
            if status_code.split('/')[1] == "running":
                return True
            else:
                return False
    return False

# Try to get OS details for given VM
def get_os_details(host, vmuuid):
    all_vms = get_all_vms()
    vm_id = all_vms.get(vmuuid)
    if vm_id is None:
        # Handle Endian-ness issue with Azure VM UUIDs
        tokens = vmuuid.split('-')
        t = tokens[0]
        alt_vmuuid = "%s%s%s%s" % (t[6:8], t[4:6], t[2:4], t[0:2])
        t = tokens[1]
        alt_vmuuid = alt_vmuuid + "-%s%s" % (t[2:4], t[0:2])
        t = tokens[2]
        alt_vmuuid = alt_vmuuid + "-%s%s" % (t[2:4], t[0:2])
        alt_vmuuid = alt_vmuuid + '-%s-%s' % (tokens[3], tokens[4])
        vm_id = all_vms.get(alt_vmuuid)
        if vm_id is None:
            return False, None, None

    logging.debug("Getting OS details for host [%s] vmuuid [%s]", host, vmuuid)
    rjson = run_az_cmd("vm get-instance-view --ids '%s'" % vm_id)
    rjson = rjson['instanceView']
    if is_vm_running(rjson):
        return True, rjson.get('osName'), rjson.get('osVersion')
    else:
        return False, None, None

# Get details for all VMs
def get_vms(subscription, resource_group):
    all_vms = { }
    rjson = run_az_cmd("vm list --subscription '%s' --resource-group '%s'" % (subscription, resource_group))
    for vm in rjson:
        all_vms[vm['vmId']] = vm['id']
    return all_vms

# Get a list of subscriptions for current AAD/Tenant
def get_all_subscriptions():
    allsubs = []
    rjson = run_az_cmd('account subscription list')
    for sub in rjson:
        allsubs.append(sub['subscriptionId'])
    return allsubs

#Get all resource groups for a subscription
def get_all_resourcegroups_for_subscription(subid):
    allresourcegroups = []
    rjson = run_az_cmd("group list --subscription '%s'" % subid)
    for rg in rjson:
        allresourcegroups.append(rg['name'])

    return allresourcegroups

