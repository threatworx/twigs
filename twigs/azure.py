import sys
import json
import os
import subprocess
import requests
import re
import logging
import datetime

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

def convert_to_datetime(datetime_str):
    if '.' in datetime_str:
        # Known behavior with Azure TimeGenerate values wherein at times it includes microseconds and that too with 7 digits (instead of 6 digits)
        datetime_str = datetime_str.split('.')[0]
        return datetime.datetime.strptime(datetime_str,  "%Y-%m-%dT%H:%M:%S")
    else:
        return datetime.datetime.strptime(datetime_str,  "%Y-%m-%dT%H:%M:%SZ")

def is_product_removed(rpt, assetid, pnv, last_reported_on):
    tasset = rpt.get(assetid)
    if tasset is None:
        return False
    removed_on  = rpt[assetid].get(pnv)
    if removed_on is None:
        return False
    else:
        removed_on = convert_to_datetime(removed_on)
        last_reported_on = convert_to_datetime(last_reported_on)
        if removed_on > last_reported_on:
            logging.debug("Product [%s] removed on asset [%s]", pnv, assetid)
            logging.debug("ConfigurationData product last_reported_on %s", last_reported_on)
            logging.debug("ConfigurationChange product removed_on %s", removed_on)
            return True
    return False

def prepare_removed_product_tracker(workspace_id):
    logging.info("Processing configuration change data retrieved from Azure...")
    # Removed Product Tracker - this is a 2 level dict as assetid -> product -> removedtime 
    rpt = { }
    rjson = run_az_cmd("monitor log-analytics query -w '%s' --analytics-query 'ConfigurationChange | where ConfigChangeType == \"Software\" and ChangeCategory == \"Removed\" | summarize arg_max(TimeGenerated, *) by Computer, VMUUID, Publisher, SoftwareName, SoftwareType | project VMUUID, SoftwareName, Previous, SoftwareType, TimeGenerated'" % workspace_id)
    logging.debug("ConfigurationChange data: %s", rjson)
    for item in rjson:
        if item['SoftwareType'] not in ['Application', 'Package']:
            # currently we only handle software uninstallations
            continue
        pname = item['SoftwareName']
        pversion = item['Previous']
        # Azure Monitoring Agent bug - version has "(none):1.4.6-1.el8" for Linux packages
        pversion = pversion[7:] if item['SoftwareType'] == 'Package' and pversion.startswith('(none):') else pversion
        pnv = pname + ' ' + pversion
        if item['VMUUID'] not in rpt:
            rpt[item['VMUUID']] = { }
        rpt[item['VMUUID']][pnv] = item['TimeGenerated']
    logging.debug("Removed product tracker dict: %s", rpt)
    return rpt

def parse_inventory(args, data, rpt):
    logging.info("Processing inventory retrieved from Azure...")
    hosts = []
    assets = []
    asset_map = {}
    not_running_vms = {}
    all_assets = { }
    for item in data:
        all_assets[item['Computer']] = item['VMUUID']
        logging.debug("Parsing inventory from data below:\n%s", json.dumps(item, indent=2))
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
                pnv = pname + ' ' + pversion
                if not is_product_removed(rpt, asset_map['id'], pnv, item['TimeGenerated']):
                    products.append(pnv)
            asset_map['products'] = products
            asset_map['patches'] = patches
            vm_running, os, os_version, sub_id, tags = get_vm_details(host, vmuuid)
            if vm_running == False:
                # skip vm's which are not running
                not_running_vms[vmuuid] = 1
                continue
            asset_map['type'] = get_os_type(os)
            if len(asset_map['type']) > 0:
                asset_map['tags'].append(asset_map['type'])
            if len(tags) > 0:
                asset_map['tags'].extend(tags)
            if asset_map['type'] == 'Windows':
                asset_map['tags'].append('OS_RELEASE:' + os)
                asset_map['tags'].append('OS_VERSION:' + os_version)
            else:
                asset_map['tags'].append('OS_RELEASE:%s %s' % (os, os_version))
            if args.enable_tracking_tags == True:
                asset_map['tags'].append("SOURCE:Azure:Tenant:" + get_tenant_id())
                asset_map['tags'].append("SOURCE:Azure:Subscription:" + sub_id)
            else:
                asset_map['tags'].append("SOURCE:Azure")
            assets.append(asset_map)
            hosts.append(host)
        else:
            for asset in assets:
                if asset['host'] == host:
                    if item['SoftwareType'] in ['Update', 'Patch']: #ApplicationType for MS patches
                        patch = parse_patch(item)
                        if patch is not None and asset['patch_tracker'].get(patch['id']) is None:
                            asset['patches'].append(patch)
                            asset['patch_tracker'][patch['id']] = patch['id']
                    if item['SoftwareType'] == 'Package' or item['SoftwareType'] == 'Application': #ApplicationType for Linux packages
                        pname = item['SoftwareName']
                        pversion =  item['CurrentVersion']
                        # Azure Monitoring Agent bug - version has "(none):1.4.6-1.el8" for Linux packages
                        pversion = pversion[7:] if item['SoftwareType'] == 'Package' and pversion.startswith('(none):') else pversion
                        pnv = pname + ' ' + pversion
                        if not is_product_removed(rpt, asset['id'], pnv, item['TimeGenerated']):
                            asset['products'].append(pnv)

    # Remove the additional fields 'patch_tracker' (added to avoid duplicate patches) & 'vmuuid'
    for asset in assets:
        asset.pop('patch_tracker', None)
        asset.pop('vmuuid', None)
    logging.debug("Total assets reported: %s", len(all_assets))
    logging.debug("Assets with s/w packages and patches: %s", len(assets))
    logging.debug("Not running VMs: %s", len(not_running_vms))
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
    rpt = prepare_removed_product_tracker(workspace_id)
    rjson = run_az_cmd("monitor log-analytics query -w '%s' --analytics-query 'ConfigurationData | where ConfigDataType == \"Software\" | summarize arg_max(TimeGenerated, *) by Computer, VMUUID, Publisher, SoftwareName, SoftwareType | project Computer, VMUUID, ConfigDataType, Publisher, SoftwareName, SoftwareType, CurrentVersion, TimeGenerated'" % workspace_id)
    return parse_inventory(args, rjson, rpt)

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

# Try to get OS details, subscription Id and tags for given VM
def get_vm_details(host, vmuuid):
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
            logging.debug("Unable to find VM with vmuuid [%s] for host [%s]", vmuuid, host)
            return False, None, None, None, []

    logging.debug("Getting OS details for host [%s] vmuuid [%s]", host, vmuuid)
    rjson = run_az_cmd("vm get-instance-view --ids '%s'" % vm_id)
    ijson = rjson['instanceView']
    tags = []
    if is_vm_running(ijson):
        rid = rjson['id']
        rid_tokens = rid.split('/')
        sub_id = rid_tokens[2]
        if rjson.get('tags') is not None:
            vm_tags = rjson['tags']
            for key in list(vm_tags.keys()):
                tag_name = key
                tag_value = vm_tags[key]
                tags.append(tag_name + ':' + tag_value)
        return True, ijson.get('osName'), ijson.get('osVersion'), sub_id, tags
    else:
        return False, None, None, None, tags

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

