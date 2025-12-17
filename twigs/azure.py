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

def set_encoding(encoding):
    global g_encoding
    g_encoding = encoding

def get_encoding():
    global g_encoding
    return g_encoding

def run_az_cmd(cmd, suppress_errors=False):
    cmd = 'az ' + cmd + ' --output json --only-show-errors'
    if suppress_errors:
        cmd = cmd + ' 2>/dev/null'
    try:
        logging.debug("Running cmd [%s]", cmd)
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
        ret_json = json.loads(cmd_output)
    except subprocess.CalledProcessError:
        if suppress_errors:
            logging.debug("Error running az command [%s]", cmd)
            return None
        else:
            logging.error("Error running az command [%s]", cmd)
            utils.tw_exit(1)
    except ValueError:
        if suppress_errors:
            logging.debug("Error parsing JSON output for az command [%s]: %s", cmd, cmd_output)
            return None
        else:
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

def is_product_removed(rpt, assetid, resource_id, pnv, last_reported_on):
    tasset = rpt.get(resource_id)
    if tasset is None:
        return False
    removed_on  = rpt[resource_id].get(pnv)
    if removed_on is None:
        return False
    else:
        removed_on = convert_to_datetime(removed_on)
        last_reported_on = convert_to_datetime(last_reported_on)
        if removed_on > last_reported_on:
            logging.debug("Product [%s] removed on asset [%s] with resource_id [%s]", pnv, assetid, resource_id)
            logging.debug("ConfigurationData product last_reported_on %s", last_reported_on)
            logging.debug("ConfigurationChange product removed_on %s", removed_on)
            return True
    return False

def prepare_removed_product_tracker(workspace_id):
    logging.info("Processing configuration change data retrieved from Azure...")
    # Removed Product Tracker - this is a 2 level dict as assetid -> product -> removedtime 
    rpt = { }
    rjson = run_az_cmd("monitor log-analytics query -w '%s' --analytics-query 'ConfigurationChange | where ConfigChangeType == \"Software\" and ChangeCategory == \"Removed\" | summarize arg_max(TimeGenerated, *) by _ResourceId, Publisher, SoftwareName, SoftwareType | project _ResourceId, SoftwareName, Previous, SoftwareType, TimeGenerated'" % workspace_id)
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
        resource_id = item['_ResourceId']
        if resource_id not in rpt:
            rpt[resource_id] = { }
        rpt[resource_id][pnv] = item['TimeGenerated']
    logging.debug("Removed product tracker dict: %s", rpt)
    return rpt

def get_alternate_vm_id(vmuuid):
    # Handle Endian-ness issue with Azure VM UUIDs
    tokens = vmuuid.split('-')
    t = tokens[0]
    alt_vmuuid = "%s%s%s%s" % (t[6:8], t[4:6], t[2:4], t[0:2])
    t = tokens[1]
    alt_vmuuid = alt_vmuuid + "-%s%s" % (t[2:4], t[0:2])
    t = tokens[2]
    alt_vmuuid = alt_vmuuid + "-%s%s" % (t[2:4], t[0:2])
    alt_vmuuid = alt_vmuuid + '-%s-%s' % (tokens[3], tokens[4])
    return alt_vmuuid

def parse_inventory(args, data, rpt):
    logging.info("Processing inventory retrieved from Azure...")
    vm_resources = []
    assets = []
    asset_map = {}
    not_running_vms = {}
    resource_id_2_vm_id = {}
    all_assets = { }
    for item in data:
        all_assets[item['_ResourceId']] = item['Computer']
        logging.debug("Parsing inventory from data below:\n%s", json.dumps(item, indent=2))
        host = item['Computer']
        resource_id = item['_ResourceId']
        publisher = item['Publisher']

        # If VM is known to be not running, then skip it
        if not_running_vms.get(resource_id) == 1:
            continue

        if resource_id not in vm_resources  and publisher != '0':
            if resource_id in resource_id_2_vm_id:
                vm_id = resource_id_2_vm_id[resource_id]
            else:
                vm_running, os, os_version, sub_id, vm_id, tags = get_vm_details(host, resource_id)
                if vm_running == False:
                    # skip vm's which are not running
                    not_running_vms[resource_id] = 1
                    continue
                resource_id_2_vm_id[resource_id] = vm_id
            alt_vm_id = get_alternate_vm_id(vm_id)
            vmuuid = item['VMUUID'].lower()
            if vm_id != vmuuid and alt_vm_id != vmuuid:
                # not latest VM for resource_id, so ignore it
                logging.debug("Found old software %s", item)
                continue
            logging.debug("Found new asset - host [%s] resource_id [%s]", host, resource_id)
            patches = []
            products = []
            asset_map = {}
            asset_map['owner'] = args.handle
            asset_map['id'] = vm_id
            asset_map['name'] = host
            asset_map['tags'] = [ ]
            asset_map['patch_tracker'] = { } # To help remove duplicate patches
            asset_map['resource_id'] = resource_id
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
                if not is_product_removed(rpt, asset_map['id'], asset_map['resource_id'], pnv, item['TimeGenerated']):
                    products.append(pnv)
            asset_map['products'] = products
            asset_map['patches'] = patches
            asset_map['type'] = get_os_type(os)
            if len(asset_map['type']) > 0:
                asset_map['tags'].append(asset_map['type'])
            if len(tags) > 0:
                asset_map['tags'].extend(tags)
            if asset_map['type'] == 'Windows':
                asset_map['tags'].append('OS_RELEASE:' + os)
                asset_map['tags'].append(os)
                asset_map['tags'].append('OS_VERSION:' + os_version)
            else:
                asset_map['tags'].append('OS_RELEASE:%s %s' % (os, os_version))
                asset_map['tags'].append('%s %s' % (os, os_version))
            if args.enable_tracking_tags == True:
                asset_map['tags'].append("SOURCE:Azure:Tenant:" + get_tenant_id())
                asset_map['tags'].append("Azure:Tenant:" + get_tenant_id())
                asset_map['tags'].append("SOURCE:Azure:Subscription:" + sub_id)
                asset_map['tags'].append("Azure:Subscription:" + sub_id)
            else:
                asset_map['tags'].append("SOURCE:Azure")
                asset_map['tags'].append("Azure")
            assets.append(asset_map)
            vm_resources.append(resource_id)
        else:
            vm_id = resource_id_2_vm_id[resource_id]
            alt_vm_id = get_alternate_vm_id(vm_id)
            vmuuid = item['VMUUID'].lower()
            if vm_id != vmuuid and alt_vm_id != vmuuid:
                # not latest VM for resource_id, so ignore it
                logging.debug("Found old software %s", item)
                continue
            for asset in assets:
                if asset['resource_id'] == resource_id:
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
                        if not is_product_removed(rpt, asset['id'], asset['resource_id'], pnv, item['TimeGenerated']):
                            asset['products'].append(pnv)

    # Remove the additional fields 'patch_tracker' (added to avoid duplicate patches) & 'resource_id'
    for asset in assets:
        asset.pop('patch_tracker', None)
        asset.pop('resource_id', None)
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
    rjson = run_az_cmd("monitor log-analytics query -w '%s' --analytics-query 'ConfigurationData | where ConfigDataType == \"Software\" | summarize arg_max(TimeGenerated, *) by _ResourceId, Publisher, SoftwareName, SoftwareType | project Computer, _ResourceId, VMUUID, ConfigDataType, Publisher, SoftwareName, SoftwareType, CurrentVersion, TimeGenerated'" % workspace_id)
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

def is_cm_running(cm_json):
    status = cm_json.get('status')
    if status == "Connected":
        return True
    return False

def get_tags(rjson):
    tags = []
    if rjson.get('tags') is not None:
        vm_tags = rjson['tags']
        for key in list(vm_tags.keys()):
            tag_name = key
            tag_value = vm_tags[key]
            tags.append(tag_name + ':' + tag_value)
    return tags

# Try to get OS details, subscription Id and tags for given VM
def get_vm_details(host, resource_id):
    logging.debug("Getting OS details for host [%s] resource_id [%s]", host, resource_id)
    rid_tokens = resource_id.split('/')
    sub_id = rid_tokens[2]
    if '/providers/microsoft.hybridcompute/machines/' in resource_id.lower():
        # Azure Connected Machines i.e. external to Azure
        rjson = run_az_cmd("connectedmachine show --ids '%s'" % resource_id, True)
        if rjson is None:
            return False, None, None, None, None, []
        if is_cm_running(rjson):
            osname = rjson['osName'] if rjson['osName'].lower() != 'windows' else rjson['osSku']
            osversion = rjson['osVersion']
            vm_id = rjson['vmUuid'].lower()
            tags = get_tags(rjson)
            tags.append("AzureArcConnectedMachine")
            return True, osname, osversion, sub_id, vm_id, tags
        else:
            return False, None, None, None, None, []
    else:
        # Azure VMs
        rjson = run_az_cmd("vm get-instance-view --ids '%s'" % resource_id, True)
        if rjson is None:
            # VM not found (probably deleted)
            return False, None, None, None, None, []
        ijson = rjson['instanceView']
        # At times VM is marked as running but osName details are not yet populated in instanceView JSONand in such cases it is best to skip the VM in this discovery for now.
        if is_vm_running(ijson) and ijson.get('osName') is not None and len(ijson['osName'].strip()) > 0:
            vm_id = rjson['vmId'].lower()
            tags = get_tags(rjson)
            return True, ijson.get('osName'), ijson.get('osVersion'), sub_id, vm_id, tags
        else:
            return False, None, None, None, None, []

