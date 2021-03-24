import sys
import json
import os
import requests
import re
import logging

gAllVMs = None

def get_all_vms(params):
    global gAllVMs
    if gAllVMs is not None:
        return gAllVMs
    gAllVMs = { }
    access_token = params['access_token']
    allsubs = get_all_subscriptions(access_token)
    for sub in allsubs:
        resourcegroups = get_all_resourcegroups_for_subscription(sub, access_token)
        for res_group in resourcegroups:
            vms = get_vms(access_token, sub, res_group)
            gAllVMs.update(vms)
    return gAllVMs

# Prints details about subscriptions, resource groups and workspaces
def print_details(token):
    allsubs = get_all_subscriptions(token)
    print( "")
    print("Missing details for subscription/resource group/workspace....")
    print("Available subscriptions with resource group and workspace details as below:")
    for sub in allsubs:
        print("Subscription: %s" % sub)
        resourcegroups = get_all_resourcegroups_for_subscription(sub, token)
        for res_group in resourcegroups:
            print(" ** Resource group: %s" % res_group)
        workspaces = get_all_workspaces_for_subscription(sub, token)
        for workspace in workspaces:
            print(" ** Workspace: %s" % workspace)
    print("")
    print("Please re-run twigs with appropriate values for subscription, resource group and workspace.")
    print("")
    sys.exit(1)

# Main entry point
def get_inventory(args):
    params =  {}
    params['handle'] = args.handle
    params['tenant_id'] = args.azure_tenant_id
    params['app_id'] = args.azure_application_id
    params['app_key'] = args.azure_application_key
    params['subscription'] = args.azure_subscription
    params['resource_group'] = args.azure_resource_group
    params['workspace'] = args.azure_workspace
    params['enable_tracking_tags'] = args.enable_tracking_tags
    token = get_access_token(params, "https://management.azure.com/")
    if token is None:
        return
    params['access_token'] = token
    get_all_vms(params)
    if args.azure_subscription is None or args.azure_resource_group is None or args.azure_workspace is None:
        print_details(token)
        return
    assets = retrieve_inventory(params)
    return assets

def parse_inventory(email,data,params):
    logging.info("Processing inventory retrieved from Azure...")
    hosts = []
    assets = []
    asset_map = {}
    not_running_vms = {}
    temp_assets = set()
    all_assets = { }
    for i in range(len(data)):
        all_assets[data[i][5]] = data[i][6]
        if data[i][4] == 'WindowsServices': #ConfigDataType
            #logging.warning("Logging WindowsServices data below:\n%s", json.dumps(data[i], indent=2))
            temp_assets.add(data[i][5])
            continue
        #logging.debug("Parsing inventory from data below:\n%s", json.dumps(data[i], indent=2))
        host = data[i][5]
        vmuuid = data[i][6]
        publisher = data[i][2]

        # If VM is known to be not running, then skip it
        if not_running_vms.get(vmuuid) == 1:
            continue

        if host not in hosts  and publisher != '0':
            logging.debug("Found new asset - host [%s] vmuuid [%s]", host, vmuuid)
            patches = []
            products = []
            asset_map = {}
            asset_map['owner'] = email
            asset_map['host'] = host
            asset_map['id'] = vmuuid
            asset_map['name'] = host
            asset_map['tags'] = [ ]
            asset_map['patch_tracker'] = { } # To help remove duplicate patches
            asset_map['vmuuid'] = vmuuid
            if data[i][1] == 'Update': #ApplicationType for MS patches
                patch = parse_patch(data[i])
                if patch is not None:
                    patches.append(patch)
                    asset_map['patch_tracker'][patch['id']] = patch['id']
            if data[i][1] == 'Package' or data[i][1] == 'Application': #ApplicationType for Linux packages
                pname = data[i][0]
                pversion =  data[i][3]
                products.append(pname+' ' + pversion)
            asset_map['products'] = products
            asset_map['patches'] = patches
            vm_running, os, os_version = get_os_details(host, vmuuid, params)
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
            if params['enable_tracking_tags'] == True:
                asset_map['tags'].append("SOURCE:Azure:" + params['tenant_id'])
            else:
                asset_map['tags'].append("SOURCE:Azure")
            assets.append(asset_map)
            hosts.append(host)
        else:
            for asset in assets:
                if asset['host'] == host:
                    products = asset['products']
                    patches = asset['patches']
                    if data[i][1] == 'Update': #ApplicationType for MS patches
                        patch = parse_patch(data[i])
                        if patch is not None and asset['patch_tracker'].get(patch['id']) is None:
                            patches.append(patch)
                            asset['patches'] = patches
                            asset['patch_tracker'][patch['id']] = patch['id']
                    if data[i][1] == 'Package' or data[i][1] == 'Application': #ApplicationType for Linux packages
                        pname = data[i][0]
                        pversion =  data[i][3]
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

def parse_patch(data):
    patch_id = re.findall(r'(KB[0-9]+)', data[0])
    if len(patch_id) == 0:
        return None
    patch = {}
    patch['url'] = ''
    patch['id'] = patch_id[0]
    patch['product'] = ''
    patch['description'] = data[0]
    return patch
            
def get_os_type(ostype):
    asset_type = ''
    if ostype is None:
        asset_type = ''
    elif 'Microsoft' in  ostype or 'Windows' in ostype:
        asset_type = 'Windows'
    elif 'Red Hat' in ostype or 'redhat' in ostype:
        asset_type = 'Red Hat'
    elif 'Ubuntu' in ostype or 'ubuntu' in ostype:
        asset_type = 'Ubuntu'
    elif 'CentOS' in ostype or 'centos' in ostype:
        asset_type = 'CentOS'
    elif 'Oracle' in ostype or 'oracle' in ostype:
        asset_type = "Oracle Linux"
    logging.debug("Mapped OS [%s] to Asset Type [%s]", ostype, asset_type)
    return asset_type

def retrieve_inventory(params):
    email = params['handle']
    sub_id = params['subscription']
    resource_group = params['resource_group']
    workspace_id = params['workspace']
    token = get_access_token(params, "https://api.loganalytics.io/")
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % token }
    url = 'https://api.loganalytics.io/v1/workspaces/%s/query' % workspace_id
    json_data = {"query":"ConfigurationData | summarize by SoftwareName, SoftwareType, Publisher, CurrentVersion, ConfigDataType, Computer, VMUUID"}

    logging.info("Retrieving inventory details from Azure...") 

    resp = requests.post(url, headers=headers, json=json_data)
    if resp.status_code == 200:
        response = resp.json()
        if response.get('tables'):
            tables = response['tables']
            return parse_inventory(email,tables[0]['rows'],params)
    else:
        logging.error("Error could not get asset inventory details from Azure...")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

#Get access token using  an AAD, an app id associted with that AAD and the API key/secret for that app
def get_access_token(params, resource):
    aad_id = params['tenant_id']
    aad_app_id = params['app_id']
    app_key = params['app_key']
    url = "https://login.microsoftonline.com/" + aad_id + "/oauth2/token"

    logging.info("Getting access token for resource [%s]...", resource) 

    resp = requests.post(url, data={"grant_type":"client_credentials", "client_id": aad_app_id, "client_secret": app_key, "resource":resource})
    if resp.status_code == 200:
        response = resp.json()
        token = response['access_token']
    else:
        logging.error("Error unable to get access token for API calls")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

    return token

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
def get_os_details(host, vmuuid, params):
    all_vms = get_all_vms(params)
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

    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % params['access_token'] }
    url = "https://management.azure.com" + vm_id + "/instanceView?api-version=2018-06-01"

    logging.debug("Getting OS details for host [%s] vmuuid [%s]", host, vmuuid)
    logging.debug("Using URL [%s]", url)
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        response = resp.json()
        logging.debug("Got response:\n%s", json.dumps(response, indent=2))
        if is_vm_running(response):
            return True, response.get('osName'), response.get('osVersion')
        else:
            return False, None, None
    else:
        logging.warn("Warning unable to get OS version details for VM [%s]. It might not be running..." % host)
        return False, None, None

# Get details for all VMs
def get_vms(access_token, subscription, resource_group):
    all_vms = { }
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % access_token }
    url = "https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01" % (subscription, resource_group)
    while url is not None:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            response = resp.json()
            for vm in response['value']:
                vmuuid = vm['properties']['vmId']
                all_vms[vmuuid] = vm['id']
            url = response.get('nextLink')
        else:
           url = None
    return all_vms

# Get a list of subscriptions for current AAD/Tenant
def get_all_subscriptions(token):
    allsubs = []
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % token }
    url = "https://management.azure.com/subscriptions?api-version=2018-01-01"

    resp = requests.get(url, headers=headers)

    if resp.status_code == 200:
        subs = resp.json()
        sublist = subs['value']
        for sub in sublist:
            allsubs.append(sub['subscriptionId'])
    else:
        logging.error("API call to get all subscriptions failed")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)
    return allsubs

#Get all resource groups for a subscription
def get_all_resourcegroups_for_subscription(subid,token):
    allresourcegroups = []
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % token }
    url = 'https://management.azure.com/subscriptions/%s/resourcegroups?api-version=2018-01-01' % subid
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        rgroups = resp.json()
        rlist = rgroups['value']
        for r in rlist:
            allresourcegroups.append(r['name'])
    else:
        logging.error("API call to get all resource groups failed")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

    return allresourcegroups

#Get all workspaces for the subscription
def get_all_workspaces_for_subscription(subid,token):
    allworkspaces = []
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % token }
    url = 'https://management.azure.com/subscriptions/%s/providers/Microsoft.OperationalInsights/workspaces?api-version=2017-01-01-preview' % subid

    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        workspaces = resp.json()
        wlist = workspaces['value']
        for w in wlist:
            allworkspaces.append(w['properties']['customerId'])
    else:
        logging.error("API call to get all workspaces failed")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

    return allworkspaces

