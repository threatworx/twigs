import sys
import json
import os
import requests
import re
import logging

# Prints details about subscriptions, resource groups and workspaces
def print_details(token):
    allsubs = get_all_subscriptions(token)
    print ""
    print "Missing details for subscription/resource group/workspace...."
    print "Available subscriptions with resource group and workspace details as below:"
    for sub in allsubs:
        print "Subscription: %s" % sub
        resourcegroups = get_all_resourcegroups_for_subscription(sub, token)
        for res_group in resourcegroups:
            print " ** Resource group: %s" % res_group
        workspaces = get_all_workspaces_for_subscription(sub, token)
        for workspace in workspaces:
            print " ** Workspace: %s" % workspace
    print ""
    print "Please re-run twigs with appropriate values for subscription, resource group and workspace."
    print ""
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
    token = get_access_token(params)
    if token is None:
        return
    params['access_token'] = token
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
    for i in range(len(data)):
        if data[i][4] == 'WindowsServices': #ConfigDataType
            continue
        host = data[i][5]
        publisher = data[i][2]

        if host not in hosts  and publisher != '0':
            patches = []
            products = []
            asset_map = {}
            asset_map['owner'] = email
            asset_map['host'] = host
            asset_map['id'] = host
            asset_map['name'] = host
            asset_map['tags'] = [ ]
            asset_map['patch_tracker'] = { } # To help remove duplicate patches
            if data[i][1] == 'Update': #ApplicationType for MS patches
                patch = parse_patch(data[i])
                patches.append(patch)
                asset_map['patch_tracker'][patch['id']] = patch['id']
            if data[i][1] == 'Package' or data[i][1] == 'Application': #ApplicationType for Linux packages
                pname = data[i][0]
                pversion =  data[i][3]
                products.append(pname+' ' + pversion)
            asset_map['products'] = products
            asset_map['patches'] = patches
            os = get_os_name(host,params)
            asset_map['type'] = get_os_type(os)
            if len(asset_map['type']) > 0:
                asset_map['tags'].append(asset_map['type'])
            if asset_map['type'] == 'Windows':
                asset_map['tags'].append('OS_RELEASE:' + os)
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
                        if asset['patch_tracker'].get(patch['id']) is None:
                            patches.append(patch)
                            asset['patches'] = patches
                            asset['patch_tracker'][patch['id']] = patch['id']
                    if data[i][1] == 'Package' or data[i][1] == 'Application': #ApplicationType for Linux packages
                        pname = data[i][0]
                        pversion =  data[i][3]
                        products.append(pname+' ' + pversion)
                        asset['products'] = products
    # Remove the additional field 'patch_tracker' (added to avoid duplicate patches)
    for asset in assets:
        asset.pop('patch_tracker', None)
    return assets

def parse_patch(data):
    patch_id = re.findall(r'(KB[0-9]+)', data[0])
    patch = {}
    patch['url'] = ''
    patch['id'] = patch_id[0]
    patch['product'] = ''
    patch['description'] = data[0]
    return patch
            
def get_os_type(ostype):
    if ostype is None:
        return ''
    if 'Microsoft' in  ostype or 'Windows' in ostype:
        return 'Windows'
    if 'Red Hat' in ostype or 'redhat' in ostype:
        return 'Red Hat'
    return ''

def retrieve_inventory(params):
    email = params['handle']
    sub_id = params['subscription']
    resource_group = params['resource_group']
    workspace_id = params['workspace']
    token = params['access_token']
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % token }
    url = 'https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s/api/query?api-version=2017-01-01-preview' % (sub_id,resource_group,workspace_id)
    json_data = {"query":"ConfigurationData | summarize by SoftwareName, SoftwareType, Publisher, CurrentVersion, ConfigDataType, Computer"}

    logging.info("Retrieving inventory details from Azure...") 

    resp = requests.post(url, headers=headers, json=json_data)
    if resp.status_code == 200:
        response = resp.json()
        if response.get('Tables'):
            tables = response['Tables']
            return parse_inventory(email,tables[0]['Rows'],params)
    else:
        logging.error("Error could not get asset inventory details from Azure...")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

#Get access token using  an AAD, an app id associted with that AAD and the API key/secret for that app
def get_access_token(params):         
    aad_id = params['tenant_id']
    aad_app_id = params['app_id']
    app_key = params['app_key']
    url = "https://login.microsoftonline.com/" + aad_id + "/oauth2/token"

    logging.info("Getting access token...") 

    resp = requests.post(url, data={"grant_type":"client_credentials", "client_id": aad_app_id, "client_secret": app_key, "resource":"https://management.azure.com/"})
    if resp.status_code == 200:
        response = resp.json()
        token = response['access_token']
    else:
        logging.error("Error unable to get access token for API calls")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

    return token

# Try to get OS details for given VM
def get_os_name(host,params):
    headers = { "Content-Type":"application/json", "Authorization": "Bearer %s" % params['access_token'] }
    url = "https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/instanceView?api-version=2018-06-01" % (params['subscription'], params['resource_group'],host)

    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        response = resp.json()
        return response.get('osName')
    else:
        return None

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
            allworkspaces.append(w['name'])
    else:
        logging.error("API call to get all workspaces failed")
        logging.error("Response content: %s" % resp.text)
        sys.exit(1)

    return allworkspaces

