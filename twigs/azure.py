import sys
import json
import boto3
import difflib
import codecs
import os
import subprocess
import re
import logging
import argparse
import requests

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

# Main entry point
def inventory(args):
    asset_url = "https://" + args.instance + "/api/v2/assets/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    params =  {}
    params['handle'] = args.handle
    params['tenant_id'] = args.azure_tenant_id
    params['app_id'] = args.azure_application_id
    params['app_key'] = args.azure_application_key
    params['subscription'] = args.azure_subscription
    params['resource_group'] = args.azure_resource_group
    params['workspace'] = args.azure_workspace
    token = get_access_token(params)
    if token is None:
        return
    params['access_token'] = token
    if args.azure_subscription is None or args.azure_resource_group is None or args.azure_workspace is None:
        print_details(token)
        return
    assets = get_inventory(params)
    logging.info("Importing inventory...")
    for asset in assets:
        resp = requests.get(asset_url + asset['id'] + "/" + auth_data)
        if resp.status_code != 200:
            # asset does not exist so create one with POST
            resp = requests.post(asset_url + auth_data, json=asset)
            if resp.status_code == 200:
                logging.info("Successfully created asset [%s]...", asset['name'])
            else:
                logging.error("Failed to create new asset: %s", json.dumps(asset))
                logging.error("Response details: %s", resp.content)
        else:
            # asset exists so update it with PUT
            resp = requests.put(asset_url + asset['id'] + "/" + auth_data, json=asset)
            if resp.status_code == 200:
                logging.info("Successfully updated asset [%s]...", asset['name'])
            else:
                logging.error("Failed to updated existing asset [%s]...", asset['name'])
                logging.error("Response details: %s", resp.content)    

def parse_inventory(email,data):
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
            asset_map['type'] = get_os_type(publisher)
            asset_map['tags'] = [ asset_map['type'] ]
            if data[i][1] == 'Update': #ApplicationType for MS patches
                patches.append(parse_patch(data[i]))
            if data[i][1] == 'Package' or data[i][1] == 'Application': #ApplicationType for Linux packages
                pname = data[i][0]
                pversion =  data[i][3]
                products.append(pname+' ' + pversion)
            asset_map['products'] = products
            asset_map['patches'] = patches
            assets.append(asset_map)
            hosts.append(host)
        else:
            for asset in assets:
                if asset['host'] == host:
                    products = asset['products']
                    patches = asset['patches']
                    if data[i][1] == 'Update': #ApplicationType for MS patches
                        patches.append(parse_patch(data[i]))
                        asset['patches'] = patches
                    if data[i][1] == 'Package' or data[i][1] == 'Application': #ApplicationType for Linux packages
                        pname = data[i][0]
                        pversion =  data[i][3]
                        products.append(pname+' ' + pversion)
                        asset['products'] = products
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
    if 'Microsoft' in  ostype:
        return 'Windows'
    if 'Red Hat' in ostype:
        return 'Red Hat'
    return ''

def get_inventory(params):
    email = params['handle']
    sub_id = params['subscription']
    resource_group = params['resource_group']
    workspace_id = params['workspace']
    token = params['access_token']
    CURL = '/usr/bin/curl --silent -H "Content-Type:application/json" -H "Authorization:Bearer %s" -d ' % token
    URL = '-X POST https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s/api/query?api-version=2017-01-01-preview' %(sub_id,resource_group,workspace_id)
    DATA = '{"query":"ConfigurationData | summarize by SoftwareName, SoftwareType, Publisher, CurrentVersion, ConfigDataType, Computer"}' 
    cmd = CURL + "'" + DATA + "'" + " " + URL

    logging.info("Retrieving inventory details from Azure...") 

    p = subprocess.Popen(cmd, bufsize=8192, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    pstat = p.wait()

    if output == "Error":
        print "Could not fetch threat updates"
        sys.exit(1)

    if output == "Kill":
        print "Invalid tw instance...terminating"
        sys.exit(1)

    response = json.loads(output)
    if response.get('Tables'):
        tables = response['Tables']
        return parse_inventory(email,tables[0]['Rows'])

#Get access token using  an AAD, an app id associted with that AAD and the API key/secret for that app
def get_access_token(params):         
    aad_id = params['tenant_id']
    aad_app_id = params['app_id']
    app_key = params['app_key']
    CURL = '/usr/bin/curl --silent -d '
    URL = "-X POST https://login.microsoftonline.com/" + aad_id + "/oauth2/token"
    DATA = 'grant_type=client_credentials&client_id=%s&client_secret=%s&resource=https://management.azure.com/' % (aad_app_id,app_key)

    cmd = CURL + "'" + DATA + "'"  + " " + URL

    logging.info("Getting access token...") 

    p = subprocess.Popen(cmd, bufsize=8192, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    pstat = p.wait()

    if output == "Error":
        print "Could not fetch threat updates"
        return '' 

    if output == "Kill":
        return '' 
    try:
        response = json.loads(output)
        token = response['access_token']
    except KeyError:
        error = response['error_description']
        print error
        return None
    return token

# Get a list of subscriptions for current AAD/Tenant
def get_all_subscriptions(token):
    allsubs = []
    CURL = '/usr/bin/curl --silent -H "Content-Type:application/json" -H "Authorization:Bearer %s" ' % token
    URL = "-X GET https://management.azure.com/subscriptions?api-version=2018-01-01"
    cmd = CURL + URL

    p = subprocess.Popen(cmd, bufsize=8192, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    pstat = p.wait()

    if output == "Error":
        print "Could not fetch threat updates"
        sys.exit(1)

    if output == "Kill":
        print "Invalid tw instance...terminating"
        sys.exit(1)

    subs = json.loads(output)
    sublist = subs['value']
    for sub in sublist:
        allsubs.append(sub['subscriptionId'])
    return allsubs

#Get all resource groups for a subscription
def get_all_resourcegroups_for_subscription(subid,token):
    allresourcegroups = []
    CURL = '/usr/bin/curl --silent -H "Content-Type:application/json" -H "Authorization:Bearer %s" ' % token
    URL = '-X GET https://management.azure.com/subscriptions/%s/resourcegroups?api-version=2018-01-01' % subid
    cmd = CURL + URL

    p = subprocess.Popen(cmd, bufsize=8192, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    pstat = p.wait()

    if output == "Error":
        print "Could not fetch resourcegroups"
        return []
       
    if output == "Kill":
        print "Could not fetch resourcegorups"
        return []

    rgroups = json.loads(output)
    rlist = rgroups['value']
    for r in rlist:
        allresourcegroups.append(r['name'])
    return allresourcegroups

#Get all workspaces for the subscription
def get_all_workspaces_for_subscription(subid,token):
    allworkspaces = []
    CURL = '/usr/bin/curl --silent -H "Content-Type:application/json" -H "Authorization:Bearer %s" ' % token
    URL = '-X GET https://management.azure.com/subscriptions/%s/providers/Microsoft.OperationalInsights/workspaces?api-version=2017-01-01-preview' % subid
    cmd = CURL + URL

    p = subprocess.Popen(cmd, bufsize=8192, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    pstat = p.wait()

    if output == "Error":
        print "Could not get workspaces"
        return []

    if output == "Kill":
        print "Could not get workspaces"
        return []

    workspaces = json.loads(output)
    wlist = workspaces['value']
    for w in wlist:
        allworkspaces.append(w['name'])
    return allworkspaces

