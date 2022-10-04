import sys
import json
import os
import requests
import re
import logging
import random
import time

from . import utils

def get_machines(args, token):
    headers = { "Content-Type":"application/json", "Accept": "application/json", "Authorization": "Bearer %s" % token }
    url = "https://api.securitycenter.microsoft.com/api/machines?$filter=riskScore+eq+'High'"

    logging.info("Retrieving inventory o365") 

    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logging.error("Error could not get asset inventory details from O365")
        logging.error("Response content: %s" % resp.text)
        return
    response = resp.json()
    allmachines = response['value']
    logging.debug("Retrieved "+str(len(allmachines))+" machine details")
    assets = []
    for machine in allmachines:
        asset = {}
        asset['owner'] = args.handle
        asset['id'] = machine['id']
        asset['name'] = machine['computerDnsName']
        asset['type'] = 'Windows'
        asset_tags = []
        asset_tags.append('Windows')
        asset_tags.append('SOURCE:O365')
        asset_tags.append('OS_RELEASE_ID:' + machine['version'])
        asset_tags.append('OS_VERSION:' + 'Build '+str(machine['osBuild']))
        asset_tags.append('OS_ARCH:' + machine['osProcessor'] + '-based PC')
        for tag in machine['machineTags']:
            asset_tags.append(tag)
        if asset['name'].startswith('lap'):
            asset_tags.append('LAPTOP')
        if asset['name'].startswith('wks'):
            asset_tags.append('WORKSTATION')
        if asset['name'].startswith('wow'):
            asset_tags.append('WORKSTATION_ON_WHEELS')
        if asset['name'].startswith('sh'):
            asset_tags.append('SERVER')
        asset['tags'] = asset_tags

        products = []
        logging.debug("Getting product info for "+asset['name'])
        url = "https://api.securitycenter.microsoft.com/api/machines/"+machine['id']+"/software"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logging.error("Error could not get asset inventory details from O365")
            logging.error("Response content: %s" % resp.text)
            continue
        allproducts = resp.json()['value']
        for product in allproducts:
            newproduct = product['vendor'] + " " + product['name']
            newproduct = newproduct.replace('_',' ')
            products.append(newproduct)
        asset['products'] = products

        # get vulnerabilities for machine id
        impacts = []
        logging.debug("Getting vulnerabilities for "+asset['name'])
        url = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$filter=machineId+eq+'"+machine['id']+"'"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logging.error("Error could not get asset inventory details from O365")
            logging.error("Response content: %s" % resp.text)
            continue
        allvulns = resp.json()['value']
        for v in allvulns:
            finding = {}
            finding['type'] = 'IMPACT'
            finding['id_str'] = v['cveId']
            finding['percentage'] = 100
            prod = v['productVendor'] + ' ' + v['productName'] + ' ' + v['productVersion']
            prod = prod.replace('_',' ')
            finding['keyword'] = prod
            finding['product'] = prod
            finding['analysis'] = ''
            if v['fixingKbId'] != None:
                reco = 'Requires Windows patch/KB: '+v['fixingKbId']
            else:
                reco = 'Please look for patches/remediations for "'+prod+'" in related advisories' 
            finding['recommendation'] = reco 
            impacts.append(finding)
        if len(impacts) == 0:
            logging.debug("No vulnerabilities for "+asset['name'])
            continue

        asset['impacts'] = impacts

        assets.append(asset)

        r = random.uniform(0.5,1.5)
        time.sleep(r)
    return assets

def get_access_token(args):
    aad_id = args.tenant_id
    aad_app_id = args.application_id
    app_key = args.application_key
    url = "https://login.microsoftonline.com/" + aad_id + "/oauth2/token"
    resource = "https://api.securitycenter.microsoft.com"

    logging.info("Getting access token for resource [%s]...", resource) 

    resp = requests.post(url, data={"grant_type":"client_credentials", "client_id": aad_app_id, "client_secret": app_key, "resource":resource})
    if resp.status_code == 200:
        response = resp.json()
        token = response['access_token']
    else:
        logging.error("Error unable to get access token for API calls")
        logging.error("Response content: %s" % resp.text)
        utils.tw_exit(1)

    return token

# Main entry point
def get_inventory(args):
    token = get_access_token(args)
    if token is None:
        logging.error("Error unable to get access token for API calls")
        return
    return get_machines(args,token)

