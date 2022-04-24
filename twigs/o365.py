import sys
import json
import os
import requests
import re
import logging

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
    assets = []
    for machine in allmachines:
        asset = {}
        asset['owner'] = args.handle
        asset['id'] = machine['id']
        asset['name'] = machine['lastIpAddress']
        asset['type'] = 'Windows'
        asset_tags = []
        asset_tags.append('Windows')
        asset_tags.append('Source:O365')
        asset_tags.append('OS_RELEASE:' + machine['osPlatform'])
        asset_tags.append('OS_VERSION:' + machine['version'])
        for tag in machine['machineTags']:
            asset_tags.append(tag)
        products = []
        url = "https://api.securitycenter.microsoft.com/api/machines/"+machine['id']+"/software"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logging.error("Error could not get asset inventory details from O365")
            logging.error("Response content: %s" % resp.text)
            continue
        allproducts = resp.json()['value']
        for product in products:
            newproduct = product['vendor'] + " " + product['name']
            newproduct = newproduct.replace('_',' ')
            products.append(newproduct)
        asset['products'] = products
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
        sys.exit(1)

    return token

# Main entry point
def get_inventory(args):
    token = get_access_token(args)
    if token is None:
        logging.error("Error unable to get access token for API calls")
        return
    return [] 


