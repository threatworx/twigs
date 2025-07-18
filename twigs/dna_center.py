import json
import requests
import logging
import urllib3

from . import utils

# Disable warnings for insecure HTTPS requests (optional, for self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get Auth Token
def get_token(args):
    url = args.url + "/dna/system/api/v1/auth/token"
    response = requests.post(url, auth=(args.user, args.password), verify=False)
    response.raise_for_status()
    token = response.json()["Token"]
    return token

# Get network devices
def get_devices(args, token):
    url = args.url + "dna/intent/api/v1/network-device"
    headers = {'X-Auth-Token': token}
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get('response', [])

# Main entry point
def get_inventory(args):
    assets = []
    logging.info("Retrieving network inventory from Cisco DNA Center") 
    token = get_token(args)
    devices = get_devices(args, token)

    for device in devices:
        asset = {}
        asset['owner'] = args.handle
        asset['id'] = device['managementIpAddress']
        asset['name'] = device['hostname']
        asset['type'] = 'Cisco'
        asset_tags = ['Model:'+device['platformId'], 'Serial Number:'+device['serialNumber']]
        products = ['Cisco '+device['platformId']+' '+device['softwareVersion']]
        asset['products'] = products
    return assets
