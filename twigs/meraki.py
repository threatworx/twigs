import sys
import json
import os
import requests
import re
import logging
import random
import time

from . import utils

def get_organizations(args, headers):
   url = args.base_url + f'/organizations'
   resp = requests.get(url, headers=headers)
   resp.raise_for_status()
   return resp.json()

def get_networks(args, headers, org_id):
   url = args.base_url + f'/organizations/{org_id}/networks'
   resp = requests.get(url, headers=headers, verify=False)
   resp.raise_for_status()
   return resp.json()

def get_devices(args, headers, org_id):
   url = args.base_url + f'/organizations/{org_id}/devices'
   resp = requests.get(url, headers=headers, verify=False)
   resp.raise_for_status()
   return resp.json()

def get_firmware_upgrades(args, headers, network_id):
   url = args.base_url + f'/networks/{network_id}/firmwareUpgrades'
   resp = requests.get(url, headers=headers, verify=False)
   if resp.status_code == 404:
       return None  # Some networks may not support this endpoint
   resp.raise_for_status()
   return resp.json()

def get_all_devices(args, headers):
    assets = []
    logging.info("Retrieving network inventory from Cisco Meraki") 
    organizations = get_organizations(args, headers)
    for org in organizations:
        logging.info(f"Organization: {org['name']} ({org['id']})")
        networks = get_networks(args, headers, org['id'])
        devices = get_devices(args, headers, org['id'])
        devices_by_network = {}
        for device in devices:
            devices_by_network.setdefault(device['networkId'], []).append(device)
        for net in networks:
            logging.info(f"Network: {net['name']} ({net['id']})")
            fw_info = get_firmware_upgrades(args, headers, net['id'])
            fw_versions = {}
            if fw_info and 'products' in fw_info:
               for product in fw_info['products']:
                   fw_versions[product] = fw_info['products'][product]['currentVersion']['shortName']
            for device in devices_by_network.get(net['id'], []):
                product_type = device.get('productType', 'unknown')
                fw_version = fw_versions.get(product_type, 'unknown')
                logging.info(f"Device: {device.get('name', device['serial'])} | Model: {device['model']} | Product: {product_type} | Firmware: {fw_version}")
                asset = {}
                asset['owner'] = args.handle
                asset['id'] = device['serial']
                asset['name'] = device['model']
                asset['type'] = 'Cisco'
                asset_tags = [product_type, net['name']]
                model = device['model']
                if '-' in model:
                    model = model.split('-')[0]
                prodstr = 'Cisco Meraki '+model
                if fw_version != None:
                    prodstr = prodstr + ' firmware ' + fw_version.split()[1]
                products = [prodstr]
                asset['products'] = products
                assets.append(asset)
    return assets

# Main entry point
def get_inventory(args):
    headers = {
        'X-Cisco-Meraki-API-Key': args.api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    return get_all_devices(args, headers)

