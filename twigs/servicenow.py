import sys
import json
import re
import logging
import pysnow

from . import utils as utils

def get_product_version(asset_display_name):
    temp_product_details = re.findall(r'(.*)\((.*)\)',asset_display_name)
    return temp_product_details[0][1]

def find_host(host_cache, all_hosts, host_id):
    host_slot = host_cache.get(host_id)
    if (host_slot == None):
        return None
    return all_hosts[host_slot]

def build_host_cache(all_hosts):
    host_cache = {}
    host_count = 0
    for host in all_hosts:
        host_cache[host['sys_id']] = host_count
        host_count = host_count + 1 
    return host_cache

def get_asset_inventory(args):
    logging.info("Getting asset inventory from ServiceNow (this may take some time) ...")
    client = pysnow.Client(instance=args.snow_instance, user=args.snow_user, password=args.snow_user_pwd)

    snow_base_api_path = '/table/'
    hosts = {}
    snow_api_path = snow_base_api_path + 'alm_entitlement_asset'
    alm_entitlement_assets = client.resource(api_path=snow_api_path)
    alm_entitlement_assets_response = alm_entitlement_assets.get(query={'sys_class_name':'alm_entitlement_asset'})

    # get all hosts and add these to the cache
    snow_hosts_api_path = snow_base_api_path + 'cmdb_ci_computer'
    all_hosts_query = client.resource(api_path=snow_hosts_api_path)
    all_hosts_response = all_hosts_query.get(query={})
    all_hosts = all_hosts_response.all()
    host_cache = build_host_cache(all_hosts)

    logging.info("Processing asset information....")

    for alm_entitlement_asset in alm_entitlement_assets_response.all():
        product_version = get_product_version(alm_entitlement_asset['display_name'])
        host_id = alm_entitlement_asset['allocated_to']['value']
        host = hosts.get(host_id)
        if (host == None):
            # Get the host entry from SNow
            snow_host = find_host(host_cache, all_hosts, host_id)
            if (snow_host == None):
                # error condition
                logging.error("Error: Could not find host:", host_id)
                continue
 
            # create new host entry and add it to the dictionary
            host = {}
            host['id'] = host_id
            host['name'] = snow_host['ip_address']
            host['type'] = utils.get_asset_type(snow_host['os'])
            if host['type'] is None:
                host['type'] = 'Other'
            host['owner'] = args.handle
            products = []
            products.append(snow_host['os'])
            products.append(product_version)
            host['products'] = products
            asset_tags = []
            if args.enable_tracking_tags == True:
                asset_tags.append('SOURCE:ServiceNow:' + args.snow_instance)
                asset_tags.append("SERVICENOW_ASSET_TAG:" + snow_host['asset_tag'])
            else:
                asset_tags.append('SOURCE:ServiceNow')
            asset_tags.append('OS_RELEASE:' + snow_host['os'])
            if host['type'] != 'Other':
                asset_tags.append(host['type'])
            host['tags'] = asset_tags
            hosts[host_id] = host
        else:
            host['products'].append(product_version)

    # Convert dict of hosts to list of assets
    assets = [ h for h in hosts.values() ]
    return assets
 
def get_inventory(args):
    login = args.snow_user
    password = args.snow_user_pwd
    snow_instance = args.snow_instance

    assets = get_asset_inventory(args)
    logging.info("Total %s assets found in inventory...",str(len(assets)))
    return assets

