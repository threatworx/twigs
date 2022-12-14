import sys
import logging
import json
import csv

from . import utils

all_asset_types = None

def get_assets_from_json_file(in_file):
    assets = []
    with open(in_file,'r') as fd:
        try:
            sbom_json = json.load(fd)
            assets = sbom_json['assets']
        except ValueError:
            logging.error("Error loading JSON file [%s]", in_file)
            utils.tw_exit(1)
    return assets

def get_assets_from_csv_file(in_file, args):
    assets = []
    with open(in_file, 'rU') as fd:
        csv_reader = csv.DictReader(fd, delimiter=',', escapechar='\\')
        for record in csv_reader:
            asset = create_asset_from_csv_record(record, args)
            if asset is not None:
                assets.append(asset)
    return assets

def create_asset_from_csv_record(record, args):
    asset = { }
    asset['id'] = record['Asset Id'].strip()
    asset['name'] = record['Asset Name'].strip()
    asset['type'] = record['Asset Type'].strip()
    asset['owner'] = record['Owner'].strip()
    asset['tags'] = get_mv_field(record['Tags'])
    asset['products'] = get_mv_field(record['Products'])
    asset['patches'] = get_mv_field(record['Patches'])

    if validate_update_csv_asset(asset, args) == False:
        return None

    return asset

def get_mv_field(mv_field_value):
    mv_field_values = mv_field_value.split(';')
    ret_val = []
    for item in mv_field_values:
        item = item.strip()
        if item == '':
            continue
        ret_val.append(item)
    return ret_val

def validate_update_csv_asset(asset, args):
    global all_asset_types
    if asset['id'] == '':
        return False
    if asset['name'] == '':
        return False
    if asset['type'] == '':
        asset['type'] = 'Other'
    else:
        if all_asset_types is None:
            url = "https://" + args.instance + "/api/v1/assets/types"
            auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
            response = utils.requests_get(url + auth_data)
            if response is not None and response.status_code != 200:
                logging.error("Unable to get valid asset types.")
                utils.tw_exit(1)
            all_asset_types = response.json()
        if asset['type'] not in all_asset_types:
            logging.warning("Skipping asset [%s] with invalid asset type [%s]", asset['name'],asset['type'])
            return False
    if asset['owner'] == '':
        asset['owner'] = args.handle
    return True

def process_json(sbom_abs_path, args):
    assets = get_assets_from_json_file(sbom_abs_path)
    return assets

def process_csv(sbom_abs_path, args):
    if args.token is None or len(args.token) == 0:
        logging.error("API token is required to validate asset types in CSV")
        utils.tw_exit(1)
    assets = get_assets_from_csv_file(sbom_abs_path, args)
    return assets
    
