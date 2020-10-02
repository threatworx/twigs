import sys
import platform
import os
import logging
import json
from . import utils
from .gcp_cis_tool import gcp_cis_utils

def get_deb_packages(package_list):
    plist = []
    for package in package_list:
        plist.append(package['Name'] + ' ' + package['Version'])
    return plist

def get_rpm_packages(package_list):
    plist = []
    for package in package_list:
        arch = 'noarch' if package['Arch'] == 'all' or package['Arch'] == '(none)' else package['Arch']
        plist.append(package['Name'] + ' ' + package['Version'] + '.' + arch)
    return plist

def get_installed_packages(ci_json):
    plist = []
    ip = ci_json['InstalledPackages']
    for ptype in ip.keys():
        if ptype == "deb":
            plist.extend(get_deb_packages(ip[ptype]))
        elif ptype == "rpm":
            plist.extend(get_rpm_packages(ip[ptype]))
        elif ptype in ['zypperPatches', 'gem']:
            # Skip these packages
            continue
        else:
            logging.error("Error: Compute instance [%s] has unknown package type [%s]", ci_json['SystemInformation']['LongName'], ptype)
    return plist

def is_compute_running(project, ci_name, ci_zone):
    ci_status_cmd = "compute instances --project=%s describe %s --zone=%s" % (project, ci_name, ci_zone)
    ci_json = gcp_cis_utils.run_gcloud_cmd(ci_status_cmd)
    if ci_json['status'] == 'RUNNING':
        return True
    return False

def process_compute_inventory_json(args, project_id, ci_id, ci_json):
    ci_name = ci_json['SystemInformation']['Hostname']
    asset_os = ci_json['SystemInformation']['LongName']
    logging.info("Collecting inventory for compute instance [%s] with ID [%s]", ci_name, ci_id)
    plist = get_installed_packages(ci_json)

    asset_data = {}
    asset_data['id'] = ci_id
    asset_data['name'] = project_id + '_' + ci_name
    atype = utils.get_asset_type(asset_os)
    asset_data['type'] = atype if atype is not None else 'Other'
    asset_data['owner'] = args.handle
    asset_data['products'] = plist
    asset_tags = []
    asset_tags.append('OS_RELEASE:' + asset_os)
    if atype is not None:
        asset_tags.append(atype)
    if args.enable_tracking_tags == True:
        asset_tags.append('SOURCE:GCP:'+project_id)
    else:
        asset_tags.append('SOURCE:GCP')
    asset_data['tags'] = asset_tags
    return asset_data

def get_inventory(args):
    assets = []
    gcp_cis_utils.set_encoding(args.encoding)
    compute_instances_by_project = gcp_cis_utils.get_compute_instances_with_os_inventory_by_projects()
    for project in compute_instances_by_project.keys():
        logging.info("Processing project [%s]", project)
        compute_instances_json = compute_instances_by_project[project]
        for compute_instance in compute_instances_json:
            ci_id = compute_instance['id']
            ci_name = compute_instance['name']
            ci_zone = compute_instance['zone'].split('/')[-1]

            if is_compute_running(project, ci_name, ci_zone) == False:
                # Do not refresh assets which are not running anymore
                continue

            ci_inventory_cmd = "compute instances os-inventory --project=%s describe %s --zone=%s" % (project, ci_name, ci_zone)
            ci_inventory_json = gcp_cis_utils.run_gcloud_cmd(ci_inventory_cmd)
            asset = process_compute_inventory_json(args, project, ci_id, ci_inventory_json)
            if asset is not None:
                assets.append(asset)
    logging.info("Completed inventory collection...")
    return assets

