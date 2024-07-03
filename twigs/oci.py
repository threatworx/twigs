import sys
import os
import logging
import re
from . import oci_utils

def get_asset_type(os_family):
    # Oracle OS Mgmt Hub only supports Oracle Linux and Windows 
    if os_family.startswith('ORACLE_LINUX_'):
        return 'Oracle Linux'
    elif os_family.startswith('WINDOWS_'):
        return 'Windows'

def get_os_release(os_family):
    return os_family.replace('_', ' ').title()

def get_inventory(args):
    assets = []
    oci_utils.set_encoding(args.encoding)

    compartment_name_dict = oci_utils.get_compartment_name_dict(args)
    compartments = oci_utils.get_compartments(args)
    for compartment in compartments:
        logging.info("Processing compartment [%s]", compartment_name_dict[compartment])
        instances_json = oci_utils.run_oci_cmd("os-management-hub managed-instance list --compartment-id '%s' --all" % compartment, args)
        instances_json = instances_json['data']['items']
        logging.info("Found [%s] compute instances in inventory", len(instances_json))
        for instance in instances_json:
            asset_dict = {}
            asset_dict['id'] = instance['id']
            asset_dict['name'] = instance['display-name']
            asset_dict['type'] = get_asset_type(instance['os-family'])
            asset_dict['owner'] = args.handle
            os_release = get_os_release(instance['os-family'])
            asset_tags = [ "OS_RELEASE:"+os_release, "SOURCE:OCI" ]
            if args.enable_tracking_tags:
                asset_tags.append("COMPARTMENT:" + compartment_name_dict[instance['compartment-id']])
            asset_dict['tags'] = asset_tags
            products = []
            if asset_dict['type'] == "Oracle Linux":
                packages_json = oci_utils.run_oci_cmd("os-management-hub managed-instance list-installed-packages --managed-instance-id '%s' --all" % instance['id'], args)
                packages_json = packages_json['data']['items']
                for package in packages_json:
                    pname = "%s %s.%s" % (package['name'], package['version'], package['architecture'].lower())
                    products.append(pname)
            if asset_dict['type'] == "Windows":
                # OCI OS Mgmt Hub does not provide installed products for Windows OS

                updates_json = oci_utils.run_oci_cmd("os-management-hub managed-instance list-installed-windows-updates --managed-instance-id '%s' --all" % instance['id'], args)
                updates_json = updates_json['data']['items']
                patches = []
                for update in updates_json:
                    kb_nos = re.findall(r'KB[0-9]+', update['name'])
                    if len(kb_nos) == 0:
                        continue
                    patch_dict = {
                            'url': '',
                            'id': kb_nos[0],
                            'product': '',
                            'description': update['name']
                            }
                    patches.append(patch_dict)
                asset_dict['patches'] = patches
            asset_dict['products'] = products
            assets.append(asset_dict)
    logging.info("Completed inventory collection...")
    return assets

