#!/usr/bin/env python
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import os
import logging
import argparse
import requests

import aws
import linux
import opensource
import docker
import azure
import servicenow

def export_assets_to_csv(assets, csv_file):
    logging.info("Exporting assets to CSV file [%s]", csv_file)
    with open(csv_file, "w") as file:
        for asset in assets:
            file.write(asset['id'])
            file.write(",")
            file.write(asset['name'])
            file.write(",")
            file.write(asset['type'])
            file.write(",")
            file.write(":OWNER:" + asset['owner'])
            if asset.get('tags') is not None:
                for tag in asset['tags']:
                    file.write(",")
                    file.write(":TAG:" + tag)
            for product in asset['products']:
                file.write(",")
                file.write(product)
            file.write("\n")
    logging.info("Successfully exported assets to CSV file!")

def push_asset_to_TW(asset, args):
    asset_url = "https://" + args.instance + "/api/v2/assets/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    asset_id = asset['id']

    resp = requests.get(asset_url + asset_id + "/" + auth_data)
    if resp.status_code != 200:
        # Asset does not exist so create one with POST
        resp = requests.post(asset_url + auth_data, json=asset)
        if resp.status_code == 200:
            logging.info("Successfully created new asset [%s]", asset_id)
            logging.info("Response content: %s", resp.content)
            return asset_id
        else:
            logging.error("Failed to create new asset [%s]", asset_id)
            logging.error("Response details: %s", resp.content)
            return None
    else:
        # asset exists so update it with PUT
        resp = requests.put(asset_url + asset_id + "/" + auth_data, json=asset)
        if resp.status_code == 200:
            logging.info("Successfully updated asset [%s]", asset_id)
            logging.info("Response content: %s", resp.content)
            return asset_id
        else:
            logging.error("Failed to update existing asset [%s]", asset_id)
            logging.error("Response details: %s", resp.content)
            return None

def push_assets_to_TW(assets, args):
    asset_id_list = []
    for asset in assets:
        asset_id = push_asset_to_TW(asset, args)
        if asset_id is not None:
            asset_id_list.append(asset_id)

    if args.scan_type is not None:
        if len(asset_id_list) == 0:
            logging.info("No assets to scan...")
            return 
        logging.info("Starting impact refresh for assets %s", str(asset_id_list))
        scan_api_url = "https://" + args.instance + "/api/v1/scans/?handle=" + args.handle + "&token=" + args.token + "&format=json"
        scan_payload = { }
        scan_payload['scan_type'] = args.scan_type
        scan_payload['assets'] = asset_id_list
        resp = requests.post(scan_api_url, json=scan_payload)
        if resp.status_code == 200:
            logging.info("Started impact refresh...")
        else:
            logging.error("Failed to start impact refresh")
            logging.error("Response details: %s", resp.content)

def main(args=None):
    
    if args is None:
        args = sys.argv[1:]

    logfilename = "twigs.log"
    logging_level = logging.INFO

    parser = argparse.ArgumentParser(description='ThreatWatch Information Gathering Script (twigs) to discover assets like hosts, cloud instances, containers and opensource projects')
    subparsers = parser.add_subparsers(title="modes", description="Discovery modes supported", dest="mode")
    # Required arguments
    parser.add_argument('--handle', help='The ThreatWatch registered email id/handle of the user', required=True)
    parser.add_argument('--token', help='The ThreatWatch API token of the user', required=False)
    parser.add_argument('--instance', help='The ThreatWatch instance. Defaults to ThreatWatch Cloud SaaS.', default='api.threatwatch.io')
    parser.add_argument('--csv_file', help='Specify name of the CSV file to hold the exported asset information. Defaults to out.csv', default='out.csv')
    parser.add_argument('--scan_type', choices=["quick", "regular", "full"], help='Perform impact refresh for asset(s)')

    # Arguments required for AWS discovery
    parser_aws = subparsers.add_parser ("aws", help = "Discover AWS instances")
    parser_aws.add_argument('--aws_account', help='AWS account ID', required=True)
    parser_aws.add_argument('--aws_access_key', help='AWS access key', required=True)
    parser_aws.add_argument('--aws_secret_key', help='AWS secret key', required=True)
    parser_aws.add_argument('--aws_region', help='AWS region', required=True)
    parser_aws.add_argument('--aws_s3_bucket', help='AWS S3 inventory bucket', required=True)
    parser_aws.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording AWS specific information (like AWS Account ID, etc.) as asset tags', required=False)

    # Arguments required for Azure discovery
    parser_azure = subparsers.add_parser ("azure", help = "Discover Azure instances")
    parser_azure.add_argument('--azure_tenant_id', help='Azure Tenant ID', required=True)
    parser_azure.add_argument('--azure_application_id', help='Azure Application ID', required=True)
    parser_azure.add_argument('--azure_application_key', help='Azure Application Key', required=True)
    parser_azure.add_argument('--azure_subscription', help='Azure Subscription. If not specified, then available values will be displayed', required=False)
    parser_azure.add_argument('--azure_resource_group', help='Azure Resource Group. If not specified, then available values will be displayed', required=False)
    parser_azure.add_argument('--azure_workspace', help='Azure Workspace. If not specified, then available values will be displayed', required=False)
    parser_azure.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording Azure specific information (like Azure Tenant ID, etc.) as asset tags', required=False)

    # Arguments required for ServiceNow discovery
    parser_snow = subparsers.add_parser ("servicenow", help = "Discover inventory from ServiceNow instance")
    parser_snow.add_argument('--snow_user', help='User name of ServiceNow account', required=True)
    parser_snow.add_argument('--snow_user_pwd', help='User password of ServiceNow account', required=True)
    parser_snow.add_argument('--snow_instance', help='ServiceNow Instance name', required=True)
    parser_snow.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording ServiceNow specific information (like ServiceNow instance name, etc.) as asset tags', required=False)

    # Arguments required for open source discovery
    parser_opensource = subparsers.add_parser ("opensource", help = "Discover open source assets")
    parser_opensource.add_argument('--repo', help='Local path or git repo url for project', required=True)
    parser_opensource.add_argument('--type', choices=opensource.SUPPORTED_TYPES, help='Type of open source component to scan for. Defaults to all supported types if not specified', required=False)
    parser_opensource.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_opensource.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')

    # Arguments required for linux host discovery 
    parser_linux = subparsers.add_parser ("host", help = "Discover linux host assets")
    parser_linux.add_argument('--remote_hosts_csv', help='CSV file containing details of remote hosts. CSV file column header [1st row] should be: hostname,userlogin,userpwd,privatekey,assetid,assetname. Note "hostname" column can contain hostname, IP address, CIDR range.')
    parser_linux.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_linux.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')

    # Arguments required for docker discovery 
    parser_docker = subparsers.add_parser ("docker", help = "Discover docker instances")
    parser_docker.add_argument('--image', help='The docker image (repo:tag) which needs to be inspected. If tag is not given, "latest" will be assumed.', required=True)
    parser_docker.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_docker.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
    args = parser.parse_args()


    # Setup the logger
    logging.basicConfig(filename=logfilename, level=logging_level, filemode='w', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    console = logging.StreamHandler()
    console.setLevel(logging_level)
    console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
    logging.getLogger('').addHandler(console)

    logging.info('Started new run...')
    logging.debug('Arguments: %s', str(args))

    if args.token is None or len(args.token) == 0:
        logging.debug('[token] argument is not specified. Asset information will be exported to CSV file [%s]', args.csv_file)

    assets = []
    if args.mode == 'aws':
        assets = aws.get_inventory(args)
    elif args.mode == 'azure':
        assets = azure.get_inventory(args)
    elif args.mode == 'servicenow':
        assets = servicenow.get_inventory(args)
    elif args.mode == 'opensource':
        assets = opensource.get_inventory(args)
    elif args.mode == 'host':
        assets = linux.get_inventory(args)
    elif args.mode == 'docker':
        assets = docker.get_inventory(args)

    export_assets_to_csv(assets, args.csv_file)

    if args.token is not None and len(args.token) > 0:
        push_assets_to_TW(assets, args)

    logging.info('Run completed...')

if __name__ == '__main__':
    main()
