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
import repo
import docker
import azure
import servicenow
import inv_file
import fingerprint
from __init__ import __version__

def export_assets_to_csv(assets, csv_file):
    logging.info("Exporting assets to CSV file [%s]", csv_file)
    with open(csv_file, "w") as fd:
        for asset in assets:
            fd.write(asset['id'])
            fd.write(",")
            fd.write(asset['name'])
            fd.write(",")
            fd.write(asset['type'])
            fd.write(",")
            fd.write(":OWNER:" + asset['owner'])
            if asset.get('tags') is not None:
                for tag in asset['tags']:
                    fd.write(",")
                    fd.write(":TAG:" + tag)
            for product in asset['products']:
                fd.write(",")
                fd.write(product)
            fd.write("\n")
    logging.info("Successfully exported assets to CSV file!")

def push_asset_to_TW(asset, args):
    asset_url = "https://" + args.instance + "/api/v2/assets/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    if args.email_report:
        auth_data = auth_data + "&esr=true" # email secrets report (esr)
    asset_id = asset['id']

    resp = requests.get(asset_url + asset_id + "/" + auth_data)
    if resp.status_code != 200:
        logging.info("Creating new asset [%s]", asset_id)
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
        logging.info("Updating asset [%s]", asset_id)
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

    if args.no_scan is not True:
        if len(asset_id_list) == 0:
            logging.info("No assets to scan...")
            return 
        # Start VA
        logging.info("Starting impact refresh for assets %s", str(asset_id_list))
        scan_api_url = "https://" + args.instance + "/api/v1/scans/?handle=" + args.handle + "&token=" + args.token + "&format=json"
        scan_payload = { }
        scan_payload['scan_type'] = 'full' 
        scan_payload['assets'] = asset_id_list
        # if args.purge_assets:
        #    scan_payload['mode'] = 'email-purge'
        if args.email_report:
            scan_payload['mode'] = 'email'
        resp = requests.post(scan_api_url, json=scan_payload)
        if resp.status_code == 200:
            logging.info("Started impact refresh...")
        else:
            logging.error("Failed to start impact refresh")
            logging.error("Response details: %s", resp.content)
        if args.mode == "repo":
            # Start license compliance assessment
            logging.info("Starting license compliance assessment for assets %s", str(asset_id_list))
            scan_payload['license_scan'] = True
            scan_payload.pop('scan_type', None)
            resp = requests.post(scan_api_url, json=scan_payload)
            if resp.status_code == 200:
                logging.info("Started license compliance assessment...")
            else:
                logging.error("Failed to start license compliance assessment")
                logging.error("Response details: %s", resp.content)

def main(args=None):
    
    if args is None:
        args = sys.argv[1:]

    logfilename = "twigs.log"
    logging_level = logging.INFO

    parser = argparse.ArgumentParser(description='ThreatWatch Information Gathering Script (twigs) to discover assets like hosts, cloud instances, containers and project repositories')
    subparsers = parser.add_subparsers(title="modes", description="Discovery modes supported", dest="mode")
    # Required arguments
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('--handle', help='The ThreatWatch registered email id/handle of the user. Note this can set as "TW_HANDLE" environment variable', required=False)
    parser.add_argument('--token', help='The ThreatWatch API token of the user. Note this can be set as "TW_TOKEN" environment variable', required=False)
    parser.add_argument('--instance', help='The ThreatWatch instance. Note this can be set as "TW_INSTANCE" environment variable')
    parser.add_argument('--out', help='Specify name of the CSV file to hold the exported asset information. Defaults to out.csv', default='out.csv')
    parser.add_argument('--no_scan', action='store_true', help='Do not initiate a baseline assessment')
    parser.add_argument('--email_report', action='store_true', help='After impact refresh is complete email scan report to self')
    # parser.add_argument('--purge_assets', action='store_true', help='Purge the asset(s) after impact refresh is complete and scan report is emailed to self')

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

    # Arguments required for docker discovery 
    parser_docker = subparsers.add_parser ("docker", help = "Discover docker instances")
    parser_docker.add_argument('--image', help='The docker image (repo:tag) which needs to be inspected. If tag is not given, "latest" will be assumed.', required=True)
    parser_docker.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_docker.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')

    # Arguments required for File-based discovery
    parser_file = subparsers.add_parser ("file", help = "Discover inventory from file")
    parser_file.add_argument('--in', help='Absolute path to single input inventory file or a directory containing CSV files. Supported file formats are: PDF & CSV', required=True)
    parser_file.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset. Defaults to input filename if not specified. Applies only for PDF files.')
    parser_file.add_argument('--assetname', help='A name/label to be assigned to the discovered asset. Defaults to assetid is not specified. Applies only for PDF files.')
    parser_file.add_argument('--type', choices=['repo'], help='Type of asset. Defaults to repo if not specified. Applies only for PDF files.', required=False, default='repo')

    # Arguments required for Host discovery on Linux
    parser_linux = subparsers.add_parser ("host", help = "Discover linux host assets")
    parser_linux.add_argument('--remote_hosts_csv', help='CSV file containing details of remote hosts. CSV file column header [1st row] should be: hostname,userlogin,userpwd,privatekey,assetid,assetname. Note "hostname" column can contain hostname, IP address, CIDR range.')
    parser_linux.add_argument('--host_list', help='Same as the option: remote_hosts_csv. A file (currently in CSV format) containing details of remote hosts. CSV file column header [1st row] should be: hostname,userlogin,userpwd,privatekey,assetid,assetname. Note "hostname" column can contain hostname, IP address, CIDR range.')
    parser_linux.add_argument('--secure', action='store_true', help='Use this option to encrypt clear text passwords in the host list file')
    parser_linux.add_argument('--password', help='A password used to encrypt / decrypt login information from the host list file')
    parser_linux.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_linux.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')

    # Arguments required for nmap discovery
    parser_nmap = subparsers.add_parser ("nmap", help = "Fingerprint assets using nmap. Requires nmap to be installed.")
    parser_nmap.add_argument('--hosts', help='A hostname, IP address or CIDR range', required=True)

    # Arguments required for Repo discovery
    parser_repo = subparsers.add_parser ("repo", help = "Discover project repository as asset")
    parser_repo.add_argument('--repo', help='Local path or git repo url for project', required=True)
    parser_repo.add_argument('--type', choices=repo.SUPPORTED_TYPES, help='Type of open source component to scan for. Defaults to all supported types if not specified', required=False)
    parser_repo.add_argument('--level', help='Possible values {shallow, deep}. Shallow restricts discovery to 1st level dependencies only. Deep discovers dependencies at all levels. Defaults to shallow discovery if not specified', choices=['shallow','deep'], required=False, default='shalllow')
    parser_repo.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_repo.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
    # Switches related to secrets scan for repo
    parser_repo.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
    parser_repo.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
    parser_repo.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
    parser_repo.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
    parser_repo.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
    parser_repo.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
    parser_repo.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
    parser_repo.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
    parser_repo.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
    parser_repo.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWatch.')
    parser_repo.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWatch.')

    # Arguments required for ServiceNow discovery
    parser_snow = subparsers.add_parser ("servicenow", help = "Discover inventory from ServiceNow instance")
    parser_snow.add_argument('--snow_user', help='User name of ServiceNow account', required=True)
    parser_snow.add_argument('--snow_user_pwd', help='User password of ServiceNow account', required=True)
    parser_snow.add_argument('--snow_instance', help='ServiceNow Instance name', required=True)
    parser_snow.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording ServiceNow specific information (like ServiceNow instance name, etc.) as asset tags', required=False)

    args = parser.parse_args()

    # Setup the logger
    logging.basicConfig(filename=logfilename, level=logging_level, filemode='w', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    console = logging.StreamHandler()
    console.setLevel(logging_level)
    console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
    logging.getLogger('').addHandler(console)

    logging.info('Started new run...')
    logging.debug('Arguments: %s', str(args))

    if args.handle is None:
        temp = os.environ.get('TW_HANDLE')
        if temp is None:
            logging.error('Error: Missing "--handle" argument and "TW_HANDLE" environment variable is not set as well')
            return
        logging.info('Using handle specified in "TW_HANDLE" environment variable...')
        args.handle = temp

    if args.token is None:
        temp = os.environ.get('TW_TOKEN')
        if temp is not None:
            logging.info('Using token specified in "TW_TOKEN" environment variable...')
            args.token = temp

    if args.instance is None:
        temp = os.environ.get('TW_INSTANCE')
        if temp is not None:
            logging.info('Using instance specified in "TW_INSTANCE" environment variable...')
            args.instance = temp

#    if args.purge_assets == True and args.email_report == False:
#        logging.error('Purge assets option (--purge_assets) is used with Email report (--email_report)')
#        return

    if args.token is None or len(args.token) == 0:
        logging.debug('[token] argument is not specified. Asset information will be exported to CSV file [%s]', args.out)

    assets = []
    if args.mode == 'aws':
        assets = aws.get_inventory(args)
    elif args.mode == 'azure':
        assets = azure.get_inventory(args)
    elif args.mode == 'servicenow':
        assets = servicenow.get_inventory(args)
    elif args.mode == 'repo':
        assets = repo.get_inventory(args)
    elif args.mode == 'host':
        assets = linux.get_inventory(args)
    elif args.mode == 'nmap':
        assets = fingerprint.get_inventory(args)
    elif args.mode == 'docker':
        assets = docker.get_inventory(args)
    elif args.mode == 'file':
        assets = inv_file.get_inventory(args)

    if args.mode != 'host' or args.secure == False:
        if assets is None or len(assets) == 0:
            logging.info("No assets found!")
        else:
            export_assets_to_csv(assets, args.out)
            if args.token is not None and len(args.token) > 0:
                push_assets_to_TW(assets, args)

    logging.info('Run completed...')

if __name__ == '__main__':
    main()
