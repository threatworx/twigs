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

import aws
import linux
import opensource
import docker
import azure

def validate_impact_refresh_days(impact_refresh_days):
    if impact_refresh_days is not None:
        if impact_refresh_days.isdigit():
            impact_refresh_days = int(impact_refresh_days)
            if impact_refresh_days < 0 or impact_refresh_days > 365:
                logging.error("[impact_refresh_days] parameter not valid. Valid range is 0 - 365 days.")
                sys.exit(1)
        else:
            logging.error("[impact_refresh_days] parameter is not valid number.")
            sys.exit(1)

def main(args=None):
    
    if args is None:
        args = sys.argv[1:]

    logfilename = "twigs.log"
    logging_level = logging.INFO

    parser = argparse.ArgumentParser(description='ThreatWatch Information Gathering Script (twigs) to discover assets like hosts, cloud instances, containers and opensource projects')
    subparsers = parser.add_subparsers(title="modes", description="Discovery modes supported", dest="mode")
    # Required arguments
    parser.add_argument('--handle', help='The ThreatWatch registered email id/handle of the user', required=True)
    parser.add_argument('--token', help='The ThreatWatch API token of the user', required=True)
    parser.add_argument('--instance', help='The ThreatWatch instance. Defaults to ThreatWatch Cloud SaaS.', default='api.threatwatch.io')

    # Arguments required for AWS discovery
    parser_aws = subparsers.add_parser ("aws", help = "Discover AWS instances")
    parser_aws.add_argument('--aws_account', help='AWS account ID', required=True)
    parser_aws.add_argument('--aws_access_key', help='AWS access key', required=True)
    parser_aws.add_argument('--aws_secret_key', help='AWS secret key', required=True)
    parser_aws.add_argument('--aws_region', help='AWS region', required=True)
    parser_aws.add_argument('--aws_s3_bucket', help='AWS S3 inventory bucket', required=True)

    # Arguments required for Azure discovery
    parser_aws = subparsers.add_parser ("azure", help = "Discover Azure instances")
    parser_aws.add_argument('--azure_tenant_id', help='Azure Tenant ID', required=True)
    parser_aws.add_argument('--azure_application_id', help='Azure Application ID', required=True)
    parser_aws.add_argument('--azure_application_key', help='Azure Application Key', required=True)
    parser_aws.add_argument('--azure_subscription', help='Azure Subscription. If not specified, then available values will be displayed', required=False)
    parser_aws.add_argument('--azure_resource_group', help='Azure Resource Group. If not specified, then available values will be displayed', required=False)
    parser_aws.add_argument('--azure_workspace', help='Azure Workspace. If not specified, then available values will be displayed', required=False)

    # Arguments required for open source discovery
    parser_opensource = subparsers.add_parser ("opensource", help = "Discover open source assets")
    parser_opensource.add_argument('--repo', help='Local path or git repo url for project', required=True)
    parser_opensource.add_argument('--type', choices=['python', 'ruby', 'nodejs', 'dotnet', 'yarn', 'pom'], help='Type of open source component to scan for', required=True)
    parser_opensource.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_opensource.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
    parser_opensource.add_argument('--impact_refresh_days', help='Request impact refresh for this asset for number of days (range 1 - 365 days)')

    # Arguments required for linux host discovery 
    parser_linux = subparsers.add_parser ("host", help = "Discover linux host assets")
    parser_linux.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_linux.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
    parser_linux.add_argument('--impact_refresh_days', help='Request impact refresh for this asset for number of days (range 1 - 365 days)')

    # Arguments required for docker discovery 
    parser_docker = subparsers.add_parser ("docker", help = "Discover docker instances")
    parser_docker.add_argument('--image', help='The docker image (repo:tag) which needs to be inspected. If tag is not given, "latest" will be assumed.', required=True)
    parser_docker.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
    parser_docker.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
    parser_docker.add_argument('--impact_refresh_days', help='Request impact refresh for this asset for number of days (range 1 - 365 days)')
    args = parser.parse_args()


    # Setup the logger
    logging.basicConfig(filename=logfilename, level=logging_level, filemode='w', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    console = logging.StreamHandler()
    console.setLevel(logging_level)
    console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
    logging.getLogger('').addHandler(console)

    logging.info('Started new run...')
    logging.debug('Arguments: %s', str(args))
    if args.mode == 'aws':
        aws.inventory(args)
    elif args.mode == 'azure':
        azure.inventory(args)
    elif args.mode == 'opensource':
        validate_impact_refresh_days(args.impact_refresh_days)
        opensource.inventory(args)
    elif args.mode == 'host':
        validate_impact_refresh_days(args.impact_refresh_days)
        linux.inventory(args)
    elif args.mode == 'docker':
        validate_impact_refresh_days(args.impact_refresh_days)
        docker.inventory(args)

    logging.info('Run completed...')

if __name__ == '__main__':
    main()
