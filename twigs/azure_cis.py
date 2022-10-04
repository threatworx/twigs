import sys
import os
import logging
import csv
from .azure_cis_tool import azure_cis as azure_cis_tool
from . import utils

def get_issues_from_csv_file(config_issues_csv, assetid):
    findings = []
    with open(config_issues_csv, "r") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            if 'Failed' not in row['RESULT']:
                continue
            issue = { }
            issue['twc_id'] = 'cis-azure-bench-check-'+row['CHECK'].split()[0]
            issue['asset_id'] = assetid
            issue['twc_title'] = row['CHECK']
            issue['details'] = row['DETAILS']
            issue['type'] = 'Azure CIS'
            issue['rating'] = '4'
            issue['object_id'] = row['SUBSCRIPTION']
            issue['object_meta'] = ''
            findings.append(issue)
    os.remove(config_issues_csv)
    return findings

def run_azure_cis_bench(args):
    if args.assetid.strip() == "":
        logging.error("[assetid] cannot be empty")
        utils.tw_exit(1)
    config_issues_csv = azure_cis_tool.run_tests()
    if config_issues_csv is None:
        utils.tw_exit(1)
    asset = { }
    asset['id'] = args.assetid
    asset['name'] = args.assetname if args.assetname and args.assetname.strip() != "" else asset['id']
    asset['type'] = 'Azure'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['tags'] = ['Azure', 'CIS']
    asset['config_issues'] = get_issues_from_csv_file(config_issues_csv, asset['id'])
    args.no_scan = True
    return asset

def get_inventory(args):
    asset = run_azure_cis_bench(args)
    return [ asset ]
