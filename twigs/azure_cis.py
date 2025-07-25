import sys
import os
import logging
import csv
from .azure_cis_tool import azure_cis as azure_cis_tool
from . import az_cis_metadata
from . import utils


def get_issues_from_csv_file(config_issues_csv, assetid):
    findings = []
    with open(config_issues_csv, "r") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            if 'Failed' not in row['RESULT']:
                continue
            issue = { }
            check_id = row['CHECK'].split()[0]
            issue['twc_id'] = 'cis-azure-bench-check-'+check_id
            issue['asset_id'] = assetid
            issue['twc_title'] = row['CHECK']
            az_md = az_cis_metadata.az_cis_metadata[check_id]
            details = "Category: " + az_md['category'] + "\n\n"
            details = details + "Description: " + az_md['description'] + "\n\n"
            details = details + "Rationale: " + az_md['rationale'] + "\n\n"
            if len(row['DETAILS']) > 0:
                details = details + "Findings:\n" + row['DETAILS'] + "\n\n"
            if len(az_md['remediation']) > 0:
                details = details + "Remediation: " + az_md['remediation'] + "\n\n"
            details = details + "Recommendation: " + az_md['recommendation'] + "\n\n"
            issue['details'] = details
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
