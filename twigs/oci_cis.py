import sys
import os
import logging
from .oci_cis_tool import oci_cis as oci_cis_tool
from . import utils

def run_oci_cis_bench(args):
    asset = { }
    if args.assetid.strip() == "":
        logging.error("[assetid] cannot be empty")
        utils.tw_exit(1)
    asset['id'] = args.assetid
    asset['name'] = args.assetname if args.assetname and args.assetname.strip() != "" else asset['id']
    asset['type'] = 'Oracle Cloud Infrastructure'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['tags'] = ['Oracle Cloud Infrastructure', 'CIS']
    if not args.no_obp:
        asset['tags'].append('OracleBestPractices')
    asset['config_issues'] = oci_cis_tool.run_tests(args)
    args.no_scan = True
    return asset

def get_inventory(args):
    asset = run_oci_cis_bench(args)
    return [ asset ]
