import sys
import os
import logging
from .gcp_cis_tool import gcp_cis as gcp_cis_tool

def run_gcp_cis_bench(args):
    asset = { }
    if args.assetid.strip() == "":
        logging.error("[assetid] cannot be empty")
        sys.exit(1)
    asset['id'] = args.assetid
    asset['name'] = args.assetname if args.assetname and args.assetname.strip() != "" else asset['id']
    asset['type'] = 'Google Cloud Platform'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['tags'] = ['Google Cloud Platform', 'CIS']
    asset['config_issues'] = gcp_cis_tool.run_tests(args)
    args.no_scan = True
    return asset

def get_inventory(args):
    asset = run_gcp_cis_bench(args)
    return [ asset ]
