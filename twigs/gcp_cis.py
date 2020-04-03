import sys
import os
import gcp_cis_tool.gcp_cis as gcp_cis_tool

def run_gcp_cis_bench(args):
    asset = { }
    asset['id'] = args.assetid
    asset['name'] = args.assetname if args.assetname else asset['id']
    asset['type'] = 'Google Cloud Platform'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['tags'] = ['Google Cloud Platform', 'CIS']
    asset['config_issues'] = gcp_cis_tool.run_tests()
    args.no_scan = True
    return asset

def get_inventory(args):
    asset = run_gcp_cis_bench(args)
    return [ asset ]
