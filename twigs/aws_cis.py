import sys
import os
import logging
import tempfile
import csv
import subprocess
import json
import uuid

from . import utils

# Prowler is used for AWS benchmark tests and can be found here:
# https://github.com/toniblyx/prowler

def run_cis_aws_bench(args, extra_checks=False):
    PROWLER_SH = '/prowler'
    if args.assetid.strip() == "":
        logging.error("[assetid] cannot be empty")
        utils.tw_exit(1)
    asset_id = args.assetid
    asset_name = asset_id if args.assetname is None or args.assetname.strip() == "" else args.assetname
    if args.prowler_home is None:
        args.prowler_home = os.environ.get('PROWLER_HOME')
        if args.prowler_home is None:
            args.prowler_home = '.' # default to current directory
    prowler_path = args.prowler_home + PROWLER_SH
    if not os.path.isfile(prowler_path) or not os.access(prowler_path, os.X_OK):
        logging.error('AWS Bench script not found')
        utils.tw_exit(1)

    logging.info("Running AWS Bench script [%s]", prowler_path)
    logging.info("This may take some time...")
    outfile = uuid.uuid4().hex
    csv_file_path = tempfile.gettempdir() + os.path.sep + outfile + '.csv' 
    if os.path.isfile(csv_file_path):
        os.remove(csv_file_path)
    cwd = os.getcwd()
    os.chdir(os.path.dirname(prowler_path))
    cmd = 'AWS_ACCESS_KEY_ID=' + args.aws_access_key + ' AWS_SECRET_ACCESS_KEY=' + args.aws_secret_key
    if extra_checks:
        cmd = cmd + ' ' + prowler_path + ' -b -q -g extras -M csv -o ' + tempfile.gettempdir()
    else:
        cmd = cmd + ' ' + prowler_path + ' -b -q -g cislevel2 -M csv -o ' + tempfile.gettempdir()
    cmd = cmd + ' -F ' + outfile
    #cmd = cmd + ' -F ' + outfile + ' 2>&1 >/dev/null'
    if args.verbosity < 2:
        cmd = cmd + ' 2>&1 >/dev/null'
    logging.debug("AWS checks command: %s",cmd)
    try:
        proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        exit_code = proc.wait()
    except subprocess.CalledProcessError:
        logging.error("Error running AWS bench script")
        utils.tw_exit(1)

    os.chdir(cwd) 
    asset = { }
    asset['id'] = asset_id
    asset['name'] = asset_name
    asset['type'] = 'AWS'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['config_issues'] = get_issues_from_csv_file(csv_file_path, asset_id, args.encoding, extra_checks)
    asset['tags'] = ['AWS']
    if extra_checks:
        asset['tags'].append('Audit')
    else:
        asset['tags'].append('CIS')
    os.remove(csv_file_path)
    # disable scan
    args.no_scan = True
    return asset

def get_issues_from_csv_file(csv_file_path, asset_id, encoding, extra_checks=False):
    findings = []
    prev = None
    csv_file = utils.tw_open(csv_file_path, encoding, "r")
    csv_reader = csv.DictReader(csv_file, quoting=csv.QUOTE_NONE, escapechar='\\')
    for row in csv_reader:
        if row['CHECK_RESULT'] != 'FAIL':
            continue
        if prev is None or prev != row['TITLE_ID']:
            issue = { }
            issue['twc_id']  = 'cis-aws-bench-check-'+row['TITLE_ID']
            issue['asset_id'] = asset_id
            issue['twc_title'] = row['ITEM_LEVEL'] + ' ' + row['TITLE_TEXT']
            issue['details'] = row['CHECK_RESULT_EXTENDED'] + '\n' + row['CHECK_REMEDIATION']
            if extra_checks:
                issue['type'] = 'AWS Audit'
            else:
                issue['type'] = 'AWS CIS'
            if row['CHECK_SEVERITY'] == 'Low':
                issue['rating'] = '1'
            elif row['CHECK_SEVERITY'] == 'Medium':
                issue['rating'] = '2'
            elif row['CHECK_SEVERITY'] == 'High':
                issue['rating'] = '4'
            elif row['CHECK_SEVERITY'] == 'Critical':
                issue['rating'] = '5'
            else:
                issue['rating'] = '3'
            issue['object_id'] = row['CHECK_RESOURCE_ID'] 
            issue['object_meta'] = ''
            prev = row['TITLE_ID']
            findings.append(issue)
        else:
            findings[-1]['details'] = findings[-1]['details'] + '\n' + row['CHECK_RESULT_EXTENDED']
    return findings

def get_inventory(args, extra_checks=False):
    asset = run_cis_aws_bench(args, extra_checks)
    return [ asset ]

