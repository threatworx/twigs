import sys
import os
import logging
import tempfile
import csv
import subprocess

# Prowler is used for AWS CIS benchmark tests and can be found here:
# https://github.com/toniblyx/prowler

def run_cis_aws_bench(args):
    PROWLER_SH = '/prowler'
    asset_id = args.assetid
    asset_name = asset_id if args.assetname is None else assetname
    prowler_path = args.prowler_home + PROWLER_SH
    if not os.path.isfile(prowler_path) or not os.access(prowler_path, os.X_OK):
        logging.error('AWS CIS Bench script not found')
        sys.exit(1)

    logging.info("Running AWS CIS Bench script [%s]", prowler_path)
    logging.info("This may take sometime...")
    cwd = os.getcwd()
    os.chdir(os.path.dirname(prowler_path))
    cmd = 'AWS_ACCESS_KEY_ID=' + args.aws_access_key + ' AWS_SECRET_ACCESS_KEY=' + args.aws_secret_key
    cmd = cmd + ' ' + prowler_path + ' -b -q -g cislevel2 -M csv 2>/dev/null'
    csv_file_path = tempfile.gettempdir() + os.path.sep + 'aws_cis_bench_out.csv'
    with open(csv_file_path, "w") as csv_file:
        try:
            proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=csv_file, stderr=None, close_fds=True)
            exit_code = proc.wait()
        except subprocess.CalledProcessError:
            logging.error("Error running CIS AWS bench script")
            sys.exit(1)

    os.chdir(cwd) 
    asset = { }
    asset['id'] = asset_id
    asset['name'] = asset_name
    asset['type'] = 'AWS'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['tags'] = ['AWS', 'CIS']
    asset['config_issues'] = get_issues_from_csv_file(csv_file_path, asset_id)
    os.remove(csv_file_path)
    # disable scan
    args.no_scan = True
    return asset

def get_issues_from_csv_file(csv_file_path, asset_id):
    findings = []
    prev = None
    with open(csv_file_path, "r") as csv_file:
        csv_reader = csv.DictReader(csv_file, quoting=csv.QUOTE_NONE, escapechar='\\')
        for row in csv_reader:
            if row['RESULT'] != 'FAIL':
                continue
            if prev is None or prev != row['TITLE_ID']:
                issue = { }
                issue['twc_id']  = 'cis-aws-bench-check-'+row['TITLE_ID']
                issue['asset_id'] = asset_id
                issue['twc_title'] = row['LEVEL'] + ' ' + row['TITLE_TEXT']
                issue['details'] = row['NOTES']
                if row['LEVEL'] == 'Level 1':
                    issue['rating'] = '4'
                else:
                    issue['rating'] = '5'
                issue['object_id'] = ''
                issue['object_meta'] = ''
                prev = row['TITLE_ID']
                findings.append(issue)
            else:
                findings[-1]['details'] = findings[-1]['details'] + '\n' + row['NOTES']
    return findings

def get_inventory(args):
    asset = run_cis_aws_bench(args)
    return [ asset ]

