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
    if args.assetid.strip() == "":
        logging.error("[assetid] cannot be empty")
        sys.exit(1)
    asset_id = args.assetid
    asset_name = asset_id if args.assetname is None or args.assetname.strip() == "" else args.assetname
    if args.prowler_home is None:
        args.prowler_home = os.environ.get('PROWLER_HOME')
        if args.prowler_home is None:
            args.prowler_home = '.' # default to current directory
    prowler_path = args.prowler_home + PROWLER_SH
    if not os.path.isfile(prowler_path) or not os.access(prowler_path, os.X_OK):
        logging.error('AWS CIS Bench script not found')
        sys.exit(1)

    logging.info("Running AWS CIS Bench script [%s]", prowler_path)
    logging.info("This may take some time...")
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
            if row['CHECK_RESULT'] != 'FAIL':
                continue
            if prev is None or prev != row['TITLE_ID']:
                issue = { }
                issue['twc_id']  = 'cis-aws-bench-check-'+row['TITLE_ID']
                issue['asset_id'] = asset_id
                issue['twc_title'] = row['ITEM_LEVEL'] + ' ' + row['TITLE_TEXT']
                issue['details'] = row['CHECK_RESULT_EXTENDED']
                issue['type'] = 'AWS CIS'
                if row['CHECK_SEVERITY'] == 'Low':
                    issue['rating'] = '1'
                elif row['CHECK_SEVERITY'] == 'Medium':
                    issue['rating'] = '2'
                elif row['CHECK_SEVERITY'] == 'High':
                    issue['rating'] = '4'
                elif row['CHECK_SEVERITY'] == 'Critical':
                    issue['rating'] = '5'
                issue['object_id'] = ''
                issue['object_meta'] = ''
                prev = row['TITLE_ID']
                findings.append(issue)
            else:
                findings[-1]['details'] = findings[-1]['details'] + '\n' + row['CHECK_RESULT_EXTENDED']
    return findings

def get_inventory(args):
    asset = run_cis_aws_bench(args)
    return [ asset ]

