import sys
import os
import subprocess
import logging
import re

from . import utils

def run_docker_bench(args):
    DBENCH = "/docker-bench-security.sh"

    asset_id = utils.get_ip() if args.assetid is None or args.assetid.strip() == "" else args.assetid
    asset_name = asset_id if args.assetname is None or args.assetname.strip() == "" else args.assetname
    os_release = utils.get_os_release(args, None)
    if os_release == None:
        logging.error('Unsupported OS type for running docker bench')
        utils.tw_exit(1)
    atype = utils.get_asset_type(os_release)

    dbench_path = args.docker_bench_home + DBENCH
    if not os.path.isfile(dbench_path) or not os.access(dbench_path, os.X_OK):
        logging.error('Docker bench script not found')
        utils.tw_exit(1)
    logging.info('Running docker bench script: '+dbench_path)
    cwd = os.getcwd()
    try:
        os.chdir(os.path.dirname(dbench_path))
        out = subprocess.check_output([dbench_path+" 2>/dev/null "], shell=True)
        out = out.decode(args.encoding)
        ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
        out = ansi_escape.sub('', out)
    except subprocess.CalledProcessError:
        logging.error("Error running docker bench script")
        return None
    logging.info("docker bench run completed")
    os.chdir(cwd)

    asset_data = {}
    asset_data['id'] = asset_id
    asset_data['name'] = asset_name
    asset_data['type'] = atype
    asset_data['owner'] = args.handle
    asset_data['products'] = []
    asset_tags = []
    asset_tags.append('OS_RELEASE:' + os_release)
    asset_tags.append('Docker')
    asset_tags.append('CIS')
    asset_tags.append('Container')
    asset_tags.append('Linux')
    asset_tags.append(atype)
    asset_data['tags'] = asset_tags

    findings = []
    details = ''
    issue = {}
    for l in out.splitlines():
        if not l.startswith('[WARN]') and not l.startswith('[NOTE]') and not l.startswith('[INFO]'):
            continue
        if l.startswith('[INFO] Checks') or l.startswith('[INFO] Score'):
            continue
        spa = l.split()
        if spa[1] != '*':
            if 'asset_id' in issue:
                if issue['rating'] == '2' and details.strip() == '':
                    details = ''
                    issue = {}
                    continue
                issue['details'] = details
                findings.append(issue)
                details = ''
                issue = {}
            check_id = spa[1].strip()
            issue['twc_id'] = 'docker-bench-check-'+check_id
            issue['asset_id'] = asset_id
            issue['twc_title'] = check_id + ' ' + l.split(check_id)[1].strip()
            if l.startswith('[WARN]'):
                rating = '4'
            elif l.startswith('[NOTE]'):
                rating = '3'
            else:
                rating = '2'
            issue['rating'] = rating 
            issue['type'] = 'Docker CIS'
            issue['object_id'] = ''
            issue['object_meta'] = ''
            details = ''
        else:
            details = details + l.split('*')[1].strip() + '\n'
    # add the final issue
    if 'asset_id' in issue:
        issue['details'] = details
        findings.append(issue)
    asset_data['config_issues'] = findings
    # disable scan
    args.no_scan = True
    return [ asset_data ]

def get_inventory(args):
    return run_docker_bench(args)
