import sys
sys.path.append('../twigs')
import os
import subprocess
import tempfile
import shutil
import hashlib
import tarfile
import logging
import json
import traceback

from twigs import utils

# rdict contains recommendations from recommendations.json
rdict = None

# Note this error routine assumes that the file was read-only and hence could not be deleted
def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

def process_line(line, rating, asset_id, config_issues_dict, config_issues):
    global rdict
    line_fields = line.split('|')
    category = line_fields[0]
    category_url = "https://cisofy.com/lynis/controls/" + category
    description = line_fields[1]
    suggestion = line_fields[2] if line_fields[2] != '-' else ''
    extra = line_fields[3] if line_fields[3] != '-' else ''
    twc_id_str = category + '-' + description
    twc_id_hash = hashlib.md5(twc_id_str.encode())
    twc_id_hash = twc_id_hash.hexdigest()
    existing_ci  = config_issues_dict.get(twc_id_hash)
    if existing_ci is not None:
        # update details in existing issue
        if len(suggestion) > 0:
            existing_ci['details'] = existing_ci['details'] + '<br/>' + suggestion
        return

    # create new issue
    config_issue = { }
    config_issue['twc_id'] = twc_id_hash
    config_issue['asset_id'] = asset_id
    config_issue['twc_title'] = "[%s] %s" % (category, description)
    if rdict.get(category):
        details = rdict[category]
    else:
        details = 'For additional information refer:\n' + category_url + '<br/>'
    if len(suggestion) > 0:
        details = details + '<b>Finding / Recommendation:</b><br/>' + suggestion
    config_issue['details'] = details
    config_issue['type'] = 'Host Benchmark'
    config_issue['rating'] = rating
    config_issue['object_id'] = ''
    config_issue['object_meta'] = ''
    config_issues_dict[twc_id_hash] = config_issue
    config_issues.append(config_issue)

def process_report(report_file, asset_id):
    bundled_recommendations_path = os.path.dirname(os.path.realpath(__file__)) + os.sep + 'recommendations.json'
    rf = open(bundled_recommendations_path, 'r')
    rdata = rf.read()
    rf.close()
    global rdict
    rdict = json.loads(rdata)
    config_issues = []
    config_issues_dict = { }
    with open(report_file, 'r') as rpt_file:
        while True:
            line = rpt_file.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith('warning[]='):
                process_line(line[10:], '4', asset_id, config_issues_dict, config_issues)
            elif line.startswith('suggestion[]='):
                process_line(line[13:], '2', asset_id, config_issues_dict, config_issues)
    return config_issues

def run_host_benchmark(host, asset_id, args):
    config_issues = []
    try:
        logging.info("Running host benchmark for [%s]. This may take some time...", host['hostname'])
        args_encoding = args.encoding if args is not None else 'latin-1'
        bundled_tar_path = os.path.dirname(os.path.realpath(__file__)) + os.sep + 'lynis-3.1.7.tar.gz'
        local_temp_dir = tempfile.mkdtemp()

        # Untar tar to tmp directory
        with tarfile.open(bundled_tar_path, 'r', format=tarfile.PAX_FORMAT) as tf:
            tf.extractall(path=local_temp_dir)

        # Create local tmp directory
        if host['remote'] == False:
            extract_tar_path = local_temp_dir
        else:
            # SSH and create tmp directory on remote box
            cmdarr = ['mktemp -d']
            remote_temp_dir = utils.run_cmd_on_host(args, host, cmdarr)

            remote_temp_dir = remote_temp_dir.strip()
            # SCP tar contents to remote box
            utils.scp_put_file(host, local_temp_dir + os.sep + 'lynis', remote_temp_dir)
            extract_tar_path = remote_temp_dir

        # Run host benchmark tool
        cmdarr = ['cd ' + extract_tar_path + os.sep + 'lynis && chmod 640 include/* && ./lynis audit system --quiet --logfile ../tw_lynis.log --report-file ../tw_lynis_report.dat && cd -']
        utils.run_cmd_on_host(args, host, cmdarr)

        if host['remote'] == True:
            # SCP report back to local tmp directory
            utils.scp_get_file(host, remote_temp_dir + os.sep + 'tw_lynis_report.dat', local_temp_dir)
            # Remove remote tmp directory
            cmdarr = ['rm -rf '+ remote_temp_dir]
            utils.run_cmd_on_host(args, host, cmdarr)

        # Process report from local tmp directory
        config_issues = process_report(local_temp_dir + os.sep + 'tw_lynis_report.dat', asset_id)

        # Remove local tmp directory
        shutil.rmtree(local_temp_dir, onerror = on_rm_error)

        logging.info("Completed host benchmark for [%s]", host['hostname'])

    except Exception as e:
        logging.error("Something went wrong while running host benchmarks")
        st = traceback.format_exc()
        logging.error("Exception trace details: %s", st)
    except:
        logging.error("Unknown error running remote discovery for asset [%s], host [%s]: [%s]", asset_id, host['hostname'], sys.exc_info()[1])

    return config_issues

"""
# Test local host benchmarks
local_host = { 'remote': False, 'hostname':'127.0.0.1'}
ci = run_host_benchmark(local_host, "test_asset", None)
print(ci)
"""

"""
# Test remote host benchmarks
remote_host = {
    'remote': True,
    'hostname':'hostname.somecompany.io',
    'userlogin':'userlogin',
    'userpwd':'userpwd',
    'privatekey': '',
    'assetname': 'dummy'
}
ci = run_host_benchmark(remote_host, "test_asset", None)
print(ci)
"""
