import sys
import subprocess
import os
import tempfile
import shutil
import logging
import csv

from . import cis_report_data
from .. import utils as twutils

def process_oci_cis_reports(report_dir):
    with open(report_dir + os.path.sep + "cis_summary_report.csv", "r") as fd:
        report_csv = csv.DictReader(fd)
        master_crd = cis_report_data.cis_report_data
        config_issues = []
        for row in report_csv:
            if row['Compliant'] == 'Yes' or row['Compliant'] == 'N/A':
                continue 
            crd = master_crd[row['Recommendation #']]
            issue = { }
            issue['twc_id'] = 'cis-oci-bench-check-' + row['Recommendation #']
            issue['twc_title'] = row['Recommendation #'] + ' [Level ' + row['Level'] + '] ' + row['Title']
            details = "Category: " + row['Section'] + "\n\n"
            details = details + "Description: " + crd['Description'] + "\n\n"
            details = details + "Rationale: " + crd['Rationale'] + "\n\n"
            if len(crd['Impact']) > 0:
                details = details + "Impact: " + crd['Impact'] + "\n\n"
            resources = []
            if (os.path.isfile(report_dir + os.path.sep + row['Filename'])):
                    with open(report_dir + os.path.sep + row['Filename'], 'r') as details_fd:
                        details_csv = csv.DictReader(details_fd)
                        for detail in details_csv:
                            resource_id = detail.get('id')
                            if resource_id is not None:
                                resources.append(resource_id)
            if len(resources) > 0:
                resources_str = "\n".join(resources)
                details = details + "Non-compliant resource(s):\n" + resources_str + "\n\n"
            details = details + "Remediation: " + row['Remediation'] + "\n\n"
            if len(crd['Recommendation']) > 0:
                details = details + "Recommendation: " + crd['Recommendation'] + "\n\n"

            issue['details'] = details
            issue['rating'] = '4' if row['Level' ] == "2" else '3'
            issue['object_id'] = ''
            issue['object_meta'] = ''
            issue['type'] = 'OCI CIS'
            config_issues.append(issue)
        return config_issues

def process_oci_obp_reports(report_dir):
    with open(report_dir + os.path.sep + "obp_OBP_Summary.csv", "r") as fd:
        report_csv = csv.DictReader(fd)
        config_issues = []
        for row in report_csv:
            if row['Compliant'] == 'Yes' or row['Compliant'] == 'N/A':
                continue 
            issue = { }
            issue['twc_id'] = row['Recommendation']
            issue['twc_title'] = row['Recommendation'].replace('_',' ')
            details = "Category: " + row['Recommendation'].replace('_', ' ') + "\n\n"
            resources = []
            findings_csv = report_dir + os.path.sep + "obp_" + row['Recommendation'] + "_Findings.csv"
            if (os.path.isfile(findings_csv)):
                    with open(findings_csv, 'r') as details_fd:
                        details_csv = csv.DictReader(details_fd)
                        for detail in details_csv:
                            resource_id = detail.get('id')
                            if resource_id is not None:
                                resources.append(resource_id)
            if len(resources) > 0:
                resources_str = "\n".join(resources)
                details = details + "Non-compliant resource(s):\n" + resources_str + "\n\n"

            details = details + "Documentation: " + row['Documentation'] + "\n\n"
            issue['details'] = details
            issue['rating'] = '2'
            issue['object_id'] = ''
            issue['object_meta'] = ''
            issue['type'] = 'OCI BP'
            config_issues.append(issue)
        return config_issues

def log_errors(report_dir):
    if not os.path.isfile(report_dir + os.path.sep + "error_report.csv"):
        return
    with open(report_dir + os.path.sep + "error_report.csv", "r") as fd:
        report_csv = csv.DictReader(fd)
        rows = list(report_csv)
        if len(rows) > 0:
            logging.warning("Observations while running tests:")
            count= 1
            for row in rows:
                logging.warning("%s. %s", str(count), row['error'])
                count += 1

def run_tests(args):

    if args.no_obp:
        logging.info("Running CIS benchmarks for Oracle Cloud Infrastructure. This may take some time.")
    else:
        logging.info("Running CIS benchmarks and Oracle Best Practice checks for Oracle Cloud Infrastructure. This may take some time.")
    config_issues = []
    python_cmd = sys.executable  #os.path.basename(sys.argv[0])
    logging.debug(python_cmd)
    oci_cis_script = os.path.dirname(os.path.realpath(__file__)) + "/cis_reports.py"
    tmp_rpt_dir = tempfile.mkdtemp("", "tw_oci_cis_rpt_", tempfile.gettempdir() + os.path.sep) 
    cmd = python_cmd + " " + oci_cis_script + " -c '" + args.config_file + "' -t '" + args.config_profile + "' --report-directory " + tmp_rpt_dir + " --level 2 --print-to-screen False"
    if not args.no_obp:
        cmd =  cmd + " --obp"
    if args.verbosity < 2:
        cmd = cmd + ' 2>&1 >/dev/null'
    logging.debug("OCI CIS command: %s", cmd)
    try:
        proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        exit_code = proc.wait()
    except subprocess.CalledProcessError:
        logging.error("Error running OCI CIS bench script")
        twutils.tw_exit(1)

    if exit_code == 0:
        config_issues = process_oci_cis_reports(tmp_rpt_dir)
        if not args.no_obp:
            config_issues.extend(process_oci_obp_reports(tmp_rpt_dir))
        log_errors(tmp_rpt_dir)
        #print(config_issues)
    else:
        logging.error("Error running OCI CIS benchmarks")
        logging.debug("OCI CIS benchmarks returned exit code [%s]", str(exit_code))
        shutil.rmtree(tmp_rpt_dir)
        twutils.tw_exit(1)

    shutil.rmtree(tmp_rpt_dir)

    return config_issues

