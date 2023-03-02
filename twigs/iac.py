import sys
import re
import os
import shutil
import stat
import subprocess
import logging
import json
import tempfile
import traceback

from . import iac_meta

checkov_plugin = "/usr/local/bin/checkov"

sevmap = {"LOW": "1","MEDIUM": "3","HIGH": "4","CRITICAL": "5"}

def get_code_snippet(r):
    code_snippet = ''
    if r['code_block'] is None:
        return code_snippet
    for cl in r['code_block']:
        code_snippet = code_snippet + cl[1]
    return code_snippet

def get_refs(r):
    refs = [ ]
    guideline = r.get('guideline')
    if guideline is not None:
        refs.append(guideline)
    return refs

def run_iac_checks(args, path, base_path):
    findings = []
    if not os.path.isfile(checkov_plugin) or not os.access(checkov_plugin, os.X_OK):
        logging.error('IaC security checks CLI - checkov not found')
        return findings

    params = '--output json --directory ' + path
    
    cmdarr = [checkov_plugin + " " + params]
    logging.debug("Running command %s", cmdarr)
    iac_issues = None
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        iac_issues = json.loads(out)
    except subprocess.CalledProcessError as cpe:
        if cpe.returncode == 1 and len(cpe.output) > 0:
            iac_issues = json.loads(cpe.output)
        else:
            logging.error("Error running IaC security checks CLI [checkov]")
            return findings 
    logging.info("IaC security checks CLI [checkov] checks completed")

    # checkov returns list if there are multiple technologies like terraform, kubernetes
    # else it returns dict
    if type(iac_issues) is dict:
        iac_issues = [ iac_issues ]

    for iac_issue in iac_issues:
        failed_results = iac_issue['results'].get('failed_checks') if 'results' in iac_issue else None
        if failed_results is None:
            continue
        for r in failed_results:
            imeta = iac_meta.metadata.get(r['check_id'])
            finding = {}
            finding['issue_id'] = r['check_id']
            if imeta:
                finding['rating'] = sevmap[imeta['severity']]
            else:
                finding['rating'] = '3' # default rating
            finding['filename'] = r['file_path'][1:]
            if args.no_code:
                finding['code_snippet'] = ''
            else:
                finding['code_snippet'] = get_code_snippet(r)
            finding['lineno_start'] = r['file_line_range'][0] if r['file_line_range'][0] is not None else -1
            finding['lineno_end'] = r['file_line_range'][1] if r['file_line_range'][1] is not None else -1
            if imeta:
                finding['description'] = r['check_name'] + '\n' + imeta['description']
            else:
                finding['description'] = r['check_name']
            finding['resource'] = r['resource']
            finding['refs'] = get_refs(r)
            finding['type'] = 'IaC'
            findings.append(finding)

    return findings
