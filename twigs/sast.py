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
import shutil

sast_plugin_default = "/usr/local/bin/opengrep"
sast_plugin = shutil.which("opengrep")
if sast_plugin is None:
    sast_plugin = sast_plugin_default

def get_rating(severity):
    if severity == 'ERROR':
        return '4'
    if severity == 'WARNING':
        return '3'
    return '1'

def get_description(result):
    desc = result['extra']['message']
    if 'fix' in result['extra']:
        desc = desc + '\n' + 'Suggested fix: '+result['extra']['fix']
    if 'metadata' in result['extra']:
        if 'cwe' in result['extra']['metadata']:
            if isinstance(result['extra']['metadata']['cwe'], list):
                desc = desc + '\n' + 'CWE: '+ ",".join(result['extra']['metadata']['cwe'])
            else:
                desc = desc + '\n' + 'CWE: '+result['extra']['metadata']['cwe']
        if 'owasp' in result['extra']['metadata']:
            owasp = result['extra']['metadata']['owasp']
            if isinstance(owasp, list):
                desc = desc + '\n' + 'OWASP: '+owasp[0]
            else:
                desc = desc + '\n' + 'OWASP: '+owasp
        if 'references' in result['extra']['metadata']:
            for ref in result['extra']['metadata']['references']:
                desc = desc + '\n' + ref
    return desc

def run_sast(args, path, base_path):
    findings = []
    if not os.access(sast_plugin, os.X_OK):
        logging.warning('SAST plugin CLI not found')
        return findings

    params = ' -q --json --config=r/all ' + base_path
    
    cmdarr = [sast_plugin+ " " + params]
    sast_issues = None
    try:
        out = subprocess.check_output(cmdarr, shell=True)
        sast_issues = json.loads(out)
    except subprocess.CalledProcessError as e:
        logging.error("Error running SAST plugin CLI [semgrep]")
        logging.debug("[semgrep] command: %s", cmdarr[0])
        logging.debug("Output of [semgrep]: %s", e.output)
        return findings 
    logging.info("SAST plugin CLI [semgrep] checks completed")

    results = sast_issues['results']
    for r in results:
        finding = {}
        finding['issue_id'] = r['check_id']
        finding['rating'] = get_rating(r['extra']['severity'])
        finding['filename'] = r['path'].replace(base_path,'')[1:]
        if args.no_code:
            finding['code_snippet'] = ''
        else:
            finding['code_snippet'] = r['extra']['lines']
        finding['lineno_start'] = r['start']['line']
        finding['lineno_end'] = r['end']['line']
        finding['description'] = get_description(r)
        finding['type'] = 'SAST'
        finding['cwe'] = ''
        finding['owasp'] = ''
        if 'metadata' in r['extra']:
            if 'cwe' in r['extra']['metadata']:
                if isinstance(r['extra']['metadata']['cwe'], list):
                    finding['cwe'] = r['extra']['metadata']['cwe'][0]
                else:
                    finding['cwe'] = r['extra']['metadata']['cwe']
            if 'owasp' in r['extra']['metadata']:
                owasp = r['extra']['metadata']['owasp']
                if isinstance(owasp, list):
                    finding['owasp'] = owasp[0]
                else:
                    finding['owasp'] = owasp
        findings.append(finding)

    return findings
