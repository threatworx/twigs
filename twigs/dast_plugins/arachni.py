import sys
import re
import os
import shutil
import stat
import subprocess
import logging
import json
import tempfile
import hashlib
import traceback

def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

def tw_open(in_file, in_encoding):
    if sys.version_info[0] < 3:
        f = open(in_file)
    else:
        f = open(in_file, encoding=in_encoding)
    return f

def get_rating(severity):
    if severity == 'informational':
        return '1'
    if severity == 'low':
        return '3'
    if severity == 'medium':
        return '4'
    if severity == 'high':
        return '5'

def parse_arachni(outjson, args):
    logging.info("Analyzing results")
    findings = []
    f = open(outjson, 'r')
    fdict = json.loads(f.read())
    issues = fdict['issues']
    for i in issues:
        idict = {}
        idict['asset_id'] = args.assetid
        idict['twc_id'] = 'ARACHNI-' + hashlib.md5(str(i['name']).encode('utf-8')).hexdigest()
        idict['twc_title'] = i['name']
        idict['rating'] = get_rating(i['severity'])
        idict['object_id'] = i['page']['dom']['url'] 
        idict['type'] = 'DAST'
        idict['object_meta'] = ''
        idict['details'] = i['description'] 
        findings.append(idict)
    return findings

def run(args):
    arachni_base = args.pluginpath
    arachni = arachni_base + '/arachni'
    arachni_reporter = arachni_base + '/arachni_reporter'

    if not os.path.isfile(arachni) or not os.access(arachni, os.X_OK):
        logging.error('arachni CLI not found')
        sys.exit(1) 
    if not os.path.isfile(arachni_reporter) or not os.access(arachni_reporter, os.X_OK):
        logging.error('arachni CLI not found')
        sys.exit(1) 

    logging.info("Running arachni plugin. This could take a while")
    path = tempfile.mkdtemp()
    outafr = path+"/"+args.assetid+".afr"
    outjson = path+"/"+args.assetid+".json"
    rparams = " --report-save-path "+outafr
    logging.info("Using reporting options: "+rparams)
    logging.info("Please do not override the reporting options")

    params = args.args
    if params != None:
        params = " " + params + " " + rparams + " " + args.url
    else:
        params = " " + rparams + " " + args.url
    #logging.info("arachni command line: "+arachni+ " " + params)
    cmdarr = [arachni + " " + params]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError as cpe:
        logging.error("Error running arachni CLI")
        logging.debug("[arachni] command: %s", cmdarr[0])
        logging.debug("Output of [arachni]: %s", cpe.output)
        shutil.rmtree(path, onerror = on_rm_error)
        return None 
    logging.info("arachni run completed")

    reporter_cmd = arachni_reporter + " " +outafr+" "+" --report=json:outfile="+outjson
    #logging.info("arachni_reporter command line: "+reporter_cmd)
    cmdarr = [reporter_cmd]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError as cpe:
        logging.error("Error running arachni_reporter CLI")
        logging.debug("[arachni_reporter] command: %s", cmdarr[0])
        logging.debug("Output of [arachni_reporter]: %s", cpe.output)
        shutil.rmtree(path, onerror = on_rm_error)
        return None 
    logging.info("arachni_reporter run completed")

    findings = parse_arachni(outjson, args)
    shutil.rmtree(path, onerror = on_rm_error)

    return findings
