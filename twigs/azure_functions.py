import sys
import os
import logging
import json
import tempfile
import shutil
from . import utils as lib_utils
from . import repo
from . import code_secrets as lib_code_secrets
from . import sast
from . import iac

def get_inventory(args):
    ret_assets = []
    cmd = "az functionapp list"
    out = lib_utils.run_cmd_on_host(args, None, cmd)
    fadict = json.loads(out)
    for fa in fadict:
        logging.info("Discovering Azure FunctionApp - "+fa['name'])
        faid = fa['id']
        cmd = "az functionapp deployment list-publishing-profiles --ids "+faid
        out = lib_utils.run_cmd_on_host(args, None, cmd)
        fadeploy = json.loads(out)
        for fad in fadeploy:
            basepath = None
            if fad['publishMethod'] == 'FTP':
                temp_dir = tempfile.mkdtemp()
                user = fad['userName'].split('\\')[1].replace('$','')
                passwd = fad['userPWD']
                ftpurl = fad['publishUrl']
                cmd = 'wget -m --user '+user+' --password '+passwd+' '+ftpurl+' -P '+temp_dir
                out = lib_utils.run_cmd_on_host(args, None, cmd)
                basepath = temp_dir + '/' + ftpurl.replace('ftp://','') 
                flist = [os.path.join(basepath, o) for o in os.listdir(basepath)
                    if os.path.isdir(os.path.join(basepath,o))]
                for fdir in flist:
                    fname = fdir.split('/')[-1]
                    args.assetid = fa['id'] + '-' + fname
                    args.assetname = fa['name'] + '-' + fname
                    args.repo = fdir
                    path = basepath + '/' + fname
                    logging.info("Discovering Azure Function - "+fname)
                    logging.info("Discovering code dependencies for vulnerability scan.")
                    assets = repo.discover_inventory(args, path)
                    if args.secrets_scan:
                        logging.info("Discovering secrets/sensitive information. This may take some time.")
                        secret_records = lib_code_secrets.scan_for_secrets(args, path, basepath)
                        assets[0]['secrets'] = secret_records

                    code_issues = []
                    if args.sast:
                        logging.info("Performing static analysis. This may take some time.")
                        sast_records = sast.run_sast(args, path, basepath)
                        code_issues.extend(sast_records)

                    if args.iac_checks:
                        logging.info("Identifying infrastructure as code (IaC) issues. This may take some time.")
                        iac_records = iac.run_iac_checks(args, path, basepath)
                        code_issues.extend(iac_records)

                    if len(code_issues) > 0:
                        assets[0]['sast'] = code_issues
                    assets[0]['type'] = 'Azure Function'
                    assets[0]['tags'].extend(['Azure', 'Azure Function', 'Serverless'])
                    ret_assets.extend(assets)
                shutil.rmtree(temp_dir)
    return ret_assets 
