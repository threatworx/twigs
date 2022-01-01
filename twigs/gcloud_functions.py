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
    if args.projects == None or args.projects == '':
        logging.error("No projects listed")
        return ret_assets
    plist = args.projects.split(',')
    for proj in plist:
        cmd = "gsutil ls -p "+proj
        out = lib_utils.run_cmd_on_host(args, None, cmd)
        if out == None:
            logging.warn("No cloud storage urls found for "+proj)
            continue
        for gsurl in out.splitlines():
            if 'gcf-sources' not in gsurl:
                logging.warn("No Google Function storage urls found for "+proj)
                continue
            cmd = "gsutil ls -r "+gsurl.strip()
            urlls = lib_utils.run_cmd_on_host(args, None, cmd)
            furldict = {} 
            for l in urlls.splitlines():
                if not l.endswith('function-source.zip'):
                    continue
                fname = l.split('/')[3]
                if fname not in furldict:
                    furldict[fname] = l
                else:
                    efurl = furldict[fname]
                    efver = efurl.split('/')[4].split('-')[1]
                    fver = l.split('/')[4].split('-')[1]
                    if int(fver) > int(efver):
                        furldict[fname] = l
            for f in furldict:
                l = furldict[f]
                zfname = l.split('/')[5]
                fname = l.split('/')[3]
                fver = l.split('/')[4]
                fid = fname
                fguid = fname.split('-')[-5:]
                fguid = '-'.join(fguid)
                fname = fname.replace('-'+fguid,'')
                args.assetid = fid
                args.assetname = fname + ' ' + fver 
                temp_dir = tempfile.mkdtemp()
                args.repo = temp_dir 
                cmd = 'gsutil cp '+l+' '+temp_dir
                out = lib_utils.run_cmd_on_host(args, None, cmd)
                if out == None:
                    logging.error("Error running gsutil command")
                    continue
                cmd = 'cd '+temp_dir+';unzip '+zfname
                out = lib_utils.run_cmd_on_host(args, None, cmd)
                if out == None:
                    logging.error("Error running gsutil command")
                    continue
                logging.info("Discovering Google Function - "+fname+" "+fver)
                logging.debug("Storage url "+l)
                logging.info("Discovering code dependencies for vulnerability scan.")
                assets = repo.discover_inventory(args, temp_dir)
                if args.secrets_scan:
                    logging.info("Discovering secrets/sensitive information. This may take some time.")
                    secret_records = lib_code_secrets.scan_for_secrets(args, temp_dir, temp_dir)
                    assets[0]['secrets'] = secret_records

                code_issues = []
                if args.sast:
                    logging.info("Performing static analysis. This may take some time.")
                    sast_records = sast.run_sast(args, temp_dir, temp_dir)
                    code_issues.extend(sast_records)

                if args.iac_checks:
                    logging.info("Identifying infrastructure as code (IaC) issues. This may take some time.")
                    iac_records = iac.run_iac_checks(args, temp_dir, temp_dir)
                    code_issues.extend(iac_records)

                if len(code_issues) > 0:
                    assets[0]['sast'] = code_issues
                assets[0]['type'] = 'Google Cloud Function'
                assets[0]['tags'].extend(['GCP', 'Google Function', 'Serverless'])
                ret_assets.extend(assets)
                shutil.rmtree(temp_dir)
    return ret_assets 
