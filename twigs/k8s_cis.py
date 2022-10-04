import sys
import os
import subprocess
import logging
import re
import json

from . import utils

def run_k8s_cis(args, ctype):
    k8s_cis_path = os.path.dirname(os.path.realpath(__file__)) + '/kubernetes-cis-benchmark/'
    if args.target == None or (args.target != 'master' and args.target != 'worker'):
        logging.error("No target [master | worker] specified or invalid target")
        utils.tw_exit(1)

    if args.assetid.strip() == "":
        logging.error("[assetid] cannot be empty")
        utils.tw_exit(1)

    custom_rating_dict = None
    if args.custom_ratings:
        if os.path.isfile(args.custom_ratings):
            with open(args.custom_ratings,"r") as fd:
                try:
                    temp_cr = json.load(fd)
                    custom_rating_dict = { }
                    for rating in temp_cr:
                        if rating not in ["1", "2", "3", "4", "5"]:
                            logging.error("Invalid rating [%s] specified in custom rating JSON file [%s]", rating, args.custom_ratings)
                            utils.tw_exit(1)
                        tests = temp_cr[rating]
                        for test in tests:
                            custom_rating_dict[test] = rating
                except ValueError as ve:
                    logging.error('Unable to load JSON file %s', args.custom_ratings)
                    logging.error(ve)
                    utils.tw_exit(1)
        else:
            logging.error('Unable to access JSON file %s', args.custom_ratings)
            logging.error('Please check it exists and is accessible')
            utils.tw_exit(1)

    asset = {}
    asset['id'] = args.assetid
    asset['name'] = args.assetname if args.assetname and args.assetname.strip() != "" else asset['id']
    if ctype == 'k8s':
        asset['type'] = 'Kubernetes'
        asset['tags'] = ['Kubernetes', 'CIS']
    else:
        asset['type'] = 'GKE'
        asset['tags'] = ['GKE', 'CIS']
    asset['owner'] = args.handle
    asset['products'] = []
    args.no_scan = True


    k8s_cmd = k8s_cis_path
    if args.target == 'master':
        if ctype == 'k8s': 
            k8s_cmd = '/bin/bash ./master.sh 1.6.0'
        else:
            k8s_cmd = '/bin/bash ./master.sh gke'
    else:
        if ctype == 'k8s': 
            k8s_cmd = '/bin/bash ./worker.sh 1.6.0'
        else:
            k8s_cmd = '/bin/bash ./worker.sh gke'
    logging.info('Running CIS benchmark: ')
    try:
        os.chdir(os.path.dirname(k8s_cis_path))
        out = subprocess.check_output([k8s_cmd+" 2>/dev/null"], shell=True)
        out = out.decode(args.encoding)
        ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
        out = ansi_escape.sub('', out)
    except subprocess.CalledProcessError:
        logging.error("Error running CIS script")
        return None
    logging.info("CIS run completed")

    findings = []
    details = ''
    for l in out.splitlines():
        if not l.startswith('[WARN]'):
            continue
        issue = {}
        spa = l.split()
        check_id = spa[1].strip()
        if ctype == 'gke':
            check_id = l.split('Scored]')[1].strip().split()[0]
        if ctype == 'k8s':
            issue['twc_id'] = 'kubernetes-cis-check-'+check_id
        else:
            issue['twc_id'] = 'gke-cis-check-'+check_id
        issue['asset_id'] = args.assetid 
        issue['twc_title'] = check_id + ' ' + l.split(check_id)[1].strip()
        if custom_rating_dict:
            rating = custom_rating_dict.get(check_id)
            if rating == None:
                rating = '4'
        else:
            rating = '4'
        issue['rating'] = rating 
        if ctype == 'k8s':
            issue['type'] = 'Kubernetes CIS'
        else:
            issue['type'] = 'GKE CIS'
        issue['object_id'] = ''
        issue['object_meta'] = ''
        details = issue['twc_title'].replace(check_id+' - ','')
        issue['details'] = details
        findings.append(issue)

    asset['config_issues'] = findings
    #print(json.dumps(asset, indent=4))
    return [ asset ]

def get_inventory(args, ctype):
    return run_k8s_cis(args, ctype)
