import sys
import platform
import os
import json
import logging
import requests

from . import utils

def apply_policy(policy_names, asset_id_list, args):
    url = "https://" + args.instance + "/api/v1/policies/apply/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    policy_names_list = policy_names.split(',')
    payload = { "asset_ids": asset_id_list, "policy_names": policy_names_list }
    resp = requests.post(url + auth_data, json=payload)
    if resp.status_code == 200:
        logging.info("Applying specified policy....")
        policy_job_id = resp.json()['policy_job_id']
        logging.info("Policy job started...job id is [%s]. This may take some time...", policy_job_id)
        return policy_job_id
    else:
        logging.error("Error applying specified policy")
        logging.error("Response details: %s", resp.content)
        utils.tw_exit(1)

def is_policy_job_done(policy_job_id, args):
    url = "https://" + args.instance + "/api/v1/policyjobs/" + policy_job_id + "/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    resp = requests.get(url + auth_data)
    if resp.status_code == 200:
        policy_job_json = resp.json()
        if policy_job_json['status'] == "COMPLETED":
            return True, policy_job_json
        else:
            return False, policy_job_json
    else:
        logging.error("Error retrieving policy job details for [%s]", policy_job_id)
        logging.error("Response details: %s", resp.content)
        return False, None

def process_policy_job_actions(pj_json):
    exit_with_code = False
    exit_code = None
    final_actions = { }
    policies = pj_json['policy_json']
    policies_outcome = pj_json['policy_outcome']
    for policy in policies:
        pn = policy['name']
        pa = policy['actions']
        policy_outcome = policies_outcome[pn]
        for assetid in policy_outcome.keys():
            po = policy_outcome[assetid][0]
            if po == "PASSED":
                lookup = 'on_pass'
            elif po == "FAILED":
                lookup = 'on_fail'
            if final_actions.get(pn) is None:
                final_actions[pn] = { }
            if pa.get(lookup) is not None:
                final_actions[pn][assetid] = pa[lookup]
                if "exit_with_code" in pa[lookup].keys():
                    exit_with_code = True
                    exit_code = pa[lookup]['exit_with_code']

    # Process policies with actions other than 'exit_with_code' in final_actions
    # TODO later on

    logging.info("Policy evaluation is done...")
    if exit_with_code:
        return exit_code
    else:
        return None

