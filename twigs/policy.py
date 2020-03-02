import sys
import platform
import os
import json
import logging
import requests

_builtin_policies = [
    "no_do_now_impacts",
    "no_strong_copylefts",
    "no_code_secrets"
]

_allowed_fields_by_type = { 
    'vulnerability': {'priority': ["do now", "do later"] },
    'license': {'copyleft level': []},
    'code_secret': {'status': [], 'regex':[]},
    'dast': {}
}

_allowed_operators = [ '=', '!=', '>', '<', '>=', '<=']

_supported_action_types = ["on pass", "on fail"]

_allowed_actions = ['exit with code']

def validate_policy_file(policy_json_file):
    if os.path.isfile(policy_json_file) == False:
        logging.error('Error sepcified file [%s] not found...', policy_json_file)
        sys.exit(1)

    with open(policy_json_file, "r") as fd:
        try:
            policy_json = json.load(fd)
        except json.JSONDecodeError as ex:
            logging.error('Decoding JSON file failed with error [%s]', ex)
            sys.exit(1)

    ret_val = True
    for policy in policy_json:
        temp = validate_policy(policy)
        if ret_val == True:
            ret_val = temp

    if ret_val == False:
        logging.error('One or more policy validations failed...exiting!')
        sys.exit(1)

    return policy_json

def validate_policy(policy):
    if policy.get('name') is None:
        logging.error('Policy is missing field [%s]', policy_field)
        return False
    policy_name = policy['name']
    logging.info('Validating policy [%s]', policy_name)

    ret_val = True

    using_builtin_policy = False
    global _builtin_policies
    builtin_policy_name = policy.get('builtin_policy')
    if builtin_policy_name is not None:
        if builtin_policy_name in _builtin_policies:
            using_builtin_policy = True
        else:
            logging.error("Error: Policy [%s] is using unsupported builtin policy [%s]", policy_name, builtin_policy_name)
            return False

    policy_fields = ['type', 'conditions', 'actions'] if not using_builtin_policy else ['actions']

    # check required fields exist in policy
    for policy_field in policy_fields:
        if policy.get(policy_field) is None:
            ret_val = False
            logging.error('Policy [%s] is missing field [%s]', policy_name, policy_field)

    if not using_builtin_policy:
        condition_fields = ['field', 'operator', 'value']
        for condition in policy['conditions']:
            for cf in condition_fields:
                if condition.get(cf) is None:
                    logging.error('Condition [%s] in policy [%s] is missing field [%s]', condition, policy_name, cf)
                    ret_val = False

    actions = policy.get('actions')
    if len(actions) == 0:
        logging.error('There are no actions specified in policy [%s]...', policy_name)
        ret_val = False

    if ret_val == False:
        return False

    global _allowed_fields_by_type

    if not using_builtin_policy:
        policy_type = policy['type'].lower()
        if policy_type not in _allowed_fields_by_type.keys():
            logging.error('Policy [%s] has invalid type [%s]', policy_name, policy_type)
            return False
        else:
            policy['type'] = policy_type

        global _allowed_operators

        for condition in policy['conditions']:
            if condition['field'].lower() in _allowed_fields_by_type[policy_type].keys():
                condition['field'] = condition['field'].lower()
            else:
                logging.error('Invalid field [%s] specified in condition [%s] in policy [%s]', condition['field'], condition, policy_name)
                return False
            if condition['operator'] not in _allowed_operators:
                logging.error('Invalid operator [%s] specified in condition [%s] in policy [%s]', condition['operator'], condition, policy_name)
                ret_val = False
            if len(allowed_fields_by_type[policy_type][condition['field'].lower()]) > 0:
                if condition['value'].lower() not in _allowed_fields_by_type[policy_type][condition['field'].lower()]:
                    logging.error('Invalid value [%s] specified in condtion [%s] in policy [%s]', condition['value'], condition, policy_name)
                    ret_val = False

    global _supported_action_types
    global _allowed_actions
    actions = policy['actions']
    for action_type in actions.keys():
        if action_type not in _supported_action_types:
            logging.error('Unsupported action category [%s]', action_type)
            ret_val = False
    for action_type in _supported_action_types:
        actions = policy['actions'].get(action_type)
        if actions is not None:
            for action in actions:
                if action.lower() not in _allowed_actions:
                    logging.error('Invalid action [%s] specified in policy [%s]', action, policy_name)
                    ret_val = False
    if ret_val:
        logging.info("Policy validated successfully...")
    return ret_val

def apply_policy(policy_json, asset_id_list, args):
    url = "https://" + args.instance + "/api/v1/policies/apply/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    payload = { "asset_ids": asset_id_list, "policy_json": policy_json }
    resp = requests.post(url + auth_data, json=payload)
    if resp.status_code == 200:
        logging.info("Applying specified policy....")
        policy_job_id = resp.json()['policy_job_id']
        logging.info("Policy job started...job id is [%s]. This may take sometime...", policy_job_id)
        return policy_job_id
    else:
        logging.error("Error applying specified policy")
        logging.error("Response details: %s", resp.content)
        sys.exit(1)

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
            po = policy_outcome[assetid]
            if po == "PASSED":
                lookup = 'on pass'
            elif po == "FAILED":
                lookup = 'on fail'
            if final_actions.get(pn) is None:
                final_actions[pn] = { }
            if pa.get(lookup) is not None:
                final_actions[pn][assetid] = pa[lookup]
                if "exit with code" in pa[lookup].keys():
                    exit_with_code = True
                    exit_code = pa[lookup]['exit with code']

    # Process policies with actions other than 'exit_with_code' in final_actions
    # TODO later on

    logging.info("Policy evaluation is done...")
    if exit_with_code:
        return exit_code
    else:
        return None

