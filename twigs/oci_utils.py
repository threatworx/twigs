import os
import sys
import subprocess
import json
import logging

_encoding = None
_compartments = None
_compartment_name_dict = None
_tenancy_namespace = None

def set_encoding(encoding):
    global _encoding
    _encoding = encoding

def get_encoding():
    global _encoding
    return _encoding

def run_cmd(cmd):
    try:
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
    except subprocess.CalledProcessError:
        logging.error("Error running command [%s]", cmd)
        cmd_output = ""
    return cmd_output

def run_oci_cmd(cmd, args):
    cmd = 'oci ' + cmd + " --config-file '%s' --profile '%s'" % (args.config_file, args.config_profile)
    try:
        logging.debug("Running OCI command [%s]" % cmd)
        cmd_output = run_cmd(cmd)
        logging.debug("OCI command output as below:")
        logging.debug(cmd_output)
        ret_json = json.loads(cmd_output)
    except subprocess.CalledProcessError:
        logging.error("Error running oci command [%s]", cmd)
        ret_json = { }
    except ValueError:
        logging.error("Error parsing JSON output for oci command [%s]: %s", cmd, cmd_output)
        ret_json = { }
    return ret_json

def get_compartments(args):
    global _compartments
    if _compartments is not None:
        return _compartments
    _compartments = set()
    compartments_json = run_oci_cmd('iam compartment list --include-root --all --compartment-id-in-subtree true', args)
    compartments_json = compartments_json['data']
    for entry in compartments_json:
        _compartments.add(entry['id'])
    return _compartments

def get_compartment_name_dict(args):
    global _compartment_name_dict
    if _compartment_name_dict is not None:
        return _compartment_name_dict
    _compartment_name_dict = { }
    compartments_json = run_oci_cmd('iam compartment list --include-root --all --compartment-id-in-subtree true', args)
    compartments_json = compartments_json['data']
    for entry in compartments_json:
        _compartment_name_dict[entry['id']] = entry['name']
    return _compartment_name_dict

def get_tenancy_namespace(args):
    global _tenancy_namespace
    if _tenancy_namespace is not None:
        return _tenancy_namespace
    ret_json = run_oci_cmd('os ns get', args)
    return ret_json['data']

