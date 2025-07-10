import os
import sys
import subprocess
import json
import logging
import shutil

from . import utils

_encoding = None
_compartments = None
_compartment_name_dict = None
_tenancy_namespace = None

oci_cli_default = "/usr/local/bin/oci"
oci_cli = shutil.which("oci")
if oci_cli is None:
    oci_cli = oci_cli_default

def set_encoding(encoding):
    global _encoding
    _encoding = encoding

def get_encoding():
    global _encoding
    return _encoding

def run_cmd(cmd, args):
    try:
        if args.verbosity >= 2:
            cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=subprocess.STDOUT)
        else:
            cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
    except subprocess.CalledProcessError as e:
        logging.error("Error running command [%s]", cmd)
        logging.debug("Command returned with exit code [%s]", e.returncode)
        logging.debug("Command output: %s", e.output)
        utils.tw_exit(1)
    return cmd_output

def run_oci_cmd(cmd, args):
    if not os.access(oci_cli, os.X_OK):
        logging.error('OCI CLI [%s] not found. Unable to run discovery', oci_cli)
        utils.tw_exit(1)
    cmd = oci_cli + ' ' + cmd + " --config-file '%s' --profile '%s'" % (args.config_file, args.config_profile)
    try:
        logging.debug("Running OCI command [%s]" % cmd)
        cmd_output = run_cmd(cmd, args)
        logging.debug("OCI command output as below:")
        logging.debug(cmd_output)
        ret_json = json.loads(cmd_output)
    except ValueError:
        logging.error("Error parsing JSON output for oci command [%s]: %s", cmd, cmd_output)
        utils.tw_exit(1)
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

