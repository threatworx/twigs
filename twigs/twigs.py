#!/usr/bin/env python
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import os
import logging
import argparse
import time
import json
import traceback
import pkgutil
import importlib
import getpass
import hashlib
import shutil
import stat
from os.path import expanduser
import copy
import warnings
with warnings.catch_warnings():
   warnings.simplefilter("ignore", category=Warning)
   from cryptography.hazmat.backends import default_backend
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   from cryptography.fernet import Fernet

try:
    from . import utils
    from . import aws
    from . import linux
    from . import windows
    from . import repo
    from . import docker
    from . import kubernetes
    from . import azure
    from . import o365 
    from . import acr
    from . import ecr
    from . import gcp
    from . import gcr
    from . import oci
    from . import ocr
    from . import servicenow
    from . import sbom
    from . import fingerprint
    from . import dast
    from . import docker_cis
    from . import aws_cis
    from . import azure_cis
    from . import azure_functions
    from . import gcp_cis
    from . import k8s_cis
    from . import oci_cis
    from . import gcloud_functions
    from . import vmware 
    from . import website 
    from . import meraki
    from . import dna_center 
    from . import policy as policy_lib
    from .__init__ import __version__
except (ImportError,ValueError):
    from twigs import aws
    from twigs import linux
    from twigs import windows
    from twigs import repo
    from twigs import docker
    from twigs import kubernetes
    from twigs import azure
    from twigs import o365 
    from twigs import acr
    from twigs import ecr
    from twigs import gcp
    from twigs import gcr
    from twigs import oci
    from twigs import ocr
    from twigs import servicenow
    from twigs import sbom
    from twigs import fingerprint
    from twigs import dast
    from twigs import docker_cis
    from twigs import aws_cis
    from twigs import azure_cis
    from twigs import azure_functions
    from twigs import gcp_cis
    from twigs import k8s_cis
    from twigs import oci_cis
    from twigs import gcloud_functions
    from twigs import vmware
    from twigs import website
    from twigs import meraki
    from twigs import dna_center 
    from twigs import utils
    from twigs import policy as policy_lib
    from twigs.__init__ import __version__

# Note this error routine assumes that the file was read-only and hence could not be deleted
def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

def export_assets_to_sbom_file(assets, timestamp, args):
    json_file = args.sbom
    logging.info("Exporting assets to SBOM JSON file [%s]", json_file)
    add_attack_surface_label(args, assets)
    sbom_assets = copy.deepcopy(assets)
    add_asset_tags(sbom_assets, ["SBOM"])
    sbom_json = { }
    sbom_json['meta'] = { }
    sbom_json['meta']['generated_by'] = args.handle
    sbom_json['meta']['generated_on'] = str(timestamp)
    sbom_json['meta']['tool_name'] = 'twigs'
    sbom_json['meta']['tool_version'] = __version__
    sbom_json['assets'] = sbom_assets
    with open(json_file, "w") as fd:
        json.dump(sbom_json, fd, indent=2, sort_keys=True)
    logging.info("Successfully exported assets to SBOM JSON file!")

def push_sourcecode(asset, args, base_path, skip_checksum_check):
    if hasattr(args, 'sast') == False and hasattr(args, 'iac_checks') == False:
        return
    if args.no_code:
        return
    if asset.get('sast') is None or len(asset['sast']) == 0:
        return

    sourcefilepaths = set()
    for ci in asset['sast']:
        sourcefilepaths.add(ci['filename'])
    if len(sourcefilepaths) == 0:
        return

    base_api_url = "https://%s/api/v1/assets/%s/" % (args.instance, asset['id'])
    auth_data = "?handle=%s&token=%s&format=json" % (args.handle, args.token)
    checksum_check_api_url = base_api_url + "sourcefiles_check/"
    upload_sourcefile_api_url = base_api_url + "sourcefiles/"
    BATCH_SIZE = 5 # determine how many maximum files are uploaded in one request
    sourcefilepaths = list(sourcefilepaths)
    batches = [sourcefilepaths[i:i + BATCH_SIZE] for i in range(0, len(sourcefilepaths), BATCH_SIZE)]
    for batch in batches:
        files_to_send = []
        files_in_batch = []
        request_payload = { 'sourcefiles': { } }
        index = 0
        for item in batch:
            fd = open(base_path + os.path.sep + item, 'rb')
            fc = fd.read()
            fd.seek(0) # reset the read pointer
            index = index + 1
            checksum = hashlib.sha256(fc).hexdigest()
            request_payload['sourcefiles'][item] = checksum
            files_in_batch.append((fd, checksum))

        if not skip_checksum_check:
            # Make request to check if file is updated
            resp = utils.requests_post(checksum_check_api_url + auth_data, json=request_payload)
            if resp is not None and resp.status_code == 200:
                resp_json = resp.json()
                for sfp in resp_json.keys():
                    if resp_json[sfp]:
                        # Checksum is updated, then file needs to be uploaded
                        files_to_send.append(sfp)
            else:
                logging.warning("Failed to compare checksums for batch [%s]" % batch)
                logging.debug(resp.text)
                # fail-safe handling - upload all these files anyways
                for item in batch:
                    files_to_send.append(item)
        else:
            # new asset scenario - upload all files, no need to check checksums
            for item in batch:
                files_to_send.append(item)

        if len(files_to_send) == 0:
            # there are no files that need to be pushed in this batch
            continue

        # Make request to update required files
        index = 0
        request_files = []
        for item in batch:
            if item not in files_to_send:
                index = index + 1
                continue
            this_file = (item, (files_in_batch[index][1], files_in_batch[index][0]))
            request_files.append(this_file)
            index = index + 1

        resp = utils.requests_post_files(upload_sourcefile_api_url + auth_data, request_files)
        if resp is not None and resp.status_code == 200:
            logging.info("Successfully uploaded files in batch: %s", ", ".join(files_to_send))
        else:
            logging.error("Encountered error while uploading files in batch: %s", ", ".join(files_to_send))
            logging.debug(resp.text)

        for value in files_in_batch:
            fd = value[0]
            fd.close()

# Note ret_scan_status can have following possible values:
# None - Error condition
# False - No scan needed
# Q - quick scan (product or patch updates)
# F - full scan (asset OS version/release change)
def push_asset_to_TW(asset, args):
    asset_url = "https://" + args.instance + "/api/v2/assets/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    if args.email_report:
        auth_data = auth_data + "&esr=true" # email secrets report (esr)
    if asset.get('products') is not None:
        asset['products'] = list(set(asset['products']))
    if args.org is not None and len(args.org) > 0:
        asset['org'] = args.org # Add Org info in the asset
    asset_id = asset['id']
    ret_asset_id = None
    ret_scan_status = None
    base_path = asset.pop('tw_base_path', None)
    delete_base_path = asset.pop('tw_delete_base_path', False)

    if not args.test:
        resp = utils.requests_get(asset_url + asset_id + "/" + auth_data)
        if resp is None:
            logging.info("Unable to check if asset exists...skipping asset [%s]", asset_id)
            ret_asset_id = None
            ret_scan_status = False
        else:
            if resp.status_code != 200:
                logging.info("Creating new asset [%s]", asset_id)
                # Asset does not exist so create one with POST
                resp = utils.requests_post(asset_url + auth_data, json=asset)
                if resp is not None and resp.status_code == 200:
                    logging.info("Successfully created new asset [%s]", asset_id)
                    logging.info("Response content: %s", resp.content.decode(args.encoding))
                    push_sourcecode(asset, args, base_path, True)
                    ret_asset_id = asset_id
                    ret_scan_status = 'Q' # Quick scan will result in full scan for new asset
                else:
                    logging.error("Failed to create new asset [%s]", asset_id)
                    if resp is not None:
                        logging.error("Response details: %s", resp.content.decode(args.encoding))
                    ret_asset_id = None
                    ret_scan_status = False
            else:
                logging.info("Updating asset [%s]", asset_id)
                # asset exists so update it with PUT
                resp = utils.requests_put(asset_url + asset_id + "/" + auth_data, json=asset)
                if resp is not None and resp.status_code == 200:
                    logging.info("Successfully updated asset [%s]", asset_id)
                    logging.debug("Response content: %s", resp.content.decode(args.encoding))
                    push_sourcecode(asset, args, base_path, False)
                    resp_json = resp.json()
                    if 'No product updates' in resp_json['status']:
                        ret_asset_id = asset_id
                        ret_scan_status = False
                    else:
                        ret_asset_id = asset_id
                        if 'Full scan needed' in resp_json['status']:
                            ret_scan_status = 'F'
                        else:
                            ret_scan_status = 'Q'
                else:
                    logging.error("Failed to update existing asset [%s]", asset_id)
                    if resp is not None:
                        logging.error("Response details: %s", resp.content.decode(args.encoding))
                    ret_asset_id = asset_id
                    ret_scan_status = False

    if delete_base_path:
        shutil.rmtree(base_path, onerror = on_rm_error)
    return ret_asset_id, ret_scan_status

def push_assets_to_TW(assets, args):
    asset_id_list = []
    quick_scan_asset_id_list = []
    full_scan_asset_id_list = []
    for asset in assets:
        asset_id, scan = push_asset_to_TW(asset, args)
        if asset_id is not None:
            asset_id_list.append(asset_id)
        if scan == 'Q':
            quick_scan_asset_id_list.append(asset_id)
        elif scan == 'F':
            full_scan_asset_id_list.append(asset_id)
    return asset_id_list, quick_scan_asset_id_list, full_scan_asset_id_list

def check_and_run_policy_job(args, asset_ids_list):
    pj_json = None
    if args.apply_policy is not None:
        policy_job_name = policy_lib.apply_policy(args.apply_policy, asset_ids_list, args)
        while True:
            time.sleep(60)
            status, pj_json = policy_lib.is_policy_job_done(policy_job_name, args)
            if status:
                exit_code = policy_lib.process_policy_job_actions(pj_json)
                return exit_code, pj_json
    return None, pj_json

def run_va_lic_eol_scan(asset_id_list, full_scan_asset_id_list, pj_json, args):
    scan_api_url = "https://" + args.instance + "/api/v1/scans/?handle=" + args.handle + "&token=" + args.token + "&format=json"
    if args.no_scan is not True:
        if len(asset_id_list) == 0 and len(full_scan_asset_id_list) == 0:
            logging.debug("No asset scan required")
            return 
        run_va_scan = True
        run_lic_scan = True
        if pj_json is not None:
            for policy in pj_json['policy_json']:
                if policy['type'] == 'cicdvulnpolicy':
                    logging.info("Impact assessment performed as part of policy evaluation")
                    run_va_scan = False # VA scan already done, so don't do it again
                elif policy['type'] == 'cicdlicensepolicy':
                    logging.info("License compliance performed as part of policy evaluation")
                    run_lic_scan = False # License scan already done, so don't do it again

        if run_va_scan:
            if len(asset_id_list) > 0:
                # Start  quick VA scan
                scan_payload = { }
                scan_payload['assets'] = asset_id_list
                # if args.purge_assets:
                #    scan_payload['mode'] = 'email-purge'
                if args.email_report:
                    scan_payload['mode'] = 'email'
                resp = utils.requests_post(scan_api_url, json=scan_payload)
                if resp is not None and resp.status_code == 200:
                    logging.info("Started incremental impact refresh")
                else:
                    logging.error("Failed to start incremental impact refresh")
                    if resp is not None:
                        logging.error("Response details: %s", resp.content.decode(args.encoding))

            if len(full_scan_asset_id_list) > 0:
                # Start  full VA scan
                scan_payload = { "scan_type": "full" }
                scan_payload['assets'] = full_scan_asset_id_list
                # if args.purge_assets:
                #    scan_payload['mode'] = 'email-purge'
                if args.email_report:
                    scan_payload['mode'] = 'email'
                resp = utils.requests_post(scan_api_url, json=scan_payload)
                if resp is not None and resp.status_code == 200:
                    logging.info("Started full impact refresh")
                else:
                    logging.error("Failed to start full impact refresh")
                    if resp is not None:
                        logging.error("Response details: %s", resp.content.decode(args.encoding))

        if run_lic_scan and (args.mode == "repo" or args.mode == "file_repo" or args.mode == "sbom") and len(asset_id_list) > 0:
            # Start license compliance assessment
            scan_payload = { }
            scan_payload['assets'] = asset_id_list
            scan_payload['license_scan'] = True
            # if args.purge_assets:
            #    scan_payload['mode'] = 'email-purge'
            if args.email_report:
                scan_payload['mode'] = 'email'
            resp = utils.requests_post(scan_api_url, json=scan_payload)
            if resp is not None and resp.status_code == 200:
                logging.info("Started license compliance assessment")
            else:
                logging.error("Failed to start license compliance assessment")
                if resp is not None:
                    logging.error("Response details: %s", resp.content.decode(args.encoding))

        combined_asset_id_list = []
        combined_asset_id_list.extend(asset_id_list)
        combined_asset_id_list.extend(full_scan_asset_id_list)
        if args.mode in ["host", "aws", "azure", "gcp", "oci", "acr", "gcr", "ecr", "ocr", "docker", "k8s"] and len(combined_asset_id_list) > 0:
            # Start EOL assessment
            scan_payload = { }
            scan_payload['assets'] = combined_asset_id_list
            scan_payload['eol_scan'] = True
            resp = utils.requests_post(scan_api_url, json=scan_payload)
            if resp is not None and resp.status_code == 200:
                logging.info("Started EOL assessment")
            else:
                logging.error("Failed to start EOL assessment")
                if resp is not None:
                    logging.error("Response details: %s", resp.content.decode(args.encoding))

def run_remediation_scan(asset_id_list, args):
    # Start remediation scan
    scan_api_url = "https://" + args.instance + "/api/v1/scans/?handle=" + args.handle + "&token=" + args.token + "&format=json"
    scan_payload = { }
    scan_payload['assets'] = asset_id_list
    scan_payload['remediation_scan'] = True
    scan_payload['issue_types'] = ["SAST", "IaC", "GCP CIS", "AWS CIS", "OCI CIS", "Azure CIS", "Host Benchmark"]
    # Note add "Impact" only if twscan is not being run i.e. no_scan is True
    if args.no_scan:
        scan_payload['issue_types'].append('Impact')
    resp = utils.requests_post(scan_api_url, json=scan_payload)
    if resp is not None and resp.status_code == 200:
        logging.info("Started remediation scan")
    else:
        logging.error("Failed to start remediation scan")
        if resp is not None:
            logging.error("Response details: %s", resp.content.decode(args.encoding))

def get_host_as_label(in_label, asset):
    if asset['type'] == "Google Container-Optimized OS":
        return in_label + "::Google COS"
    elif asset['type'] == 'Other':
        return in_label + "::Unclassified"
    else:
        return in_label + "::" + asset['type']

def get_container_as_label(in_label, asset):
    if asset['type'] == "Container App":
        return in_label + "::App"
    else:
        return in_label + "::Image::" + asset['type']

def get_code_as_label(in_label, asset):
    if asset.get('tags') is None:
        asset_tags_set = set()
    else:
        asset_tags_set = set(asset['tags'])
    supported_types_set = set(repo.SUPPORTED_TYPES)
    supported_types_set = supported_types_set.union({'Secret','SAST', 'IaC'})
    intersection_set = supported_types_set & asset_tags_set
    if len(intersection_set) == 0:
        return in_label + "::Empty"
    elif len(intersection_set) == 1:
        return in_label + "::" + list(intersection_set)[0]
    else:
        return in_label + "::Multiple"

def add_attack_surface_label(args, assets):
    for asset in assets:
        as_label = None
        if args.mode == 'aws':
            as_label = get_host_as_label("Cloud::AWS::EC2", asset)
        elif args.mode == 'azure':
            as_label = get_host_as_label("Cloud::Azure::VM", asset)
        elif args.mode == 'gcp':
            as_label = get_host_as_label("Cloud::GCP::Compute", asset)
        elif args.mode == 'oci':
            as_label = get_host_as_label("Cloud::OCI::Compute", asset)
        elif args.mode == 'o365':
            as_label = get_host_as_label("Corporate::Server", asset)
        elif args.mode == 'acr':
            as_label = get_container_as_label("Cloud::Azure::ACR", asset)
        elif args.mode == 'ecr':
            as_label = get_container_as_label("Cloud::AWS::ECR", asset)
        elif args.mode == 'gcr':
            as_label = get_container_as_label("Cloud::GCP::GCR", asset)
        elif args.mode == 'ocr':
            as_label = get_container_as_label("Cloud::OCI::OCR", asset)
        elif args.mode == 'servicenow':
            as_label = get_host_as_label("Corporate::Server", asset)
        elif args.mode == 'repo':
            as_label = get_code_as_label("Code", asset)
        elif args.mode == "github":
            as_label = get_code_as_label("Code", asset)
        elif args.mode == "gitlab":
            as_label = get_code_as_label("Code", asset)
        elif args.mode == "bitbucket":
            as_label = get_code_as_label("Code", asset)
        elif args.mode in ['host', 'win_host']:
            as_label = get_host_as_label("Corporate::Server", asset)
        elif args.mode == 'vmware':
            if asset['type'] == 'VMware vCenter':
                as_label = "Corporate::VMware::vCenter"
            elif asset['type'] == 'VMware ESXi':
                as_label = "Corporate::VMware::ESXi"
        elif args.mode == 'nmap':
            if asset['type'] == 'HP Printer':
                as_label = "Corporate::Printer::HP Printer"
            else:
                as_label = get_host_as_label("Corporate::Server", asset)
        elif args.mode == 'docker':
            as_label = get_container_as_label("Container::Docker", asset)
        elif args.mode == 'k8s':
            as_label = get_container_as_label("Container::Kubernetes", asset)
        elif args.mode == 'sbom':
            # Skip for TW SBOM, other sboms populate TP along with Code
            if args.standard != "threatworx" and args.org is not None and len(args.org) > 0:
                tp_name = args.org
                as_label = "Third Party::%s::Code" % tp_name
                as_label = get_code_as_label(as_label, asset)
        elif args.mode == 'dast':
            pass
        elif args.mode == 'docker_cis':
            as_label = "Container::Docker::Misconfig"
        elif args.mode == 'aws_cis':
            as_label = "Cloud::AWS::Account"
        elif args.mode == 'aws_audit':
            as_label = "Cloud::AWS::Account"
        elif args.mode == 'azure_cis':
            as_label = "Cloud::Azure::Tenant"
        elif args.mode == 'gcp_cis':
            as_label = "Cloud::GCP::Org"
        elif args.mode == 'oci_cis':
            as_label = "Cloud::OCI::Tenant"
        elif args.mode == 'k8s_cis':
            as_label = "Container::Kubernetes::Misconfig"
        elif args.mode == 'gke_cis':
            as_label = "Cloud::GCP::GKE::Misconfig"
        elif args.mode == 'azure_functions':
            as_label = get_code_as_label("Cloud::Azure::Serverless", asset)
        elif args.mode == 'gcloud_functions':
            as_label = get_code_as_label("Cloud::GCP::Serverless", asset)
        elif args.mode == 'meraki' or args.mode == 'dna_center':
            as_label = get_code_as_label("Corporate::Network::Cisco", asset)

        if as_label is not None:
            asset['attack_surface_label'] = as_label

def remove_standard_tags(assets):
    for asset in assets:
        existing_tags = asset['tags']
        if existing_tags is not None:
            new_tags = []
            for et in existing_tags:
                if et.split(':')[0] in utils.SYSTEM_TAGS:
                    new_tags.append(et)
            asset['tags'] = new_tags

def add_asset_tags(assets, tags):
    if assets is None:
        return
    for asset in assets:
        existing_tags = asset.get('tags')
        if existing_tags is None:
            asset['tags'] = tags
        else:
            existing_tags.extend(tags)

def add_asset_owners(assets, additional_owners):
    for asset in assets:
        asset['notify'] = additional_owners

def add_asset_location(assets, location):
    for asset in assets:
        asset['location'] = location

def add_asset_timestamp(assets, timestamp):
    for asset in assets:
        asset['timestamp'] = str(timestamp)

def add_asset_criticality_tag(assets, asset_criticality):
    asset_criticality_tag = 'CRITICALITY:'+str(asset_criticality)
    add_asset_tags(assets, [asset_criticality_tag])

def authenticate_user(tw_user, tw_pwd, tw_instance):
    payload = { }
    payload["handle"] = tw_user
    payload["password"] = tw_pwd
    twigs_auth_url = "https://" + tw_instance + "/api/v1/twigsauth/"
    resp = utils.requests_post(twigs_auth_url, json=payload)
    if resp is not None and resp.status_code == 200:
        logging.info("User logged in successfully")
        return resp.json()["token"]
    else:
        logging.error("User authentication failed")
        if resp is not None:
            logging.debug("Response: %s", resp.content)
        sys.exit(1)

def login_user(args):
    try:
        if sys.version_info.major < 3:
            tw_user = raw_input("Enter email of ThreatWorx user: ")
        else:
            tw_user = input("Enter email of ThreatWorx user: ")
        temp_pwd = getpass.getpass(prompt='Enter password: ')
        if sys.version_info.major < 3:
            tw_instance = raw_input("Enter ThreatWorx instance [threatworx.io]: ")
        else:
            tw_instance = input("Enter ThreatWorx instance [threatworx.io]: ")
    except KeyboardInterrupt:
        print("")
        sys.exit(1)
    if tw_instance == "":
        tw_instance = "threatworx.io"
    tw_token = authenticate_user(tw_user, temp_pwd, tw_instance)
    auth_dict = {}
    auth_dict['handle'] = tw_user
    auth_dict['token'] = tw_token
    auth_dict['instance'] = tw_instance
    user_home_dir = expanduser("~")
    tw_dir = user_home_dir + os.path.sep + '.tw'
    if os.path.isdir(tw_dir) == False:
        os.mkdir(tw_dir, 0o700)
    auth_file = tw_dir + os.path.sep + 'auth.json'
    if os.path.exists(auth_file):
        os.remove(auth_file)
    with open(auth_file, "w") as fd:
        json.dump(auth_dict, fd)
    os.chmod(auth_file, 0o600)
    sys.exit(0)

def logout_user(args):
    user_home_dir = expanduser("~")
    tw_dir = user_home_dir + os.path.sep + '.tw'
    if os.path.isdir(tw_dir):
        auth_file = tw_dir + os.path.sep + 'auth.json'
        if os.path.exists(auth_file):
            os.remove(auth_file)
    sys.exit(0)

def get_logged_in_user_details():
    ret_dict = { }
    user_home_dir = expanduser("~")
    tw_dir = user_home_dir + os.path.sep + '.tw'
    if os.path.isdir(tw_dir):
        auth_file = tw_dir + os.path.sep + 'auth.json'
        if os.path.exists(auth_file):
            with open(auth_file, "r") as fd:
                ret_dict = json.load(fd)
    return ret_dict

def main(args=None):

    try:
    
        if args is None:
            args = sys.argv[1:]

        if sys.platform != 'win32':
            utils.set_requests_verify(os.path.dirname(os.path.realpath(__file__)) + os.sep + 'gd-ca-bundle.crt')

        parser = argparse.ArgumentParser(description='ThreatWorx Information Gathering Script (twigs) to discover assets like hosts, cloud instances, containers and source code repositories')
        subparsers = parser.add_subparsers(title="modes", description="Discovery modes and commands supported", dest="mode")
        # Required arguments
        parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
        parser.add_argument('--handle', help='The ThreatWorx registered email of the user. Note this can set as "TW_HANDLE" environment variable', required=False)
        parser.add_argument('--token', help='The ThreatWorx API token of the user. Note this can be set as "TW_TOKEN" environment variable', required=False)
        parser.add_argument('--instance', help='The ThreatWorx instance. Note this can be set as "TW_INSTANCE" environment variable')
        parser.add_argument('--org', help='Associate discovered asset(s) with specified organization')
        parser.add_argument('--run_id', help='Specify a distinct identifier for this twigs discovery run')
        # Hidden argument to track the record identifier for a run
        parser.add_argument('--run_record_id', help=argparse.SUPPRESS)
        parser.add_argument('--location', help='Specify location information for discovered asset(s).')
        parser.add_argument('--create_empty_asset', action='store_true', help='Create empty asset even if nothing is discovered. Applicable to source code (repo) assets.')
        parser.add_argument('--tag_critical', action='store_true', help='Tag the discovered asset(s) as critical')
        parser.add_argument('--tag', action='append', help='Add specified tag to discovered asset(s). You can specify this option multiple times to add multiple tags')
        parser.add_argument('--owner', action='append', help='Add additional owner(s) to discovered asset(s). You can specify this option multiple times to add multiple owners. Note user discovering the asset is added as owner by default')
        parser.add_argument('--no_auto_tags', action='store_true', help='Disable auto tagging of assets with standard classification tags. Only user specified tags will be applied')
        #parser.add_argument('--asset_criticality', choices=['1', '2', '3','4', '5'], help='Business criticality of the discovered assets on a scale of 1 (low) to 5 (high).', required=False)
        parser.add_argument('--apply_policy', help='One or more policy names as a comma-separated list', required=False)
        parser.add_argument('--sbom', help='Specify name of the SBOM file to hold the exported asset information.')
        parser.add_argument('--out', help=argparse.SUPPRESS)
        parser.add_argument('--no_scan', action='store_true', help='Do not initiate a baseline assessment')
        parser.add_argument('--email_report', action='store_true', help='After impact refresh is complete email scan report to self')
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-q','--quiet', action='store_true', help='Disable verbose logging')
        group.add_argument('-v','--verbosity', action='count', default=0, help='Specify the verbosity level. Use multiple times to increase verbosity level')
        if sys.platform != 'win32':
            parser.add_argument('--schedule', help='Run this twigs command at specified schedule (crontab format)')
        parser.add_argument('--encoding', help='Specify the encoding. Default is "latin-1"', default='latin-1')
        parser.add_argument('--insecure', action='store_true', help=argparse.SUPPRESS) # deprecated
        parser.add_argument('--nosslverify', action='store_true', help=argparse.SUPPRESS)
        # parser.add_argument('--purge_assets', action='store_true', help='Purge the asset(s) after impact refresh is complete and scan report is emailed to self')

        #test to be able to run without handle, token, or instance 
        parser.add_argument('--test' , action="store_true", help = 'Run a test scan without reporting to threatworx instance')

        # Arguments required for Login
        parser_login = subparsers.add_parser("login", help = "Login to twigs")

        # Arguments required for Logout
        parser_logout = subparsers.add_parser("logout", help = "Logout from twigs")

        # Arguments required for AWS discovery
        parser_aws = subparsers.add_parser ("aws", help = "Discover AWS instances")
        parser_aws.add_argument('--aws_account', help='AWS account ID', required=True)
        parser_aws.add_argument('--aws_access_key', help='AWS access key', required=True)
        parser_aws.add_argument('--aws_secret_key', help='AWS secret key', required=True)
        parser_aws.add_argument('--aws_region', help='AWS region', required=True)
        parser_aws.add_argument('--aws_s3_bucket', help='AWS S3 inventory bucket', required=True)
        parser_aws.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording AWS specific information (like AWS Account ID, etc.) as asset tags', required=False)
        
        # Arguments required for Azure discovery
        parser_azure = subparsers.add_parser ("azure", help = "Discover Azure instances")
        parser_azure.add_argument('--azure_workspace', help='Azure Log Analytics Workspace ID', required=False)
        parser_azure.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording Azure specific information (like Azure Tenant ID, etc.) as asset tags', required=False)

        # Arguments required for Google Cloud Platform discovery
        parser_gcp = subparsers.add_parser ("gcp", help = "Discover Google Cloud Platform instances")
        parser_gcp.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording GCP specific information (like Project ID, etc.) as asset tags', required=False)

        # Arguments required for Oracle Cloud discovery
        parser_oci = subparsers.add_parser ("oci", help = "Discover Oracle Cloud Compute instances")
        parser_oci.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording OCI specific information (like Compartment name, etc.) as asset tags', required=False)
        parser_oci.add_argument('--config_file', help="Specify the OCI configuration file. Default value is '~/.oci/config'", required=False, default='~/.oci/config')
        parser_oci.add_argument('--config_profile', help="Specify the profile in OCI configuration file. Default profile is 'DEFAULT'", required=False, default='DEFAULT')

        # Arguments required for AWS Container Registry discovery 
        parser_ecr = subparsers.add_parser ("ecr", help = "Discover AWS Container Registry images")
        parser_ecr.add_argument('--registry', help='The AWS Container Registry (AWS account ID) which needs to be inspected for all repositories.')
        parser_ecr.add_argument('--image', help='The fully qualified image name (repositoryUri with optional tag) to be inspected. If tag is not given, latest will be determined for all images under this repository')
        parser_ecr.add_argument ("--repository_type", help = "Specify repository type (public/private). Defaults to private repositories if not specified", choices=['public','private'], default='private')
        parser_ecr.add_argument('--tmp_dir', help='Temporary directory. Defaults to /tmp', required=False)

        parser_ecr.add_argument('--containerid', help=argparse.SUPPRESS, required=False)
        parser_ecr.add_argument('--assetid', help=argparse.SUPPRESS, required=False)
        parser_ecr.add_argument('--assetname', help=argparse.SUPPRESS, required=False)
        parser_ecr.add_argument('--start_instance', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--repo', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--branch', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--type', choices=repo.SUPPORTED_TYPES, help=argparse.SUPPRESS)
        parser_ecr.add_argument('--level', help=argparse.SUPPRESS, choices=['shallow','deep'], default='shallow')
        parser_ecr.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--secrets_scan', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--enable_entropy', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--regex_rules_file', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--check_common_passwords', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--common_passwords_file', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--include_patterns', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--include_patterns_file', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--exclude_patterns', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--exclude_patterns_file', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--mask_secret', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--no_code', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--sast', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--iac_checks', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--ignore_comments', action='store_true', help=argparse.SUPPRESS)
        parser_ecr.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_ecr.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for Azure Container Registry container discovery 
        parser_acr = subparsers.add_parser ("acr", help = "Discover Azure Container Registry images")
        parser_acr.add_argument('--registry', help='The Azure Container Registry which needs to be inspected.')
        parser_acr.add_argument('--image', help='The fully qualified image name (with tag) which needs to be inspected. If tag is not given, latest will be determined and used.')
        parser_acr.add_argument('--tmp_dir', help='Temporary directory. Defaults to /tmp', required=False)
        parser_acr.add_argument('--containerid', help=argparse.SUPPRESS, required=False)
        parser_acr.add_argument('--assetid', help=argparse.SUPPRESS, required=False)
        parser_acr.add_argument('--assetname', help=argparse.SUPPRESS, required=False)
        parser_acr.add_argument('--start_instance', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--repo', help=argparse.SUPPRESS)
        parser_acr.add_argument('--branch', help=argparse.SUPPRESS)
        parser_acr.add_argument('--type', choices=repo.SUPPORTED_TYPES, help=argparse.SUPPRESS)
        parser_acr.add_argument('--level', help=argparse.SUPPRESS, choices=['shallow','deep'], default='shallow')
        parser_acr.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--secrets_scan', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--enable_entropy', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--regex_rules_file', help=argparse.SUPPRESS)
        parser_acr.add_argument('--check_common_passwords', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--common_passwords_file', help=argparse.SUPPRESS)
        parser_acr.add_argument('--include_patterns', help=argparse.SUPPRESS)
        parser_acr.add_argument('--include_patterns_file', help=argparse.SUPPRESS)
        parser_acr.add_argument('--exclude_patterns', help=argparse.SUPPRESS)
        parser_acr.add_argument('--exclude_patterns_file', help=argparse.SUPPRESS)
        parser_acr.add_argument('--mask_secret', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--no_code', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--sast', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--iac_checks', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--ignore_comments', action='store_true', help=argparse.SUPPRESS)
        parser_acr.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_acr.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for Google Cloud Registry container discovery 
        parser_gcr = subparsers.add_parser ("gcr", help = "Discover Google Cloud Registry images")
        group = parser_gcr.add_mutually_exclusive_group(required=True)
        group.add_argument('--location', help='The location (region / multi-region) of the repository.')
        group.add_argument('--repository', help='The GCR container/artifact registry URL which needs to be inspected.')
        group.add_argument('--image', help='The fully qualified image name (with tag / digest) which needs to be inspected. If tag / digest is not given, latest will be determined and used.')
        parser_gcr.add_argument('--tmp_dir', help='Temporary directory. Defaults to /tmp', required=False)
        parser_gcr.add_argument('--containerid', help=argparse.SUPPRESS, required=False)
        parser_gcr.add_argument('--assetid', help=argparse.SUPPRESS, required=False)
        parser_gcr.add_argument('--assetname', help=argparse.SUPPRESS, required=False)
        parser_gcr.add_argument('--start_instance', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--repo', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--branch', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--type', choices=repo.SUPPORTED_TYPES, help=argparse.SUPPRESS)
        parser_gcr.add_argument('--level', help=argparse.SUPPRESS, choices=['shallow','deep'], default='shallow')
        parser_gcr.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--secrets_scan', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--enable_entropy', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--regex_rules_file', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--check_common_passwords', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--common_passwords_file', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--include_patterns', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--include_patterns_file', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--exclude_patterns', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--exclude_patterns_file', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--mask_secret', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--no_code', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--sast', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--iac_checks', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--ignore_comments', action='store_true', help=argparse.SUPPRESS)
        parser_gcr.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_gcr.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for Oracle Container Registry discovery 
        parser_ocr = subparsers.add_parser ("ocr", help = "Discover Oracle Container Registry images")
        parser_ocr.add_argument('--region', help='The region identifier of the container registry.', required=True)
        parser_ocr.add_argument('--repository', help='The repository name which needs to be inspected.')
        parser_ocr.add_argument('--tmp_dir', help='Temporary directory. Defaults to /tmp', required=False)
        parser_ocr.add_argument('--config_file', help="Specify the OCI configuration file. Default value is '~/.oci/config'", required=False, default='~/.oci/config')
        parser_ocr.add_argument('--config_profile', help="Specify the profile in OCI configuration file. Default profile is 'DEFAULT'", required=False, default='DEFAULT')
        parser_ocr.add_argument('--containerid', help=argparse.SUPPRESS, required=False)
        parser_ocr.add_argument('--assetid', help=argparse.SUPPRESS, required=False)
        parser_ocr.add_argument('--assetname', help=argparse.SUPPRESS, required=False)
        parser_ocr.add_argument('--start_instance', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--repo', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--branch', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--type', choices=repo.SUPPORTED_TYPES, help=argparse.SUPPRESS)
        parser_ocr.add_argument('--level', help=argparse.SUPPRESS, choices=['shallow','deep'], default='shallow')
        parser_ocr.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--secrets_scan', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--enable_entropy', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--regex_rules_file', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--check_common_passwords', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--common_passwords_file', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--include_patterns', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--include_patterns_file', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--exclude_patterns', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--exclude_patterns_file', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--mask_secret', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--no_code', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--sast', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--iac_checks', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--ignore_comments', action='store_true', help=argparse.SUPPRESS)
        parser_ocr.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_ocr.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for docker discovery 
        parser_docker = subparsers.add_parser ("docker", help = "Discover docker instances")
        parser_docker.add_argument('--image', help='The docker image (repo:tag) which needs to be inspected. If tag is not given, "latest" will be assumed.')
        parser_docker.add_argument('--containerid', help='The container ID of a running docker container which needs to be inspected.')
        parser_docker.add_argument('--assetid', help=argparse.SUPPRESS)
        parser_docker.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_docker.add_argument('--tmp_dir', help='Temporary directory. Defaults to /tmp', default='/tmp')
        parser_docker.add_argument('--start_instance', action='store_true', help='If image inventory fails, try starting a container instance to inventory contents. Use with caution', required=False)
        parser_docker.add_argument('--repo', help=argparse.SUPPRESS)
        parser_docker.add_argument('--branch', help=argparse.SUPPRESS)
        parser_docker.add_argument('--type', choices=repo.SUPPORTED_TYPES, help=argparse.SUPPRESS)
        parser_docker.add_argument('--level', help=argparse.SUPPRESS, choices=['shallow','deep'], default='shallow')
        parser_docker.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--secrets_scan', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--enable_entropy', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--regex_rules_file', help=argparse.SUPPRESS)
        parser_docker.add_argument('--check_common_passwords', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--common_passwords_file', help=argparse.SUPPRESS)
        parser_docker.add_argument('--include_patterns', help=argparse.SUPPRESS)
        parser_docker.add_argument('--include_patterns_file', help=argparse.SUPPRESS)
        parser_docker.add_argument('--exclude_patterns', help=argparse.SUPPRESS)
        parser_docker.add_argument('--exclude_patterns_file', help=argparse.SUPPRESS)
        parser_docker.add_argument('--mask_secret', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--no_code', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--sast', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--iac_checks', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--ignore_comments', action='store_true', help=argparse.SUPPRESS)
        parser_docker.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_docker.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for Kubernetes discovery
        parser_k8s = subparsers.add_parser ("k8s", help = "Discover Kubernetes environment")
        group = parser_k8s.add_mutually_exclusive_group(required=True)
        group.add_argument('--deployment_yaml', help='Path to Kubernetes deployment manifest definition YAML file.')
        group.add_argument('--helm_chart', help='Specify the helm chart (folder, repo/chartname).')
        parser_k8s.add_argument('--tmp_dir', help='Temporary directory. Defaults to /tmp', required=False)
        parser_k8s.add_argument('--containerid', help=argparse.SUPPRESS, required=False)
        parser_k8s.add_argument('--assetid', help=argparse.SUPPRESS, required=False)
        parser_k8s.add_argument('--assetname', help=argparse.SUPPRESS, required=False)
        parser_k8s.add_argument('--start_instance', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--repo', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--branch', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--type', choices=repo.SUPPORTED_TYPES, help=argparse.SUPPRESS)
        parser_k8s.add_argument('--level', help=argparse.SUPPRESS, choices=['shallow','deep'], default='shallow')
        parser_k8s.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--secrets_scan', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--enable_entropy', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--regex_rules_file', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--check_common_passwords', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--common_passwords_file', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--include_patterns', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--include_patterns_file', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--exclude_patterns', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--exclude_patterns_file', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--mask_secret', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--no_code', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--sast', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--iac_checks', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--ignore_comments', action='store_true', help=argparse.SUPPRESS)
        parser_k8s.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_k8s.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for Repo discovery
        parser_repo = subparsers.add_parser ("repo", help = "Discover source code repository as asset")
        group = parser_repo.add_mutually_exclusive_group(required=True)
        group.add_argument('--repo', help='Local path or git repo url for project')
        parser_repo.add_argument('--branch', help='Optional branch of remote git repo')
        parser_repo.add_argument('--type', choices=repo.SUPPORTED_TYPES, help='Type of open source component to scan for. Defaults to all supported types if not specified', required=False)
        parser_repo.add_argument('--level', help='Possible values {shallow, deep}. Shallow restricts discovery to 1st level dependencies only. Deep discovers dependencies at all levels. Defaults to shallow discovery if not specified', choices=['shallow','deep'], required=False, default='shallow')
        parser_repo.add_argument('--include_unused_dependencies', action='store_true', default=True, help=argparse.SUPPRESS)
        #parser_repo.add_argument('--include_unused_dependencies', action='store_true', help='Include unused dependencies in the repository asset (applies to certain types of open source components only, may introduce false positives if used)')
        parser_repo.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
        parser_repo.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        # Switches related to secrets scan for repo
        parser_repo.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
        parser_repo.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
        parser_repo.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
        parser_repo.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
        parser_repo.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
        parser_repo.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
        parser_repo.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
        parser_repo.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
        parser_repo.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
        parser_repo.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWorx.')
        parser_repo.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWorx.')
        parser_repo.add_argument('--sast', action='store_true', help='Perform static code analysis on your source code')
        parser_repo.add_argument('--iac_checks', action='store_true', help='Perform security checks on IaC templates')
        parser_repo.add_argument('--ignore_comments', action='store_true', help='Ignore lines in source code containing comments for secrets scan')

        # Arguments required for GitHub Enterprise discovery
        parser_ghe = subparsers.add_parser ("github", help = "Discover GitHub Enterprise repositories as assets")
        parser_ghe.add_argument('--gh_identity', help='A valid GitHub Enterprise organization name or user name', required=True)
        parser_ghe.add_argument('--gh_access_token', help='A valid GitHub Enterprise token. Must have repo read permissions', required=True)
        parser_ghe.add_argument('--gh_api_url', help='Optional URL of your Github Enterprise API if self-hosted. Defaults to https://api.github.com', default='https://api.github.com')
        parser_ghe.add_argument('--repo', help=argparse.SUPPRESS)
        parser_ghe.add_argument('--branch', help=argparse.SUPPRESS)
        parser_ghe.add_argument('--type', choices=repo.SUPPORTED_TYPES, help='Type of open source component to scan for. Defaults to all supported types if not specified', required=False)
        parser_ghe.add_argument('--level', help='Possible values {shallow, deep}. Shallow restricts discovery to 1st level dependencies only. Deep discovers dependencies at all levels. Defaults to shallow discovery if not specified', choices=['shallow','deep'], required=False, default='shallow')
        parser_ghe.add_argument('--include_unused_dependencies', action='store_true', help='Include unused dependencies in the repository asset (applies to certain types of open source components only, may introduce false positives if used)')
        parser_ghe.add_argument('--assetid', help=argparse.SUPPRESS)
        parser_ghe.add_argument('--assetname', help=argparse.SUPPRESS)
        # Switches related to secrets scan for repo
        parser_ghe.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
        parser_ghe.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
        parser_ghe.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
        parser_ghe.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
        parser_ghe.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
        parser_ghe.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
        parser_ghe.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
        parser_ghe.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
        parser_ghe.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
        parser_ghe.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWorx.')
        parser_ghe.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWorx.')
        parser_ghe.add_argument('--sast', action='store_true', help='Perform static code analysis on your source code')
        parser_ghe.add_argument('--iac_checks', action='store_true', help='Perform security checks on IaC templates')
        parser_ghe.add_argument('--ignore_comments', action='store_true', help='Ignore lines in source code containing comments for secrets scan')

        # Arguments required for GitLab Enterprise discovery
        parser_gle = subparsers.add_parser ("gitlab", help = "Discover GitLab Enterprise repositories as assets")
        parser_gle.add_argument('--gl_access_token', help='A valid GitLab Enterprise token. Must have correct permissions to read repositories and metadata', required=True)
        parser_gle.add_argument('--gl_host', help='Optional FQDN of your GitLab Enterprise server if self-hosted. Defaults to gitlab.com', default='gitlab.com')
        parser_gle.add_argument('--repo', help=argparse.SUPPRESS)
        parser_gle.add_argument('--branch', help=argparse.SUPPRESS)
        parser_gle.add_argument('--type', choices=repo.SUPPORTED_TYPES, help='Type of open source component to scan for. Defaults to all supported types if not specified', required=False)
        parser_gle.add_argument('--level', help='Possible values {shallow, deep}. Shallow restricts discovery to 1st level dependencies only. Deep discovers dependencies at all levels. Defaults to shallow discovery if not specified', choices=['shallow','deep'], required=False, default='shallow')
        parser_gle.add_argument('--include_unused_dependencies', action='store_true', help='Include unused dependencies in the repository asset (applies to certain types of open source components only, may introduce false positives if used)')
        parser_gle.add_argument('--assetid', help=argparse.SUPPRESS)
        parser_gle.add_argument('--assetname', help=argparse.SUPPRESS)
        # Switches related to secrets scan for repo
        parser_gle.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
        parser_gle.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
        parser_gle.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
        parser_gle.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
        parser_gle.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
        parser_gle.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
        parser_gle.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
        parser_gle.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
        parser_gle.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
        parser_gle.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWorx.')
        parser_gle.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWorx.')
        parser_gle.add_argument('--sast', action='store_true', help='Perform static code analysis on your source code')
        parser_gle.add_argument('--iac_checks', action='store_true', help='Perform security checks on IaC templates')
        parser_gle.add_argument('--ignore_comments', action='store_true', help='Ignore lines in source code containing comments for secrets scan')

        # Arguments required for Bitbucket discovery
        parser_bb = subparsers.add_parser ("bitbucket", help = "Discover Bitbucket repositories as assets")
        parser_bb.add_argument('--bb_user', help='A valid Bitbucket user name to be used for authentication', required=True)
        parser_bb.add_argument('--bb_app_password', help='A valid Bitbucket app password. Must have correct permissions to read repositories and metadata', required=True)
        parser_bb.add_argument('--bb_repo_url', help='Bitbucket API repo URL for your workspace. Usually looks like "https://api.bitbucket.org/2.0/repositories/<myworkspace>" with your workspace name', required=True)
        parser_bb.add_argument('--repo', help=argparse.SUPPRESS)
        parser_bb.add_argument('--branch', help=argparse.SUPPRESS)
        parser_bb.add_argument('--type', choices=repo.SUPPORTED_TYPES, help='Type of open source component to scan for. Defaults to all supported types if not specified', required=False)
        parser_bb.add_argument('--level', help='Possible values {shallow, deep}. Shallow restricts discovery to 1st level dependencies only. Deep discovers dependencies at all levels. Defaults to shallow discovery if not specified', choices=['shallow','deep'], required=False, default='shallow')
        parser_bb.add_argument('--include_unused_dependencies', action='store_true', help='Include unused dependencies in the repository asset (applies to certain types of open source components only, may introduce false positives if used)')
        parser_bb.add_argument('--assetid', help=argparse.SUPPRESS)
        parser_bb.add_argument('--assetname', help=argparse.SUPPRESS)
        # Switches related to secrets scan for repo
        parser_bb.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
        parser_bb.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
        parser_bb.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
        parser_bb.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
        parser_bb.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
        parser_bb.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
        parser_bb.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
        parser_bb.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
        parser_bb.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
        parser_bb.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWorx.')
        parser_bb.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWorx.')
        parser_bb.add_argument('--sast', action='store_true', help='Perform static code analysis on your source code')
        parser_bb.add_argument('--iac_checks', action='store_true', help='Perform security checks on IaC templates')
        parser_bb.add_argument('--ignore_comments', action='store_true', help='Ignore lines in source code containing comments for secrets scan')

        # Arguments required for Azure Functions 
        parser_az_functions = subparsers.add_parser("azure_functions", help = "Discover and scan Azure Functions soure code")
        parser_az_functions.add_argument('--repo', help=argparse.SUPPRESS)
        parser_az_functions.add_argument('--branch', help=argparse.SUPPRESS)
        parser_az_functions.add_argument('--type', help=argparse.SUPPRESS)
        parser_az_functions.add_argument('--level', help=argparse.SUPPRESS, default='shallow')
        parser_az_functions.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_az_functions.add_argument('--assetid', help=argparse.SUPPRESS)
        parser_az_functions.add_argument('--assetname', help=argparse.SUPPRESS)
        # Switches related to secrets scan for repo
        parser_az_functions.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
        parser_az_functions.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
        parser_az_functions.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
        parser_az_functions.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
        parser_az_functions.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
        parser_az_functions.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
        parser_az_functions.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
        parser_az_functions.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
        parser_az_functions.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
        parser_az_functions.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWorx.')
        parser_az_functions.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWorx.')
        parser_az_functions.add_argument('--sast', action='store_true', help='Perform static code analysis on your source code')
        parser_az_functions.add_argument('--iac_checks', action='store_true', help='Perform security checks on IaC templates')
        parser_az_functions.add_argument('--ignore_comments', action='store_true', help='Ignore lines in source code containing comments for secrets scan')

        # Arguments required for Google Cloud Functions 
        parser_gcloud_functions = subparsers.add_parser("gcloud_functions", help = "Discover and scan Google Cloud Functions soure code")
        parser_gcloud_functions.add_argument('--projects', help='A comma separated list of GCP project IDs', required=True)
        parser_gcloud_functions.add_argument('--repo', help=argparse.SUPPRESS)
        parser_gcloud_functions.add_argument('--branch', help=argparse.SUPPRESS)
        parser_gcloud_functions.add_argument('--type', help=argparse.SUPPRESS)
        parser_gcloud_functions.add_argument('--level', help=argparse.SUPPRESS, default='shallow')
        parser_gcloud_functions.add_argument('--include_unused_dependencies', action='store_true', help=argparse.SUPPRESS)
        parser_gcloud_functions.add_argument('--assetid', help=argparse.SUPPRESS)
        parser_gcloud_functions.add_argument('--assetname', help=argparse.SUPPRESS)
        parser_gcloud_functions.add_argument('--secrets_scan', action='store_true', help='Perform a scan to look for secrets in the code')
        parser_gcloud_functions.add_argument('--enable_entropy', action='store_true', help='Identify entropy based secrets')
        parser_gcloud_functions.add_argument('--regex_rules_file', help='Path to JSON file specifying regex rules')
        parser_gcloud_functions.add_argument('--check_common_passwords', action='store_true', help='Look for top common passwords.')
        parser_gcloud_functions.add_argument('--common_passwords_file', help='Specify your own common passwords file. One password per line in file')
        parser_gcloud_functions.add_argument('--include_patterns', help='Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.')
        parser_gcloud_functions.add_argument('--include_patterns_file', help='Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.')
        parser_gcloud_functions.add_argument('--exclude_patterns', help='Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.')
        parser_gcloud_functions.add_argument('--exclude_patterns_file', help='Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.')
        parser_gcloud_functions.add_argument('--mask_secret', action='store_true', help='Mask identified secret before storing for reference in ThreatWorx.')
        parser_gcloud_functions.add_argument('--no_code', action='store_true', help='Disable storing code for reference in ThreatWorx.')
        parser_gcloud_functions.add_argument('--sast', action='store_true', help='Perform static code analysis on your source code')
        parser_gcloud_functions.add_argument('--iac_checks', action='store_true', help='Perform security checks on IaC templates')
        parser_gcloud_functions.add_argument('--ignore_comments', action='store_true', help='Ignore lines in source code containing comments for secrets scan')

        # Arguments required for Host discovery on Linux
        parser_linux = subparsers.add_parser ("host", help = "Discover linux host assets")
        #parser_linux.add_argument('--remote_hosts_csv', help='CSV file containing details of remote hosts. CSV file column header [1st row] should be: hostname,userlogin,userpwd,privatekey,assetid,assetname. Note "hostname" column can contain hostname, IP address, CIDR range.', help=argparse.SUPPRESS)
        parser_linux.add_argument('--remote_hosts_csv', help=argparse.SUPPRESS)
        parser_linux.add_argument('--host_list', help='A file (currently in CSV format) containing details of remote hosts. CSV file column header [1st row] should be: hostname,userlogin,userpwd,privatekey,assetid,assetname. Note "hostname" column can contain hostname, IP address, CIDR range.')
        parser_linux.add_argument('--secure', action='store_true', help='Use this option to encrypt clear text passwords in the host list file')
        parser_linux.add_argument('--password', help='A password used to encrypt / decrypt login information from the host list file')
        parser_linux.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
        parser_linux.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_linux.add_argument('--no_ssh_audit', action='store_true', help='Skip ssh audit')
        parser_linux.add_argument('--no_host_benchmark', action='store_true', help='Skip host benchmark audit')
        parser_linux.add_argument('--check_vuln', action='append', help='Run plugin to detect impact of specified vulnerabilities. You can use this option multiple times to specify multiple vulnerabilities')
        parser_linux.add_argument('--check_all_vulns', action='store_true', help='Run plugins to detect impact of all vulnerabilities')

        # Arguments required for Host discovery on Windows
        parser_win = subparsers.add_parser ("win_host", help = "Discover Windows host assets (requires WinRM / PS Remoting to be enabled)")
        parser_win.add_argument('--host_list', help='A file (currently in CSV format) containing details of remote hosts. CSV file column header [1st row] should be: hostname,userlogin,userpwd,privatekey,assetid,assetname. Note "hostname" column can contain hostname, IP address, CIDR range.')
        parser_win.add_argument('--secure', action='store_true', help='Use this option to encrypt clear text passwords in the host list file')
        parser_win.add_argument('--password', help='A password used to encrypt / decrypt login information from the host list file')

        # Arguments required for vmware discovery
        parser_vmware = subparsers.add_parser ("vmware", help = "Discover VMware vCenter/ESX assets")
        parser_vmware.add_argument('--host', help='A vCenter host name or IP', required=True)
        parser_vmware.add_argument('--user', help='A vCenter user name', required=True)
        parser_vmware.add_argument('--password', help='Password for the vCenter user. Note this can be set as "VCENTER_PASSWD" environment variable')

        # Arguments required for nmap discovery
        parser_nmap = subparsers.add_parser ("nmap", help = "Discover endpoints and services as assets using nmap")
        parser_nmap.add_argument('--hosts', help='Hostname, IP address or CIDR range. Multiple values should be comma separated')
        parser_nmap.add_argument('--services', nargs='+', choices=['web', 'database', 'os', 'vmware', 'printers', 'cctv'], help='Specify what class of services / devices you want to scan', default='web')
        parser_nmap.add_argument('--extra_ports', help='List of comma separated ports that you would like to include in the scans in addition to the standard service ports e.g. 444,9000-9100,...')
        parser_nmap.add_argument('--timing', help=argparse.SUPPRESS, default='5')
        parser_nmap.add_argument('--discovery_scan_type', help=argparse.SUPPRESS)
        parser_nmap.add_argument('--discovery_port_list', help=argparse.SUPPRESS)
        parser_nmap.add_argument('--no_ssh_audit', action='store_true', help='Skip ssh audit')
        parser_nmap.add_argument('--include_info', help=argparse.SUPPRESS, action='store_true')
        
        # Arguments required for SBOM-based discovery
        parser_sbom = subparsers.add_parser("sbom", help = "Ingest asset inventory from SBOM (Software Bill Of Materials)")
        parser_sbom.add_argument('--input', help='Absolute path to SBOM artifact', required=True)
        parser_sbom.add_argument('--standard', choices=sbom.SUPPORTED_SBOM_STANDARDS, help='Specifies SBOM standard.', required=True)
        all_formats = set()
        for std in sbom.SUPPORTED_SBOM_FORMATS_FOR_STANDARD:
            for f in sbom.SUPPORTED_SBOM_FORMATS_FOR_STANDARD[std]:
                all_formats.add(f)
        all_formats = list(all_formats)
        parser_sbom.add_argument('--format', choices=all_formats, help='Specifies format of SBOM artifact.', required=True)
        parser_sbom.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=False)
        parser_sbom.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_sbom.add_argument('--comment', help='Specify user comment for SBOM')

        # Arguments required for ServiceNow discovery
        parser_snow = subparsers.add_parser ("servicenow", help = "Ingest inventory from ServiceNow CMDB")
        parser_snow.add_argument('--snow_instance', help='ServiceNow Instance name', required=True)
        exclusive_group = parser_snow.add_mutually_exclusive_group(required=True)
        exclusive_group.add_argument('--snow_client_id', help='Client ID for OAuth')
        exclusive_group.add_argument('--snow_user', help='User name of ServiceNow account')
        exclusive_group = parser_snow.add_mutually_exclusive_group(required=True)
        exclusive_group.add_argument('--snow_client_secret', help='Client secret for OAuth')
        exclusive_group.add_argument('--snow_user_pwd', help='User password of ServiceNow account')
        parser_snow.add_argument('--enable_tracking_tags', action='store_true', help='Enable recording ServiceNow specific information (like ServiceNow instance name, etc.) as asset tags', required=False)

        # Arguments required for ssl audit 
        parser_website = subparsers.add_parser ("webapp", help = "Discover and test web application for vulnerabilities and misconfigurations. Includes OS/Service fingerprinting, SSL audit and DAST using zaproxy")
        parser_website.add_argument('--url', help='URL')
        parser_website.add_argument('--planfile', help='ZAP automation plan file')
        parser_website.add_argument('--assetname', help='Optional name/label to be assigned to the web URL asset')
        parser_website.add_argument('--include_info', help=argparse.SUPPRESS, action='store_true')
        parser_website.add_argument('--no_ssh_audit', action='store_true', help='Skip ssh audit')
        parser_website.add_argument('--no_ssl_audit', action='store_true', help='Skip ssl audit')
        parser_website.add_argument('--timing', help=argparse.SUPPRESS, default='5')
        parser_website.add_argument('--discovery_scan_type', help=argparse.SUPPRESS)
        parser_website.add_argument('--discovery_port_list', help=argparse.SUPPRESS)
        parser_website.add_argument('--services', help=argparse.SUPPRESS)
        parser_website.add_argument('--extra_ports', help=argparse.SUPPRESS)
 
        # Arguments required for AWS CIS benchmarks
        parser_aws_cis = subparsers.add_parser ("aws_cis", help = "Run AWS CIS benchmarks")
        parser_aws_cis.add_argument('--aws_access_key', help='AWS access key', required=True)
        parser_aws_cis.add_argument('--aws_secret_key', help='AWS secret key', required=True)
        parser_aws_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_aws_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_aws_cis.add_argument('--prowler_home', help='Location of cloned prowler github repo. Defaults to /usr/share/prowler', default='/usr/share/prowler')

        # Arguments required for AWS Audit Checks 
        parser_aws_audit = subparsers.add_parser ("aws_audit", help = "Run AWS audit checks including PCI, GDPR, HIPAA")
        parser_aws_audit.add_argument('--aws_access_key', help='AWS access key', required=True)
        parser_aws_audit.add_argument('--aws_secret_key', help='AWS secret key', required=True)
        parser_aws_audit.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_aws_audit.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_aws_audit.add_argument('--prowler_home', help='Location of cloned prowler github repo. Defaults to /usr/share/prowler', default='/usr/share/prowler')


        # Arguments required for Azure CIS benchmarks
        parser_az_cis = subparsers.add_parser("azure_cis", help = "Run Azure CIS benchmarks")
        parser_az_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_az_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')

        # Arguments required for GCP CIS benchmarks
        parser_gcp_cis = subparsers.add_parser("gcp_cis", help = "Run Google Cloud Platform CIS benchmarks")
        parser_gcp_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_gcp_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_gcp_cis.add_argument('--projects', help='A comma separated list of GCP project IDs to run the checks against')
        parser_gcp_cis.add_argument('--expanded', action='store_true', help='Create separate issue for each violation')
        parser_gcp_cis.add_argument('--custom_ratings', help='Specify JSON file which provides custom ratings for GCP CIS benchmark tests')

        # Arguments required for Oracle Cloud Infrastructure (OCI) CIS benchmarks
        parser_oci_cis = subparsers.add_parser("oci_cis", help = "Run Oracle Cloud Infrastructure CIS benchmarks")
        parser_oci_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_oci_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_oci_cis.add_argument('--no_obp', action='store_true', help='Do not run Oracle Best Practice checks')
        parser_oci_cis.add_argument('--config_file', help="Specify the OCI configuration file. Default value is '~/.oci/config'", required=False, default='~/.oci/config')
        parser_oci_cis.add_argument('--config_profile', help="Specify the profile in OCI configuration file. Default profile is 'DEFAULT'", required=False, default='DEFAULT')

        # Arguments required for docker CIS benchmarks 
        parser_docker_cis = subparsers.add_parser ("docker_cis", help = "Run docker CIS benchmarks")
        parser_docker_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset')
        parser_docker_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_docker_cis.add_argument('--docker_bench_home', help='Location of docker bench CLI. Defaults to /usr/share/docker-bench-security', default='/usr/share/docker-bench-security')

        # Arguments required for K8S CIS benchmarks 
        parser_k8s_cis = subparsers.add_parser ("k8s_cis", help = "Run Kubernetes CIS benchmarks")
        parser_k8s_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_k8s_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_k8s_cis.add_argument('--target', help='Run test against Kubernetes master or worker nodes', choices=['master','worker'], required=True)
        parser_k8s_cis.add_argument('--custom_ratings', help='Specify JSON file which provides custom ratings for Kubernetes CIS benchmarks')

        # Arguments required for GKE CIS benchmarks 
        parser_gke_cis = subparsers.add_parser ("gke_cis", help = "Run GKE CIS benchmarks")
        parser_gke_cis.add_argument('--assetid', help='A unique ID to be assigned to the discovered asset', required=True)
        parser_gke_cis.add_argument('--assetname', help='A name/label to be assigned to the discovered asset')
        parser_gke_cis.add_argument('--target', help='Run test against GKE master or worker nodes', choices=['master','worker'], required=True)
        parser_gke_cis.add_argument('--custom_ratings', help='Specify JSON file which provides custom ratings for Kubernetes CIS benchmarks')

        # Arguments required for O365 / defender discovery
        parser_o365 = subparsers.add_parser ("o365", help = "Ingest inventory from Microsoft Office 365 / Defender")
        parser_o365.add_argument('--tenant_id', help='O365 Tenant ID', required=True)
        parser_o365.add_argument('--application_id', help='O365 Application ID', required=True)
        parser_o365.add_argument('--application_key', help='O365 Application Key', required=True)
        parser_o365.add_argument('--all', help='Inventory all active devices. Default behavior is to inventory active high risk score devices', action='store_true')

        # Arguments required for Cisco Meraki discovery
        parser_meraki = subparsers.add_parser ("meraki", help = "Discover network devices from Cisco Meraki")
        parser_meraki.add_argument('--base_url', help='Base URL for Meraki console. Defaults to https://api.meraki.com/v1', required=False, default='https://api.meraki.com/v1')
        parser_meraki.add_argument('--api_key', help='Meraki API Key', required=True)

        # Arguments required for Cisco DNA Center / Catalyst Center discovery
        parser_dna_center = subparsers.add_parser ("dna_center", help = "Discover network devices from Cisco DNA Center a.k.a Catalyst Center")
        parser_dna_center.add_argument('--url', help='Base URL DNA Center', required=True)
        parser_dna_center.add_argument('--user', help='User name for basic authentication', required=True)
        parser_dna_center.add_argument('--password', help='Password for basic authentication', required=True)

        args = parser.parse_args()
        if args.out is not None:
            args.sbom  = args.out

        lfn_suffix = args.run_id if args.run_id is not None else args.mode
        logfilename = "twigs_%s.log" % lfn_suffix

        logging_level = logging.WARNING
        if args.verbosity >= 1:
            logging_level = logging.INFO
        if args.verbosity >= 2:
            logging_level = logging.DEBUG
        if args.quiet:
            logging_level = logging.ERROR
        # Setup the logger
        logging.basicConfig(filename=logfilename, level=logging_level, filemode='w', format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
        console = logging.StreamHandler()
        console.setLevel(logging_level)
        console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
        logging.getLogger('').addHandler(console)

        # In insecure mode, we want to set verify=False for requests
        if args.insecure or args.nosslverify:
            utils.set_requests_verify(False)

        logging.info('Started new run')
        logging.debug('Arguments: %s', str(args))

        if args.mode == "login":
            login_user(args)
        elif args.mode == "logout":
            logout_user(args)

        logged_in_user_dict = { }

        if args.test:
            args.handle = "DUMMY-HANDLE "
            args.token = "DUMMY_TOKEN"
            args.instance = "threatworx.io" 

        if args.handle is None:
            logged_in_user_dict = get_logged_in_user_details()
            temp = logged_in_user_dict.get('handle')
            if temp is None:
                temp = os.environ.get('TW_HANDLE')
                if temp is None:
                    logging.error('Error: Missing "--handle" argument, user not logged in twigs and "TW_HANDLE" environment variable is not set as well')
                    sys.exit(1)
                logging.info('Using handle specified in "TW_HANDLE" environment variable')
            else:
                logging.info('Using handle of logged in user')
            args.handle = temp

        if args.token is None:
            temp = logged_in_user_dict.get('token')
            if temp is None:
                temp = os.environ.get('TW_TOKEN')
                if temp is not None:
                    logging.info('Using token specified in "TW_TOKEN" environment variable')
            else:
                logging.info('Using token of logged in user')
            args.token = temp

        if args.token is None and args.apply_policy is not None:
            logging.error('Error: Policy cannot be applied since "--token" argument is missing and "TW_TOKEN" environment variable is not set as well!')
            sys.exit(1)

        if args.instance is None:
            temp = logged_in_user_dict.get('instance')
            if temp is None:
                temp = os.environ.get('TW_INSTANCE')
                if temp is not None:
                    logging.info('Using instance specified in "TW_INSTANCE" environment variable')
                    args.instance = temp
                elif args.token is not None:
                    # missing instance but token is specified
                    logging.error('Error: Missing "--instance" argument and "TW_INSTANCE" environment variable is not set as well')
                    sys.exit(1)
            else:
                logging.info('Using instance of logged in user')
                args.instance = temp

#    if args.purge_assets == True and args.email_report == False:
#        logging.error('Purge assets option (--purge_assets) is used with Email report (--email_report)')
#        sys.exit(1)

        if (args.token is None or len(args.token) == 0) and args.sbom is None:
            logging.error('[token] argument is not specified and [out] argument is not specified. Unable to share discovered assets.')
            sys.exit(1)

        if sys.platform != 'win32' and args.schedule is not None:
            from crontab import CronSlices
            # validate schedule
            if CronSlices.is_valid(args.schedule) == False:
                logging.error("Error: Invalid cron schedule [%s] specified!" % args.schedule)
                sys.exit(1)

        utils.set_run_args(args)
        response = utils.create_new_tool_run_record()
        if not args.test:
            if response is not None and response.status_code != 200:
                logging.error("Could not create run record")
                utils.tw_exit(1)

        assets = []
        if args.mode == 'aws':
            assets = aws.get_inventory(args)
        elif args.mode == 'azure':
            assets = azure.get_inventory(args)
        elif args.mode == 'gcp':
            assets = gcp.get_inventory(args)
        elif args.mode == 'oci':
            assets = oci.get_inventory(args)
        elif args.mode == 'o365':
            assets = o365.get_inventory(args)
        elif args.mode == 'acr':
            assets = acr.get_inventory(args)
        elif args.mode == 'ecr':
            assets = ecr.get_inventory(args)
        elif args.mode == 'gcr':
            assets = gcr.get_inventory(args)
        elif args.mode == 'ocr':
            assets = ocr.get_inventory(args)
        elif args.mode == 'servicenow':
            assets = servicenow.get_inventory(args)
        elif args.mode == 'repo':
            assets = repo.get_inventory(args)
        elif args.mode == "github":
            assets = repo.get_inventory(args)
            add_asset_tags(assets, ["REPO_TYPE:github"])
        elif args.mode == "gitlab":
            assets = repo.get_inventory(args)
            add_asset_tags(assets, ["REPO_TYPE:gitlab"])
        elif args.mode == "bitbucket":
            assets = repo.get_inventory(args)
            add_asset_tags(assets, ["REPO_TYPE:bitbucket"])
        elif args.mode == 'host':
            assets = linux.get_inventory(args)
        elif args.mode == 'win_host':
            assets = windows.get_inventory(args)
        elif args.mode == 'vmware':
            assets = vmware.get_inventory(args)
        elif args.mode == 'nmap':
            assets = fingerprint.get_inventory(args)
        elif args.mode == 'docker':
            assets = docker.get_inventory(args)
        elif args.mode == 'k8s':
            assets = kubernetes.get_inventory(args)
        elif args.mode == 'meraki':
            assets = meraki.get_inventory(args)
        elif args.mode == 'dna_center':
            assets = dna_center.get_inventory(args)
        elif args.mode == 'sbom':
            ret_code, asset_ids_list = sbom.upload_sbom(args)
            if ret_code and asset_ids_list is not None:
                exit_code, pj_json = check_and_run_policy_job(args, asset_ids_list)
                if exit_code is not None:
                    logging.info("Exiting with code [%s] based on policy evaluation", exit_code)
                    utils.update_tool_run_record('SUCCESS')
                    sys.exit(int(exit_code))
                else:
                    utils.tw_exit(0)
            else:
                utils.tw_exit(1)
        elif args.mode == 'dast':
            assets = dast.get_inventory(args)
        elif args.mode == 'docker_cis':
            assets = docker_cis.get_inventory(args)
        elif args.mode == 'aws_cis':
            assets = aws_cis.get_inventory(args)
        elif args.mode == 'aws_audit':
            assets = aws_cis.get_inventory(args, True)
        elif args.mode == 'azure_cis':
            assets = azure_cis.get_inventory(args)
        elif args.mode == 'gcp_cis':
            assets = gcp_cis.get_inventory(args)
        elif args.mode == 'oci_cis':
            assets = oci_cis.get_inventory(args)
        elif args.mode == 'k8s_cis':
            assets = k8s_cis.get_inventory(args, 'k8s')
        elif args.mode == 'gke_cis':
            assets = k8s_cis.get_inventory(args, 'gke')
        elif args.mode == 'azure_functions':
            assets = azure_functions.get_inventory(args)
        elif args.mode == 'gcloud_functions':
            assets = gcloud_functions.get_inventory(args)
        elif args.mode == 'webapp':
            assets = website.get_inventory(args)

        exit_code = None
        run_status = 'SUCCESS'
        if args.mode != 'host' or args.secure == False:
            if assets is None or len(assets) == 0:
                logging.info("No assets found!")
                run_status = 'WARNING'
            else:
                """
                if args.asset_criticality is not None:
                    add_asset_criticiality_tag(assets, args.asset_criticality)
                """

                add_attack_surface_label(args, assets)

                if args.no_auto_tags:
                    remove_standard_tags(assets)

                if args.tag_critical:
                    add_asset_criticality_tag(assets, '5')

                if args.tag:
                    add_asset_tags(assets, args.tag)

                if args.owner:
                    add_asset_owners(assets, args.owner)

                if args.location:
                    add_asset_location(assets, args.location)

                timestamp = int(time.time())
                if args.mode != "sbom":
                    # SBOM assets will have their own timestamp
                    add_asset_timestamp(assets, timestamp)

                if args.sbom is not None:
                    export_assets_to_sbom_file(assets, timestamp, args)

                if args.token is not None and len(args.token) > 0:
                    asset_id_list, quick_scan_asset_id_list, full_scan_asset_id_list = push_assets_to_TW(assets, args)
                    exit_code, pj_json = check_and_run_policy_job(args, asset_id_list)
                    run_va_lic_eol_scan(quick_scan_asset_id_list, full_scan_asset_id_list, pj_json, args)
                    #run_remediation_scan(asset_id_list, args)
            
                if args.schedule is not None and sys.platform != 'win32':
                    from crontab import CronTab
                    # create/update cron job
                    cron_cmd = sys.argv[0]
                    if "--handle" not in sys.argv:
                        cron_cmd = cron_cmd + " " + "--handle " + '"' + args.handle + '"'
                    if "--token" not in sys.argv:
                        cron_cmd = cron_cmd + " " + "--token " + '"' + args.token + '"'
                    if "--instance" not in sys.argv:
                        cron_cmd = cron_cmd + " " + "--instance " + '"' + args.instance + '"'
                    skip_next = False
                    for index in range(1, len(sys.argv)):
                        if sys.argv[index] == "--schedule":
                            skip_next = True
                            continue
                        if skip_next:
                            skip_next = False
                            continue
                        if sys.argv[index].startswith('-'):
                            cron_cmd = cron_cmd + " " + sys.argv[index]
                        else:
                            cron_cmd = cron_cmd + " " + '"' + sys.argv[index] + '"'
                    cron_comment = "TWIGS_" + args.mode
                    with CronTab(user=True) as user_cron:
                        # Find any existing jobs and remove those
                        ejobs = user_cron.find_comment(cron_comment)
                        for ejob in ejobs:
                            user_cron.remove(ejob)
                        njob = user_cron.new(command=cron_cmd, comment=cron_comment)
                        njob.setall(args.schedule)
                        logging.info("Added to crontab with comment [%s]", cron_comment)

        logging.info('Run completed')

        # check for upgrade
        latest_version = utils.get_latest_version()
        if __version__ != latest_version:
            logging.warning('You are using twigs version '+__version__+'; however version '+latest_version+' is available.')
            logging.warning('You should consider upgrading via the "pip install twigs --upgrade" command.')

        if exit_code is not None:
            logging.info("Exiting with code [%s] based on policy evaluation", exit_code)
            utils.update_tool_run_record(run_status)
            sys.exit(int(exit_code))

        utils.update_tool_run_record(run_status)
    except Exception as e:
        logging.error("Something went wrong with this twigs run")
        st = traceback.format_exc()
        logging.error("Exception trace details: %s", st)
        utils.tw_exit(1)

if __name__ == '__main__':
    main()
