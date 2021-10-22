import sys
import subprocess
import json
import logging

# Some global variables here
_projects = None
_organizations = None
_folders = None
_iam_policies_by_projects = None
_compute_instances_by_projects = None
_services_by_projects = None

_encoding = None
_expanded_issues = None
_custom_ratings_dict = None

def set_encoding(encoding):
    global _encoding
    _encoding = encoding

def get_encoding():
    global _encoding
    return _encoding

def set_expanded(expanded):
    global _expanded_issues
    _expanded_issues = expanded

def get_expanded():
    global _expanded_issues
    return _expanded_issues

def set_custom_ratings(custom_ratings_dict):
    global _custom_ratings_dict
    _custom_ratings_dict = custom_ratings_dict

def get_custom_ratings():
    global _custom_ratings_dict
    return _custom_ratings_dict

def run_cmd(cmd):
    try:
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
    except subprocess.CalledProcessError:
        logging.error("Error running command [%s]", cmd)
        cmd_output = ""
    return cmd_output

def run_gcloud_cmd(cmd):
    cmd = 'gcloud ' + cmd + ' --format=json --quiet'
    try:
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
        ret_json = json.loads(cmd_output)
    except subprocess.CalledProcessError:
        logging.error("Error running gcloud command [%s]", cmd)
        ret_json = { }
    except ValueError:
        logging.error("Error parsing JSON output for gcloud command [%s]: %s", cmd, cmd_output)
        ret_json = { }
    return ret_json

# details param is a 3 value tuple as follows (msg, list of twc_id values, resource id)
def create_issue(twc_id, twc_title, details, rating, object_id, object_meta):
    issues = []
    custom_ratings_dict = get_custom_ratings()
    if custom_ratings_dict is not None:
        test_id = twc_id.split('-')[4]
        custom_rating = custom_ratings_dict.get(test_id)
        rating = custom_rating if custom_rating is not None else rating
    if get_expanded() == True:
        for detail in details:
            issues.append(create_issue_helper(twc_id + '_' + "_".join(detail[1]), twc_title, detail[0], rating, detail[2], ''))
    else:
        consolidated_details = ''
        for detail in details:
            if consolidated_details != '':
                consolidated_details = consolidated_details + "\n"
            consolidated_details = consolidated_details + detail[0]
        issues.append(create_issue_helper(twc_id, twc_title, consolidated_details, rating, object_id, object_meta))
    return issues

def create_issue_helper(twc_id, twc_title, details, rating, object_id, object_meta):
    issue = { }
    issue['twc_id'] = twc_id
    issue['twc_title'] = twc_title
    issue['details'] = details
    issue['rating'] = rating
    issue['object_id'] = object_id
    issue['object_meta'] = object_meta
    issue['type'] = 'GCP CIS'
    return issue

def append_issue(config_issues, issue):
    if issue is not None:
        config_issues.extend(issue)

# Get all projects
def get_all_projects():
    global _projects
    if _projects is not None:
        return _projects
    _projects = []
    out_json = run_gcloud_cmd('projects list')
    for p in out_json:
        _projects.append(p['projectId'])
    return _projects

# Get all organizations
def get_all_organizations():
    global _organizations
    if _organizations is not None:
        return _organizations
    _organizations = []
    out_json = run_gcloud_cmd('organizations list')
    for o in out_json:
        org_name = o['name']
        org_id = org_name.split('/')[-1]
        _organizations.append(org_id)
    return _organizations

def _add_sub_folders(folder, folders):
    out_json = run_gcloud_cmd("resource-manager folders list --folder=%s" % folder)
    for f in out_json:
        folders.append(f['folderId'])
        add_sub_folders(f['folderId'], folders)

# List all folders
def get_all_folders():
    global _folders
    if _folders is not None:
        return _folders
    _folders = []
    orgs = get_all_organizations()
    for o in orgs:
        out_json = run_gcloud_cmd("resource-manager folders list --organization=%s" % o)
        for f in out_json:
            folders.append(f['folderId'])
            # Get sub-folders if any
            _add_sub_folders(f['folderId'], folders)
    return _folders

def get_iam_policies_by_projects():
    global _iam_policies_by_projects
    if _iam_policies_by_projects is not None:
        return _iam_policies_by_projects
    _iam_policies_by_projects = { }
    projects = get_all_projects()
    for p in projects:
        out_json = run_gcloud_cmd("projects get-iam-policy %s" % p)
        _iam_policies_by_projects[p] = out_json
    return _iam_policies_by_projects

def get_compute_instances_by_projects():
    global _compute_instances_by_projects
    if _compute_instances_by_projects is not None:
        return _compute_instances_by_projects
    _compute_instances_by_projects = { }
    projects = get_compute_enabled_projects()
    for p in projects:
        out_json = run_gcloud_cmd("compute instances list --project=%s" % p)
        _compute_instances_by_projects[p] = out_json
    return _compute_instances_by_projects

def get_compute_instances_with_os_inventory_by_projects():
    compute_instances_by_projects = { }
    projects = get_compute_enabled_projects()
    for p in projects:
        out_json = run_gcloud_cmd("compute instances os-inventory --project=%s list-instances" % p)
        compute_instances_by_projects[p] = out_json
    return compute_instances_by_projects

def add_members_with_role(entry, role, add_to_set):
    if entry['role'] == role:
        for m in entry['members']:
            if m.startswith('user:'):
                add_to_set.add(m.split(':')[1])

def _get_services_by_projects():
    global _services_by_projects
    if _services_by_projects is not None:
        return _services_by_projects
    _services_by_projects = { }
    projects = get_all_projects()
    for p in projects:
        out_json = run_gcloud_cmd("services list --project=%s" % p)
        _services_by_projects[p] = out_json
    return _services_by_projects

def _get_projects_with_service_enabled(service):
    ret_projects = []
    services_by_projects = _get_services_by_projects()
    for p in services_by_projects.keys():
        out_json = services_by_projects[p]
        for entry in out_json:
            if entry['name'].endswith(service) and entry['state'] == "ENABLED":
                ret_projects.append(p)
    return ret_projects

def get_cloud_kms_enabled_projects():
    return _get_projects_with_service_enabled("cloudkms.googleapis.com")

def get_logging_enabled_projects():
    return _get_projects_with_service_enabled("logging.googleapis.com")

def get_compute_enabled_projects():
    return _get_projects_with_service_enabled("compute.googleapis.com")

def get_dns_enabled_projects():
    return _get_projects_with_service_enabled("dns.googleapis.com")

def get_bigquery_enabled_projects():
    return _get_projects_with_service_enabled("bigquery.googleapis.com")

def check_database_flag(dbtype, flag, value, details_msg):
    details = []
    projects = get_all_projects()
    for p in projects:
        out_json = run_gcloud_cmd("sql instances list --project=%s --filter='DATABASE_VERSION:%s'" % (p, dbtype))
        for entry in out_json:
            flag_set = False
            db_flags = entry['settings'].get('databaseFlags')
            if db_flags is not None:
                for db_flag in db_flags:
                    if db_flag['name'] == flag and (value is None or db_flag['value'] == value):
                        flag_set = True
                        break
            if flag_set == False:
                details.append((details_msg % (entry['name'], p), [entry['name'], p, dbtype, flag], entry['name']))
    return details

