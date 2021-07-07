import sys
import json
import logging
from . import gcp_cis_utils as gcp_cis_utils

def check5_1():
    # 5.1 Ensure that Cloud Storage bucket is not anonymously or publicly accessible (Scored)

    logging.info("5.1 Ensure that Cloud Storage bucket is not anonymously or publicly accessible (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        output = gcp_cis_utils.run_cmd("gsutil ls -p %s 2>/dev/null" % p)
        for bucket in output.splitlines():
            out_json = gcp_cis_utils.run_cmd("gsutil iam get %s 2>/dev/null" % bucket)
            try:
                out_json = json.loads(out_json) 
                bindings = out_json.get('bindings')
            except ValueError:
                logging.warn("Unable to load response JSON in Cloud Storage bucket access check...")
                bindings = None
            if bindings is not None:
                for entry in out_json['bindings']:
                    if "allUsers" in entry['members'] or "allAuthenticatedUsers" in entry['members']:
                        details.append(("Cloud Storage bucket [%s] in project [%s] is anonymously or publicly accessible" % (bucket, p), [bucket, p], bucket))
                        break
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-5.1', '5.1 [Level 1] Ensure that Cloud Storage bucket is not anonymously or publicly accessible (Scored)', details, '4', '', '')
    return None

def check5_2():
    # 5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled (Scored)

    logging.info("5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        output = gcp_cis_utils.run_cmd("gsutil ls -p %s 2>/dev/null" % p)
        for bucket in output.splitlines():
            output_2 = gcp_cis_utils.run_cmd("gsutil uniformbucketlevelaccess get %s 2>/dev/null" % bucket)
            if "\n  Enabled: False\n" in output_2:
                details.append(("Cloud Storage bucket [%s] in project [%s] does not have uniform bucket-level access enabled" % (bucket, p), [bucket, p], bucket))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-5.2', '5.2 [Level 2] Ensure that Cloud Storage buckets have uniform bucket-level access enabled (Scored)', details, '5', '', '')
    return None

def run_checks():
    config_issues = []
    gcp_cis_utils.append_issue(config_issues, check5_1())
    gcp_cis_utils.append_issue(config_issues, check5_2())
    return config_issues

