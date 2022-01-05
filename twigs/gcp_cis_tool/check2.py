import sys
import re
import logging
from . import gcp_cis_utils as gcp_cis_utils

def check2_1():
    # 2.1 Ensure that Cloud Audit Logging is configured properly across all services and all users from a project (Scored)

    logging.info("2.1 Ensure that Cloud Audit Logging is configured properly across all services and all users from a project (Scored)")
    details = []
    iam_policies_by_project = gcp_cis_utils.get_iam_policies_by_projects()
    for p in iam_policies_by_project.keys():
        out_json = iam_policies_by_project[p]
        acs = out_json.get('auditConfigs')
        if acs is None:
            details.append(("Cloud Audit Logging is not configured for project [%s]" % p, [p], p))
            continue
        for ac in acs:
            s = ac.get('service')
            if s is None or s != "allServices":
                details.append(("Cloud Audit Logging is not configured for all services for project [%s]" % p, [p], p))
                continue
            alcs = ac.get('auditLogConfigs')
            if alcs is None:
                details.append(("Cloud Audit Logging is not configured properly for project [%s]" % p, [p], p))
                continue
            lt_dr_found = False
            lt_dw_found = False
            for alc in alcs:
                if alc.get('logType') == "DATA_READ":
                    lt_dr_found = True
                elif alc.get('logType') == "DATA_WRITE":
                    lt_dw_found = True
                ems = alc.get('exemptedMembers')
                if ems is None:
                    continue
                for em in ems:
                    if em.startswith('user:'):
                        details.append(("Audit configuration has exempted member [%s] for log type [%s] for project [%s]" % (em.split(':')[1], alc.get('logType'), p), [em.split(':')[1], alc.get('logType'), p], p))
            if lt_dr_found == False:
                details.append(("Cloud audit logging configuration is not enabled for DATA_READ operation for  project [%s]" % p, [p, "DataReadNotEnabled"], p))
            if lt_dw_found == False:
                details.append(("Cloud audit logging configuration is not enabled for DATA_WRITE operation for  project [%s]" % p, [p, "DataWriteNotEnabled"], p))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.1', '2.1 [Level 1] Ensure that Cloud Audit Logging is configured properly across all services and all users from a project (Scored)', details, '4', '', '')
    return None

def check2_2():
    # 2.2 Ensure that sinks are configured for all log entries (Scored)

    logging.info("2.2 Ensure that sinks are configured for all log entries (Scored)")
    details = []
    # Check if sink is configured at organization or folder level
    orgs = gcp_cis_utils.get_all_organizations()
    for o in orgs:
        sink_found = False
        out_json = gcp_cis_utils.run_gcloud_cmd("logging sinks list --organization=%s" % o)
        for entry in out_json:
            if entry['filter'] == "(empty filter)":
                # TODO confirm that the destination exits
                sink_found = True
        if sink_found == False:
            details.append(("Sinks are not configured for all log entries for organization [%s]" % o, [o, "organization"], o))
    folders = gcp_cis_utils.get_all_folders()
    for f in folders:
        sink_found = False
        out_json = gcp_cis_utils.run_gcloud_cmd("logging sinks list --folder=%s" % f)
        for entry in out_json:
            if entry['filter'] == "(empty filter)":
                # TODO confirm that the destination exits
                sink_found = True
        if sink_found == False:
            details.append(("Sinks are not configured for all log entries for folder [%s]" % f, [f, "folder"], f))
    projects = gcp_cis_utils.get_logging_enabled_projects()
    for p in projects:
        sink_found = False
        out_json = gcp_cis_utils.run_gcloud_cmd("logging sinks list --project=%s" % p)
        for entry in out_json:
            if entry['filter'] == "(empty filter)":
                # TODO confirm that the destination exits
                sink_found = True
        if sink_found == False:
            details.append(("Sinks are not configured for all log entries for project [%s]" % p, [p, "project"], p))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.2', '2.2 [Level 1] Ensure that sinks are configured for all log entries (Scored)', details, '4', '', '')
    return None

def _check_bucket_retention_policy(source, source_label, logbucket, details):
    output = gcp_cis_utils.run_cmd("gsutil retention get %s 2>/dev/null" % logbucket)
    if "has no Retention Policy" in output:
        details.append(("No retention policy is configured for log bucket [%s] in %s [%s]" % (logbucket, source_label, source), [logbucket, source_label, source], logbucket))
    if "Retention Policy (UNLOCKED)" in output:
        details.append(("Retention policy is not locked for log bucket [%s] in %s [%s]" % (logbucket, source_label, source), [logbucket, source_label, source], logbucket))

def check2_3():
    # 2.3 Ensure that retention policies on log buckets are configured using Bucket Lock (Scored)

    logging.info("2.3 Ensure that retention policies on log buckets are configured using Bucket Lock (Scored)")
    details = []
    # Get sinks for organizations
    orgs = gcp_cis_utils.get_all_organizations()
    for o in orgs:
        out_json = gcp_cis_utils.run_gcloud_cmd("logging sinks list --organization=%s" % o)
        for entry in out_json:
            if entry['destination'].startswith("storage.googleapis.com/"):
                logbucket = "gs://" + entry['destination'][23:]
                _check_bucket_retention_policy(o, "organization", logbucket, details)
    # Get sinks for folders
    folders = gcp_cis_utils.get_all_folders()
    for f in folders:
        out_json = gcp_cis_utils.run_gcloud_cmd("logging sinks list --folder=%s" % f)
        for entry in out_json:
            if entry['destination'].startswith("storage.googleapis.com/"):
                logbucket = "gs://" + entry['destination'][23:]
                _check_bucket_retention_policy(f, "folder", logbucket, details)
    # Get sinks for projects
    projects = gcp_cis_utils.get_logging_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("logging sinks list --project=%s" % p)
        for entry in out_json:
            if entry['destination'].startswith("storage.googleapis.com/"):
                logbucket = "gs://" + entry['destination'][23:]
                _check_bucket_retention_policy(p, "project", logbucket, details)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.3', '2.3 [Level 1] Ensure that retention policies on log buckets are configured using Bucket Lock (Scored)', details, '4', '', '')
    return None

def _strip_all_whitespaces(in_str):
    p = re.compile(r'\s+')
    out_str = re.sub(p, '', in_str)
    return out_str

def _check_log_metric_filter_and_alerts(in_filter, details_msg):
    logging.debug("In _check_log_metric_filter_and_alerts")
    details = []
    projects = gcp_cis_utils.get_logging_enabled_projects()
    for p in projects:
        logging.debug("Processing project [%s]", p)
        out_json = gcp_cis_utils.run_gcloud_cmd("beta logging metrics list --project=%s" % p)
        poac_metric_found = False
        for entry in out_json:
            mf = entry['filter'].strip().replace('\n',' ')
            logging.debug("Comparing sanitizied filters...")
            sanitized_mf = _strip_all_whitespaces(mf)
            sanitized_in_filter = _strip_all_whitespaces(in_filter)
            logging.debug("%s", sanitized_mf)
            logging.debug("%s", sanitized_in_filter)
            if sanitized_mf == sanitized_in_filter:
                logging.debug("Filters matched")
                mdt = entry['metricDescriptor']['type']
                logging.debug("metricsDescriptor.type is [%s]", mdt)
                out_json_2 = gcp_cis_utils.run_gcloud_cmd("alpha monitoring policies list --project=%s" % p)
                for entry_2 in out_json_2:
                    for cond in entry_2['conditions']:
                        logging.debug("Condition is %s", cond)
                        if cond.get('conditionThreshold') is None:
                            continue
                        #logging.debug("condition.conditionThreshold.filter is [%s]",cond['conditionThreshold']['filter'])
                        mt_string = "metric.type=\"" + mdt + "\""
                        if mt_string in cond['conditionThreshold']['filter'] and entry_2['enabled']:
                            logging.debug("Alert policy found")
                            poac_metric_found = True
        if poac_metric_found == False:
            logging.debug("Alert policy not found")
            details.append((details_msg % p, [p], p))
    return details

def check2_4():
    # 2.4 Ensure log metric filter and alerts exist for project ownership assignments/changes (Scored)

    logging.info("2.4 Ensure log metric filter and alerts exist for project ownership assignments/changes (Scored)")
    POAC_METRIC_FILTER = '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")'
    details_msg = "Log metric filter and alerts do not exist for Project Ownership assignments/changes for project [%s]"
    details =  _check_log_metric_filter_and_alerts(POAC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.4', '2.4 [Level 1] Ensure log metric filter and alerts exist for project ownership assignments/changes (Scored)', details, '4', '', '')
    return None

def check2_5():
    # 2.5 Ensure that the log metric filter and alerts exist for Audit Configuration changes (Scored)

    logging.info("2.5 Ensure that the log metric filter and alerts exist for Audit Configuration changes (Scored)")
    ACC_METRIC_FILTER = 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
    details_msg = "Log metric filter and alerts do not exist for Audit Configuration changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(ACC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.5', '2.5 [Level 1] Ensure that the log metric filter and alerts exist for Audit Configuration changes (Scored)', details, '4', '', '')
    return None

def check2_6():
    # 2.6 Ensure that the log metric filter and alerts exist for Custom Role changes (Scored)

    logging.info("2.6 Ensure that the log metric filter and alerts exist for Custom Role changes (Scored)")

    CRC_METRIC_FILTER = 'resource.type="iam_role" AND protoPayload.methodName = "google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"'
    details_msg = "Log metric filter and alerts do not exist for Custom Role changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(CRC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.6', '2.6 [Level 1] Ensure that the log metric filter and alerts exist for Custom Role changes (Scored)', details, '4', '', '')
    return None

def check2_7():
    # 2.7 Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes (Scored)

    logging.info("2.7 Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes (Scored)")

    VPCNFRC_METRIC_FILTER = 'resource.type="gce_firewall_rule" AND jsonPayload.event_subtype="compute.firewalls.patch" OR jsonPayload.event_subtype="compute.firewalls.insert"'
    details_msg = "Log metric filter and alerts do not exist for VPC Network Firewall Rule changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(VPCNFRC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.7', '2.7 [Level 1] Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes (Scored)', details, '4', '', '')
    return None

def check2_8():
    # 2.8 Ensure that the log metric filter and alerts exist for VPC network route changes (Scored)

    logging.info("2.8 Ensure that the log metric filter and alerts exist for VPC network route changes (Scored)")

    VPCNRC_METRIC_FILTER = 'resource.type="gce_route" AND jsonPayload.event_subtype="compute.routes.delete" OR jsonPayload.event_subtype="compute.routes.insert"'
    details_msg = "Log metric filter and alerts do not exist for VPC Network Route changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(VPCNRC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.8', '2.8 [Level 1] Ensure that the log metric filter and alerts exist for VPC network route changes (Scored)', details, '4', '', '')
    return None

def check2_9():
    # 2.9 Ensure that the log metric filter and alerts exist for VPC network changes (Scored)

    logging.info("2.9 Ensure that the log metric filter and alerts exist for VPC network changes (Scored)")

    VPCNC_METRIC_FILTER = 'resource.type=gce_network AND jsonPayload.event_subtype="compute.networks.insert" OR jsonPayload.event_subtype="compute.networks.patch" OR jsonPayload.event_subtype="compute.networks.delete" OR jsonPayload.event_subtype="compute.networks.removePeering" OR jsonPayload.event_subtype="compute.networks.addPeering"'
    details_msg = "Log metric filter and alerts do not exist for VPC Network changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(VPCNC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.9', '2.9 [Level 1] Ensure that the log metric filter and alerts exist for VPC network changes (Scored)', details, '4', '', '')
    return None

def check2_10():
    # 2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes (Scored)

    logging.info("2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes (Scored)")

    CSIAMPC_METRIC_FILTER = 'resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"'
    details_msg = "Log metric filter and alerts do not exist for Cloud Storage IAM Permission changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(CSIAMPC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.10', '2.10 [Level 1] Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes (Scored)', details, '4', '', '')
    return None

def check2_11():
    # 2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes (Scored)

    logging.info("2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes (Scored)")

    SQLICC_METRIC_FILTER = 'protoPayload.methodName="cloudsql.instances.update"'
    details_msg = "Log metric filter and alerts do not exist for SQL Instance Configuration changes for project [%s]"
    details = _check_log_metric_filter_and_alerts(SQLICC_METRIC_FILTER, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-2.11', '2.11 [Level 1] Ensure that the log metric filter and alerts exist for SQL instance configuration changes (Scored)', details, '4', '', '')
    return None

def run_checks():
    config_issues = []
    gcp_cis_utils.append_issue(config_issues, check2_1())
    gcp_cis_utils.append_issue(config_issues, check2_2())
    gcp_cis_utils.append_issue(config_issues, check2_3())
    gcp_cis_utils.append_issue(config_issues, check2_4())
    gcp_cis_utils.append_issue(config_issues, check2_5())
    gcp_cis_utils.append_issue(config_issues, check2_6())
    gcp_cis_utils.append_issue(config_issues, check2_7())
    gcp_cis_utils.append_issue(config_issues, check2_8())
    gcp_cis_utils.append_issue(config_issues, check2_9())
    gcp_cis_utils.append_issue(config_issues, check2_10())
    gcp_cis_utils.append_issue(config_issues, check2_11())
    return config_issues

