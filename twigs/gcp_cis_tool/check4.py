import sys
import logging
from . import gcp_cis_utils as gcp_cis_utils

def check4_1():
    # 4.1 Ensure that instances are not configured to use the default service account (Scored)

    logging.info("4.1 Ensure that instances are not configured to use the default service account (Scored)")
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = gcp_cis_utils.run_gcloud_cmd("projects describe %s" % p)
        project_no = out_json['projectNumber']
        default_service_account = project_no + "-compute@developer.gserviceaccount.com"
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            if (entry['name'].startswith('gke-') and entry.get('labels') is not None and 'goog-gke-node' in entry['labels'].keys()) or (entry.get('labels') is not None and 'cloud.google.com/gke-nodepool' in entry['labels'].keys()):
                continue
            if entry.get('serviceAccounts') is None:
                continue
            for sa in entry['serviceAccounts']:
                if sa['email'] == default_service_account:
                    details.append(("Compute instance [%s] uses default service account [%s] in project [%s]" % (entry['name'], default_service_account, p), [entry['name'], default_service_account, p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.1', '4.1 [Level 1] Ensure that instances are not configured to use the default service account (Scored)', details, '4', '', '')
    return None

def check4_2():
    # 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Scored)

    logging.info("4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Scored)")
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = gcp_cis_utils.run_gcloud_cmd("projects describe %s" % p)
        project_no = out_json['projectNumber']
        default_service_account = project_no + "-compute@developer.gserviceaccount.com"
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            if (entry['name'].startswith('gke-') and entry.get('labels') is not None and 'goog-gke-node' in entry['labels'].keys()) or (entry.get('labels') is not None and 'cloud.google.com/gke-nodepool' in entry['labels'].keys()):
                continue
            if entry.get('serviceAccounts') is None:
                continue
            for sa in entry['serviceAccounts']:
                if sa['email'] == default_service_account and "https://www.googleapis.com/auth/cloud-platform" in sa['scopes']:
                    details.append(("Compute instance [%s] uses default service account [%s] with full access to all Cloud APIs in project [%s]" % (entry['name'], default_service_account, p), [entry['name'], default_service_account, p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.2', '4.2 [Level 1] Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Scored)', details, '4', '', '')
    return None

def check4_3():
    # 4.3 Ensure "Block Project-wide SSH keys" is enabled for VM instances (Scored)

    logging.info('4.3 Ensure "Block Project-wide SSH keys" is enabled for VM instances (Scored)')
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            if (entry['name'].startswith('gke-') and entry.get('labels') is not None and 'goog-gke-node' in entry['labels'].keys()) or (entry.get('labels') is not None and 'cloud.google.com/gke-nodepool' in entry['labels'].keys()):
                continue
            metadata = entry.get('metadata')
            block_pw_ssh_keys_enabled = False
            if metadata is not None:
                metadata_items = metadata.get('items')
                if metadata_items is not None:
                    for mdi in metadata_items:
                        if mdi['key'] == 'block-project-ssh-keys' and mdi['value'] == 'true':
                            block_pw_ssh_keys_enabled = True
            if block_pw_ssh_keys_enabled == False:
                details.append(("Compute instance [%s] does not have Block Project-wide SSH keys enabled in project [%s]" % (entry['name'], p), [entry['name'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.3', '4.3 [Level 1] Ensure "Block Project-wide SSH keys" is enabled for VM instances (Scored)', details, '4', '', '')
    return None

def check4_4():
    # 4.4 Ensure oslogin is enabled for a Project (Scored)

    logging.info('4.4 Ensure oslogin is enabled for a Project (Scored)')
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        oslogin_enabled = False
        out_json = gcp_cis_utils.run_gcloud_cmd("compute project-info describe --project=%s" % p)
        cimd = out_json.get('commonInstanceMetadata')
        if cimd is not None:
            metadata_items = cimd.get('items')
            if metadata_items is not None:
                for mdi in metadata_items:
                    if mdi['key'] == 'enable-oslogin' and mdi['value'] == 'TRUE':
                        oslogin_enabled = True
        overriding_instances = []
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            metadata = entry.get('metadata')
            instance_overrides = False
            if metadata is not None:
                metadata_items = metadata.get('items')
                if metadata_items is not None:
                    for mdi in metadata_items:
                        if mdi['key'] == 'enable-oslogin' and mdi['value'] == 'FALSE':
                            instance_overrides = True
            if instance_overrides:
                overriding_instances.append(entry['name'])
        if oslogin_enabled == False:
            details.append(("oslogin is not enabled for project [%s]" % p, [p], p))
        elif len(overriding_instances) > 0:
            for overriding_instance in overriding_instances:
                details.append(("oslogin is enabled for project [%s], however following compute instance overrides the project setting [%s]" % (p, overriding_instance), [p, overriding_instance], overriding_instance))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.4', '4.4 [Level 1] Ensure oslogin is enabled for a Project (Scored)', details, '4', '', '')
    return None

def check4_5():
    # 4.5 Ensure 'Enable connecting to serial ports' is not enabled for VM Instance (Scored)

    logging.info("4.5 Ensure 'Enable connecting to serial ports' is not enabled for VM Instance (Scored)")
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            metadata = entry.get('metadata')
            serial_port_enabled = False
            if metadata is not None:
                metadata_items = metadata.get('items')
                if metadata_items is not None:
                    for mdi in metadata_items:
                        if mdi['key'] == 'serial-port-enable' and mdi['value'] == 'true':
                            serial_port_enabled = True
            if serial_port_enabled:
                details.append(("Serial port is enabled for compute instance [%s] in project [%s]" % (entry['name'], p), [entry['name'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.5', "4.5 [Level 1] Ensure 'Enable connecting to serial ports' is not enabled for VM Instance (Scored)", details, '4', '', '')
    return None

def check4_6():
    # 4.6 Ensure that IP forwarding is not enabled on Instances (Scored)

    logging.info("4.6 Ensure that IP forwarding is not enabled on Instances (Scored)")
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            if (entry['name'].startswith('gke-') and entry.get('labels') is not None and 'goog-gke-node' in entry['labels'].keys()) or (entry.get('labels') is not None and 'cloud.google.com/gke-nodepool' in entry['labels'].keys()):
                continue
            if entry.get('canIpForward') is not None and entry['canIpForward']:
                details.append(("IP forwarding is enabled on compute instance [%s] in project [%s]" % (entry['name'], p), [entry['name'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.6', '4.6 [Level 1] Ensure that IP forwarding is not enabled on Instances (Scored)', details, '4', '', '')
    return None

def check4_7():
    # 4.7 Ensure VM disks for critical VMs are encrypted with Customer- Supplied Encryption Keys (CSEK) (Scored)

    logging.info("Not supported - 4.7 Ensure VM disks for critical VMs are encrypted with Customer- Supplied Encryption Keys (CSEK) (Scored)")
    return None

def check4_8():
    # 4.8 Ensure Compute instances are launched with Shielded VM enabled (Scored)

    logging.info("4.8 Ensure Compute instances are launched with Shielded VM enabled (Scored)")
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            shieldedInstanceConfig = entry.get('shieldedInstanceConfig')
            if shieldedInstanceConfig is None:
                details.append(("Compute instance [%s] in project [%s] is not launched with Shielded VM enabled" % (entry['name'], p), [entry['name'], p], entry['name']))
            else:
                if shieldedInstanceConfig['enableVtpm'] == False or shieldedInstanceConfig['enableIntegrityMonitoring'] == False:
                    details.append(("Compute instance [%s] in project [%s] is not launched with Shielded VM enabled" % (entry['name'], p), [entry['name'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.8', '4.8 [Level 2] Ensure Compute instances are launched with Shielded VM enabled (Scored)', details, '5', '', '')
    return None

def check4_9():
    # 4.9 Ensure that Compute instances do not have public IP addresses (Scored)

    logging.info("4.9 Ensure that Compute instances do not have public IP addresses (Scored)")
    details = []
    compute_instances_by_projects = gcp_cis_utils.get_compute_instances_by_projects()
    for p in compute_instances_by_projects.keys():
        out_json = compute_instances_by_projects[p]
        for entry in out_json:
            if (entry['name'].startswith('gke-') and entry.get('labels') is not None and 'goog-gke-node' in entry['labels'].keys()) or (entry.get('labels') is not None and 'cloud.google.com/gke-nodepool' in entry['labels'].keys()):
                continue
            for ni in entry['networkInterfaces']:
                if ni.get('accessConfigs') is not None:
                    details.append(("Compute instance [%s] in project [%s] has Public IP address" % (entry['name'], p), [entry['name'], p], entry['name']))
                    break
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-4.9', '4.9 [Level 2] Ensure that Compute instances do not have public IP addresses (Scored)', details, '5', '', '')
    return None

def check4_10():
    # 4.10 Ensure that App Engine applications enforce HTTPS connections (Not Scored)

    logging.info("Not supported - 4.10 Ensure that App Engine applications enforce HTTPS connections (Not Scored)")
    return None

def run_checks():
    config_issues = []
    gcp_cis_utils.append_issue(config_issues, check4_1())
    gcp_cis_utils.append_issue(config_issues, check4_2())
    gcp_cis_utils.append_issue(config_issues, check4_3())
    gcp_cis_utils.append_issue(config_issues, check4_4())
    gcp_cis_utils.append_issue(config_issues, check4_5())
    gcp_cis_utils.append_issue(config_issues, check4_6())
    gcp_cis_utils.append_issue(config_issues, check4_7())
    gcp_cis_utils.append_issue(config_issues, check4_8())
    gcp_cis_utils.append_issue(config_issues, check4_9())
    gcp_cis_utils.append_issue(config_issues, check4_10())
    return config_issues

