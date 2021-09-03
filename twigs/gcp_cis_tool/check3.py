import sys
import logging
from . import gcp_cis_utils as gcp_cis_utils

def check3_1():
    # 3.1 Ensure that the default network does not exist in a project (Scored)

    logging.info("3.1 Ensure that the default network does not exist in a project (Scored)")

    details = []
    projects = gcp_cis_utils.get_compute_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("compute networks list --project=%s" % p)
        for entry in out_json:
            if entry.get('name') == 'default':
                details.append(("Default network exists for project [%s]" % p, [p], p))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.1', '3.1 [Level 2] Ensure that the default network does not exist in a project (Scored)', details, '5', '', '')
    return None

def check3_2():
    # 3.2 Ensure legacy networks do not exist for a project (Scored)

    logging.info("3.2 Ensure legacy networks do not exist for a project (Scored)")

    details = []
    projects = gcp_cis_utils.get_compute_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("compute networks list --project=%s" % p)
        for entry in out_json:
            if entry.get('x_gcloud_subnet_mode') == 'LEGACY':
                details.append(("Legacy network [%s] exists for project [%s]" % (entry['name'], p), [entry['name'], p], p))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.2', '3.2 [Level 1] Ensure legacy networks do not exist for a project (Scored)', details, '4', '', '')
    return None

def check3_3():
    # 3.3 Ensure that DNSSEC is enabled for Cloud DNS (Scored)

    logging.info("3.3 Ensure that DNSSEC is enabled for Cloud DNS (Scored)")

    details = []
    projects = gcp_cis_utils.get_dns_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("dns managed-zones list --project=%s" % p)
        for entry in out_json:
            if entry.get('visibility') == 'public':
                dnssec = entry.get('dnssecConfig')
                if dnssec is None or dnssec.get('state') != 'on':
                    details.append(("DNSSEC is not enabled for Managed Zone [%s] in  project [%s]" % (entry['name'], p), [entry['name'], p], p))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.3', '3.3 [Level 1] Ensure that DNSSEC is enabled for Cloud DNS (Scored)', details, '4', '', '')
    return None

def _check_DNSSEC_key_setting(keyType, details_msg):
    details = []
    projects = gcp_cis_utils.get_dns_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("dns managed-zones list --project=%s" % p)
        for entry in out_json:
            if entry.get('visibility') == 'public':
                dnssec = entry.get('dnssecConfig')
                if dnssec is not None:
                    defaultKeySpecs = dnssec.get('defaultKeySpecs')
                    if defaultKeySpecs is not None:
                        for entry_2 in defaultKeySpecs:
                            if entry_2['keyType'] == keyType and entry_2['algorithm'].lower() == "rsasha1":
                                details.append((details_msg % (entry['name'], p), [entry['name'], keyType, "rsasha1", p], p))
    return details

def check3_4():
    # 3.4 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC (Not Scored)

    logging.info("3.4 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC (Not Scored)")
    details_msg = "RSASHA1 is used for key-signing in Cloud DNS DNSSEC for managed zone [%s] in project [%s]"
    details = _check_DNSSEC_key_setting("keySigning", details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.4', '3.4 [Level 1] Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC (Not Scored)', details, '4', '', '')
    return None

def check3_5():
    # 3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC (Not Scored)

    logging.info("3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC (Not Scored)")

    details_msg = "RSASHA1 is used for zone-signing in Cloud DNS DNSSEC for managed zone [%s] in project [%s]"
    details = _check_DNSSEC_key_setting("zoneSigning", details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.5', '3.5 [Level 1] Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC (Not Scored) ', details, '4', '', '')
    return None

def _check_open_port(port_no, details_msg):
    details = []
    projects = gcp_cis_utils.get_compute_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("compute firewall-rules list --project=%s" % p)
        for entry in out_json:
            if entry['direction'] != 'INGRESS':
                continue
            if entry.get('allowed') is None:
                continue
            for allowed in entry['allowed']:
                port_open = False
                if allowed.get('IPProtocol') is not None and (allowed['IPProtocol'] == 'tcp' or allowed['IPProtocol'] == 'all'):
                    if entry.get('sourceRanges') is None:
                        continue
                    for sr in entry['sourceRanges']:
                        if sr == "0.0.0.0/0":
                            ports = allowed.get('ports')
                            if ports is None:
                                port_open = True
                            else:
                                for port in ports:
                                    if '-' in port:
                                        # range of ports is given
                                        start_port = int(port.split('-')[0])
                                        end_port = int(port.split('-')[1])
                                        if start_port <= port_no and port_no <= end_port:
                                            port_open = True
                                    elif port_no == int(port):
                                        port_open = True
                if port_open:
                    details.append((details_msg % p, [p, str(port_no)], p))
                    return details
    return details

def check3_6():
    # 3.6 Ensure that SSH access is restricted from the internet (Scored)

    logging.info("3.6 Ensure that SSH access is restricted from the internet (Scored)")
    details_msg = "SSH access [port 22] is open from the internet for project [%s]"
    details = _check_open_port(22, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.6', '3.6 [Level 2] Ensure that SSH access is restricted from the internet (Scored) ', details, '5', '', '')
    return None

def check3_7():
    # 3.7 Ensure that RDP access is restricted from the Internet (Scored)

    logging.info("3.7 Ensure that RDP access is restricted from the Internet (Scored)")
    details_msg = "RDP access [port 3389] is open from the internet for project [%s]"
    details = _check_open_port(3389, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.7', '3.7 [Level 2] Ensure that RDP access is restricted from the Internet (Scored) ', details, '5', '', '')
    return None

def check3_8():
    # 3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network (Scored)

    logging.info("3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network (Scored)")
    details = []
    projects = gcp_cis_utils.get_compute_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("compute networks subnets list --project=%s" % p)
        for entry in out_json:
            enableFlowLogs = entry.get('enableFlowLogs')
            if enableFlowLogs is None or enableFlowLogs == False:
                details.append(("Subnet [%s] with IP address range [%s] for project [%s] does not have VPC Flow Logs enabled" % (entry['name'], entry['ipCidrRange'], p), [entry['name'], entry['ipCidrRange'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.8', '3.8 [Level 1] Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network (Scored)', details, '4', '', '')
    return None

def _check_target_proxy(p, cmd, msg_prefix):
    details = []
    out_json = gcp_cis_utils.run_gcloud_cmd("compute %s list --project=%s" % (cmd, p))
    for entry in out_json:
        sslPolicy = entry.get('sslPolicy')
        if sslPolicy is None:
            details.append(("%s proxy load balancer [%s] in project [%s] uses GCP default policy which is insecure" % (msg_prefix, entry['name'], p), [msg_prefix, entry['name'], p], entry['name']))
        else:
            sslPolicyName = sslPolicy.split('/')[-1]
            out_json_2 = gcp_cis_utils.run_gcloud_cmd("compute ssl-policies describe %s --project=%s" % (sslPolicyName, p))
            policySatisfied = False
            if out_json_2['profile'] == "MODERN" and out_json_2['minTlsVersion'] == "TLS_1_2":
                policySatisfied = True
            if out_json_2['profile'] == "RESTRICTED":
                policySatisfied = True
            if out_json_2['profile'] == "CUSTOM":
                not_allowed_ciphers = set()
                not_allowed_ciphers.add("TLS_RSA_WITH_AES_128_GCM_SHA256")
                not_allowed_ciphers.add("TLS_RSA_WITH_AES_256_GCM_SHA384")
                not_allowed_ciphers.add("TLS_RSA_WITH_AES_128_CBC_SHA")
                not_allowed_ciphers.add("TLS_RSA_WITH_AES_256_CBC_SHA")
                not_allowed_ciphers.add("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
                enabled_ciphers = set(out_json_2['enabledFeatures'])
                weak_ciphers_used = enabled_ciphers.intersection(not_allowed_ciphers)
                if len(weak_ciphers_used) == 0:
                    policySatisfied = True

            if policySatisfied == False:
                details.append(("%s proxy load balancer [%s] in project [%s] uses SSL policy with weak ciphers" % (msg_prefix, entry['name'], p), [msg_prefix, entry['name'], p], entry['name']))
    return details

def check3_9():
    # 3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites (Not Scored)

    logging.info("3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites (Not Scored)")
    details = []
    proxy_types = ["target-https-proxies", "target-ssl-proxies"]
    projects = gcp_cis_utils.get_compute_enabled_projects()
    for p in projects:
        details.extend(_check_target_proxy(p, "target-https-proxies", "HTTPS"))
        details.extend(_check_target_proxy(p, "target-ssl-proxies", "SSL"))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-3.9', '3.9 [Level 1] Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites (Not Scored)', details, '4', '', '')
    return None

def run_checks():
    config_issues = []
    gcp_cis_utils.append_issue(config_issues, check3_1())
    gcp_cis_utils.append_issue(config_issues, check3_2())
    gcp_cis_utils.append_issue(config_issues, check3_3())
    gcp_cis_utils.append_issue(config_issues, check3_4())
    gcp_cis_utils.append_issue(config_issues, check3_5())
    gcp_cis_utils.append_issue(config_issues, check3_6())
    gcp_cis_utils.append_issue(config_issues, check3_7())
    gcp_cis_utils.append_issue(config_issues, check3_8())
    gcp_cis_utils.append_issue(config_issues, check3_9())
    return config_issues

