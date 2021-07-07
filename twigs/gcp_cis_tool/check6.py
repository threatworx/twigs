import sys
import logging
from . import gcp_cis_utils as gcp_cis_utils
  
def check6_1_1():
    # 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges (Scored)

    logging.info("Not supported - 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges (Scored)")
    return None

def check6_1_2():
    # 6.1.2 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off' (Scored)

    logging.info("6.1.2 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off' (Scored)")
    details_msg = "Cloud SQL Mysql instance [%s] in project [%s] does not have 'local_infile' database flag set to 'off'"
    details = gcp_cis_utils.check_database_flag('MYSQL*', 'local_infile', 'off', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.1.2', "6.1.2 [Level 1] Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off' (Scored)", details, '4', '', '')
    return None

def check6_2_1():
    # 6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)

    logging.info("6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_checkpoints' database flag set to 'on'"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_checkpoints', 'on', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.1', "6.2.1 [Level 1] Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)", details, '4', '', '')
    return None

def check6_2_2():
    # 6.2.2 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)

    logging.info("6.2.2 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_connections' database flag set to 'on'"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_connections', 'on', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.2', "6.2.2 [Level 1] Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)", details, '4', '', '')
    return None

def check6_2_3():
    # 6.2.3 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)

    logging.info("6.2.3 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_disconnections' database flag set to 'on'"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_disconnections', 'on', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.3', "6.2.3 [Level 1] Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)", details, '4', '', '')
    return None

def check6_2_4():
    # 6.2.4 Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)

    logging.info("6.2.4 Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_lock_waits' database flag set to 'on'"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_lock_waits', 'on', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.4', "6.2.4 [Level 1] Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Scored)", details, '4', '', '')
    return None

def check6_2_5():
    # 6.2.5 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately (Not Scored)

    logging.info("6.2.5 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately (Not Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_min_messages' database flag set"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_min_messages', None, details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.5', "6.2.5 [Level 1] Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately (Not Scored)", details, '4', '', '')
    return None

def check6_2_6():
    # 6.2.6 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on) (Scored)

    logging.info("6.2.6 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on) (Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_temp_files' database flag set to '0' (on)"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_temp_files', '0', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.6', "6.2.6 [Level 1] Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on) (Scored)", details, '4', '', '')
    return None

def check6_2_7():
    # 6.2.7 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled) (Scored)

    logging.info("6.2.7 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled) (Scored)")
    details_msg = "Cloud SQL PostgreSQL instance [%s] in project [%s] does not have 'log_min_duration_statement' database flag set to '-1' (disabled)"
    details = gcp_cis_utils.check_database_flag("POSTGRES*", 'log_min_duration_statement', '-1', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.2.7', "6.2.7 [Level 1] Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled) (Scored)", details, '4', '', '')
    return None

def check6_3_1():
    # 6.3.1 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' (Scored)

    logging.info("6.3.1 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' (Scored)")
    details_msg = "Cloud SQL SQL Server instance [%s] in project [%s] does not have 'cross db ownership chaining' database flag set to 'off'"
    details = gcp_cis_utils.check_database_flag("SQLSERVER*", 'cross db ownership chaining', 'off', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.3.1', "6.3.1 [Level 1] Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' (Scored)", details, '4', '', '')
    return None

def check6_3_2():
    # 6.3.2 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off' (Scored)

    logging.info("6.3.2 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off' (Scored)")
    details_msg = "Cloud SQL SQL Server instance [%s] in project [%s] does not have 'contained database authentication' database flag set to 'off'"
    details = gcp_cis_utils.check_database_flag("SQLSERVER*", 'contained database authentication', 'off', details_msg)
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.3.2', "6.3.2 [Level 1] Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off' (Scored)", details, '4', '', '')
    return None

def check6_4():
    # 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL (Scored)
    
    logging.info("6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("sql instances list --project=%s" % p)
        for entry in out_json:
            require_ssl = False
            settings = entry.get("settings")
            if settings is not None:
                ipConfig = settings.get("ipConfiguration")
                if ipConfig is not None:
                    req_ssl = ipConfig.get('requireSsl')
                    if req_ssl is not None and req_ssl == True:
                        require_ssl = True
            if require_ssl == False:
                details.append(("Cloud SQL database instance [%s] in project [%s] does not require all incoming connections to use SSL" % (entry['name'], p), [entry['name'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.4', "6.4 [Level 1] Ensure that the Cloud SQL database instance requires all incoming connections to use SSL (Scored)", details, '4', '', '')
    return None

def check6_5():
    # 6.5 Ensure that Cloud SQL database instances are not open to the world (Scored)
    
    logging.info("6.5 Ensure that Cloud SQL database instances are not open to the world (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("sql instances list --project=%s" % p)
        for entry in out_json:
            settings = entry.get("settings")
            if settings is not None:
                ipConfig = settings.get("ipConfiguration")
                if ipConfig is not None:
                    auth_nws = ipConfig.get('authorizedNetworks')
                    if auth_nws is None:
                        continue
                    for auth_nw in auth_nws:
                        if auth_nw.get('value') == "0.0.0.0/0":
                            details.append(("Cloud SQL database instance [%s] in project [%s] is open to the world" % (entry['name'], p), [entry['name'], p], entry['name'], p))
                            break
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.5', "6.5 [Level 1] Ensure that Cloud SQL database instances are not open to the world (Scored)", details, '4', '', '')
    return None

def check6_6():
    # 6.6 Ensure that Cloud SQL database instances do not have public IPs (Scored)
    
    logging.info("6.6 Ensure that Cloud SQL database instances do not have public IPs (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("sql instances list --project=%s" % p)
        for entry in out_json:
            if entry['instanceType'] == "CLOUD_SQL_INSTANCE" and entry['backendType'] == "SECOND_GEN":
                ipAddresses = entry.get('ipAddresses')
                if ipAddresses is not None:
                    for ipAddress in ipAddresses:
                        if ipAddress['type'] == "PRIMARY":
                            details.append(("Cloud SQL database instance [%s] in project [%s] has Public IP address" % (entry['name'], p), [entry['name'], p], entry['name']))
                            break
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.6', "6.6 [Level 2] Ensure that Cloud SQL database instances do not have public IPs (Scored)", details, '5', '', '')
    return None

def check6_7():
    # 6.7 Ensure that Cloud SQL database instances are configured with automated backups (Scored)
    
    logging.info("6.7 Ensure that Cloud SQL database instances are configured with automated backups (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("sql instances list --project=%s" % p)
        for entry in out_json:
            backup_enabled = False
            settings = entry.get("settings")
            if settings is not None:
                backupConfig = settings.get("backupConfiguration")
                if backupConfig is not None:
                    bkp_enabled = backupConfig.get('enabled')
                    if bkp_enabled is not None and bkp_enabled == True:
                        backup_enabled = True
            if backup_enabled == False:
                details.append(("Cloud SQL database instance [%s] in project [%s] does not have automated backups enabled" % (entry['name'], p), [entry['name'], p], entry['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-6.7', "6.7 [Level 1] Ensure that Cloud SQL database instances are configured with automated backups (Scored)", details, '4', '', '')
    return None

def run_checks():
    config_issues = []
    gcp_cis_utils.append_issue(config_issues, check6_1_1())
    gcp_cis_utils.append_issue(config_issues, check6_1_2())
    gcp_cis_utils.append_issue(config_issues, check6_2_1())
    gcp_cis_utils.append_issue(config_issues, check6_2_2())
    gcp_cis_utils.append_issue(config_issues, check6_2_3())
    gcp_cis_utils.append_issue(config_issues, check6_2_4())
    gcp_cis_utils.append_issue(config_issues, check6_2_5())
    gcp_cis_utils.append_issue(config_issues, check6_2_6())
    gcp_cis_utils.append_issue(config_issues, check6_2_7())
    gcp_cis_utils.append_issue(config_issues, check6_3_1())
    gcp_cis_utils.append_issue(config_issues, check6_3_2())
    gcp_cis_utils.append_issue(config_issues, check6_4())
    gcp_cis_utils.append_issue(config_issues, check6_5())
    gcp_cis_utils.append_issue(config_issues, check6_6())
    gcp_cis_utils.append_issue(config_issues, check6_7())
    return config_issues

