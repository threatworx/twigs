import sys
import datetime
import logging
from . import gcp_cis_utils as gcp_cis_utils

def check1_1():
    # 1.1 Ensure that corporate login credentials are used (Scored)

    logging.info("1.1 Ensure that corporate login credentials are used (Scored)")
    # Get all projects
    projects = gcp_cis_utils.get_all_projects()

    # List all organizations
    orgs = gcp_cis_utils.get_all_organizations()

    # List all folders
    folders = gcp_cis_utils.get_all_folders()

    # List accounts for each project
    details = []
    iam_policies_by_project = gcp_cis_utils.get_iam_policies_by_projects()
    for p in iam_policies_by_project.keys():
        out_json = iam_policies_by_project[p]
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        for entry in bindings:
            members = entry.get('members')
            for m in members:
                if m.endswith('gmail.com'):
                    details.append(("Personal email [%s] is used for role [%s] in IAM policies for project [%s]" % (m.split(':')[1], entry['role'], p), [m.split(':')[1], entry['role'], p], m.split(':')[1]))
    
    # List accounts for each organization
    for o in orgs:
        out_json = gcp_cis_utils.run_gcloud_cmd("organizations get-iam-policy %s" % (o))
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        for entry in bindings:
            members = entry.get('members')
            for m in members:
                if m.endswith('gmail.com'):
                    details.append(("Personal email [%s] is used for role [%s] in IAM policies for project [%s]" % (m.split(':')[1], entry['role'], o), [m.split(':')[1], entry['role'], o], m.split(':')[1]))

    # List accounts for each folder
    for f in folders:
        out_json = gcp_cis_utils.run_gcloud_cmd("resource-manager folders get-iam-policy " % f)
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        for entry in bindings:
            members = entry.get('members')
            for m in members:
                if m.endswith('gmail.com'):
                    details.append(("Personal email [%s] is used for role [%s] in IAM policies for project [%s]" % (m.split(':')[1], entry['role'], f), [m.split(':')[1], entry['role'], f], m.split(':')[1]))

    # record violation
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.1', '1.1 [Level 1] Ensure that corporate login credentials are used (Scored)', details, '4', '', '')
    return None

def check1_2():
    # 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts (Not Scored)
    logging.info("Not supported - 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts (Not Scored)")
    return None

def check1_3():
    # 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts (Not Scored)

    logging.info("Not supported - 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts (Not Scored)")
    return None

def check1_4():

    # 1.4 Ensure that there are only GCP-managed service account keys for each service account (Scored)

    logging.info("1.4 Ensure that there are only GCP-managed service account keys for each service account (Scored)")
    details = []
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("iam service-accounts list --project=%s" % p)
        for entry in out_json:
            sa_email = entry['email']
            if sa_email.endswith('.iam.gserviceaccount.com'):
                out_json_2 = gcp_cis_utils.run_gcloud_cmd("iam service-accounts keys list --iam-account=%s --managed-by=user" % sa_email)
                for entry2 in out_json_2:
                    details.append(("User managed service account [%s] has user-managed key" % sa_email, [sa_email], sa_email))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.4', '1.4 [Level 1] Ensure that there are only GCP-managed service account keys for each service account (Scored)', details, '4', '', '')
    return None

def check1_5():
    # 1.5 Ensure that Service Account has no Admin privileges (Scored)

    logging.info("1.5 Ensure that Service Account has no Admin privileges (Scored)")
    details = []
    iam_policies_by_project = gcp_cis_utils.get_iam_policies_by_projects()
    for p in iam_policies_by_project.keys():
        out_json = iam_policies_by_project[p]
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        for entry in bindings:
            if 'admin' in entry['role'].lower() or entry['role'] in ["roles/editor", "roles/owner"]:
                for m in entry['members']:
                    if m.endswith('.iam.gserviceaccount.com'):
                        details.append(("User created and managed service account [%s] has role [%s] in project [%s]" % (m, entry['role'], p), [m, entry['role'], p], m))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.5', '1.5 [Level 1] Ensure that Service Account has no Admin privileges (Scored)', details, '4', '', '')
    return None

def check1_6():
    # 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level (Scored)

    logging.info("1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level (Scored)")
    details = []
    iam_policies_by_project = gcp_cis_utils.get_iam_policies_by_projects()
    for p in iam_policies_by_project.keys():
        out_json = iam_policies_by_project[p]
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        for entry in bindings:
            if entry['role'] in ["roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"]:
                for m in entry['members']:
                    if m.startswith('user:'):
                        details.append(("IAM user [%s] is assigned role [%s] in project [%s]" % (m.split(':')[1], entry['role'], p), [m.split(':')[1], entry['role'], p], m.split(':')[1]))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.6', '1.6 [Level 1] Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level (Scored)', details, '4', '', '')
    return None

def check1_7():
    # 1.7 Ensure user-managed/external keys for service accounts are rotated every 90 days or less (Scored)

    logging.info("1.7 Ensure user-managed/external keys for service accounts are rotated every 90 days or less (Scored)")
    details = []
    last90days = datetime.datetime.now() - datetime.timedelta(days=90)
    projects = gcp_cis_utils.get_all_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("iam service-accounts list --project=%s" % p)
        for entry in out_json:
            out_json_2 = gcp_cis_utils.run_gcloud_cmd("iam service-accounts keys list --iam-account %s --managed-by=user" % entry['email'])
            for entry_2 in out_json_2:
                entry_2_vat = entry_2['validAfterTime']
                if '.' in entry_2_vat:
                    entry_2_vat = entry_2_vat.split('.')[0] + 'Z'
                vat = datetime.datetime.strptime(entry_2_vat, "%Y-%m-%dT%H:%M:%SZ")
                if vat < last90days:
                    details.append(("User managed service account [%s] has not rotated key in last 90 days. Key has been valid since %s" % (entry['email'], entry_2['validAfterTime']), [entry['email']], entry['email']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.7', '1.7 [Level 1] Ensure user-managed/external keys for service accounts are rotated every 90 days or less (Scored)', details, '4', '', '')
    return None

def check1_8():
    # 1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users (Not Scored)

    logging.info("1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users (Not Scored)")
    details = []
    iam_policies_by_projects = gcp_cis_utils.get_iam_policies_by_projects()
    for p in iam_policies_by_projects.keys():
        out_json = iam_policies_by_projects[p]
        saa_role_users = set()
        sau_role_users = set()
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        for entry in bindings:
            gcp_cis_utils.add_members_with_role(entry, "roles/iam.serviceAccountAdmin", saa_role_users)
            gcp_cis_utils.add_members_with_role(entry, "roles/iam.serviceAccountUser", sau_role_users)
        intersection = saa_role_users.intersection(sau_role_users)
        if len(intersection) > 0:
            for tuser in intersection:
                details.append(("Separation of duties is not enforced for IAM user [%s] for roles (Service Account Admin & Service Account User) in project [%s]" % (tuser, p),[tuser, p], tuser))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.8', '1.8 [Level 2] Ensure that Separation of duties is enforced while assigning service account related roles to users (Not Scored)', details, '5', '', '')
    return None

def check1_9():
    # 1.9 Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible (Scored)

    logging.info("1.9 Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible (Scored)")
    details = []
    projects = gcp_cis_utils.get_cloud_kms_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("kms keyrings list --location=global --project=%s" % p)
        for entry in out_json:
            out_json_2 = gcp_cis_utils.run_gcloud_cmd("kms keys list --keyring=%s --location=global" % entry['name'])
            for entry_2 in out_json_2:
                out_json_3 = gcp_cis_utils.run_gcloud_cmd("kms keys get-iam-policy %s --keyring=%s --location=global" % (entry_2['name'], entry['name']))
                bindings = out_json_3.get('bindings')
                if bindings is None:
                    continue
                for entry_3 in bindings:
                    if "allUsers" in entry_3['members'] or "allAuthenticatedUsers" in entry_3['members']:
                        details.append(("Cloud KMS CryptoKey [%s] is anonymously or publically accessible in project [%s]" % (entry_2['name'], p), [entry_2['name'], p], entry_2['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.9', '1.9 [Level 1] Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible (Scored)', details, '4', '', '')
    return None

def check1_10():
    # 1.10 Ensure KMS encryption keys are rotated within a period of 90 days (Scored)

    logging.info("1.10 Ensure KMS encryption keys are rotated within a period of 90 days (Scored)")
    details = []
    next90days = datetime.datetime.now() + datetime.timedelta(days=90)
    rpd = { 'm': (129600, 'minutes'), 's': (7776000, 'seconds'), 'h': (2160, 'hours'), 'd': (90, 'days') }
    projects = gcp_cis_utils.get_cloud_kms_enabled_projects()
    for p in projects:
        out_json = gcp_cis_utils.run_gcloud_cmd("kms keyrings list --location=global --project=%s" % p)
        for entry in out_json:
            out_json_2 = gcp_cis_utils.run_gcloud_cmd("kms keys list --keyring=%s --location=global" % entry['name'])
            for entry_2 in out_json_2:
                rotationPeriod = entry_2.get('rotationPeriod')
                nextRotationTime = entry_2.get('nextRotationTime')
                if rotationPeriod is not None:
                    rpd_entry = rpd[rotationPeriod[-1]]
                    if int(rotationPeriod[:-1]) > rpd_entry[0]:
                        details.append(("Rotation period for key [%s] in project [%s] exceeeds 90 days. Currently set to rotate every [%s] %s" % (entry_2['name'], p, rotationPeriod[:-1], rpd_entry[1]), [entry_2['name'], p, "current"], entry_2['name']))
                if nextRotationTime is not None:
                    if '.' in nextRotationTime:
                        nextRotationTime = nextRotationTime.split('.')[0] + 'Z'
                    nrt = datetime.datetime.strptime(nextRotationTime, "%Y-%m-%dT%H:%M:%SZ")
                    if nrt > next90days:
                        details.append(("Next rotation time for key [%s] in project [%s] exceeds 90 days from now. Currently set to rotate next at [%s]" % (entry_2['name'], p, nextRotationTime), [entry_2['name'], p, "next"], entry_2['name']))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.10', '1.10 [Level 1] Ensure KMS encryption keys are rotated within a period of 90 days (Scored)', details, '4', '', '')
    return None

def check1_11():
    # 1.11 Ensure that Separation of duties is enforced while assigning KMS related roles to users (Scored)

    logging.info("1.11 Ensure that Separation of duties is enforced while assigning KMS related roles to users (Scored)")
    details = []
    iam_policies_by_projects = gcp_cis_utils.get_iam_policies_by_projects()
    for p in iam_policies_by_projects.keys():
        out_json = iam_policies_by_projects[p]
        bindings = out_json.get('bindings')
        if bindings is None:
            continue
        ckms_admin_set = set()
        ckms_cke_set = set()
        ckms_ckd_set = set()
        ckms_cked_set = set()
        for entry in bindings:
            gcp_cis_utils.add_members_with_role(entry, "roles/cloudkms.admin", ckms_admin_set)
            gcp_cis_utils.add_members_with_role(entry, "roles/cloudkms.cryptoKeyEncrypter", ckms_cke_set)
            gcp_cis_utils.add_members_with_role(entry, "roles/cloudkms.cryptoKeyDecrypter", ckms_ckd_set)
            gcp_cis_utils.add_members_with_role(entry, "roles/cloudkms.cryptoKeyEncrypterDecrypter", ckms_cked_set)
        intersection = ckms_admin_set.intersection(ckms_cke_set)
        if len(intersection) > 0:
            for tuser in intersection:
                details.append(("Separation of duties is not enforced for IAM user [%s] for roles (Cloud KMS Admin & Cloud KMS CryptoKey Encrypter) in project [%s]" % (tuser, p), [tuser, p, "AdminAndCryptoKeyEncrypter"], tuser))
        intersection = ckms_admin_set.intersection(ckms_ckd_set)
        if len(intersection) > 0:
            for tuser in intersection:
                details.append(("Separation of duties is not enforced for IAM users [%s] for roles (Cloud KMS Admin & Cloud KMS CryptoKey Decrypter) in project [%s]" % (tuser, p), [tuser, p, "AdminAndCryptoKeyDecrypter"], tuser))
        intersection = ckms_admin_set.intersection(ckms_cked_set)
        if len(intersection) > 0:
            for tuser in intersection:
                details.append(("Separation of duties is not enforced for IAM users [%s] for roles (Cloud KMS Admin & Cloud KMS CryptoKey Encrypter/Decrypter) in project [%s]" % (tuser, p),[tuser, p, "AdminAndCryptoKeyEncrypterDecrypter"], tuser))
    if len(details) > 0:
        return gcp_cis_utils.create_issue('cis-gcp-bench-check-1.11', '1.11 [Level 2] Ensure that Separation of duties is enforced while assigning KMS related roles to users (Scored)', details, '5', '', '')
    return None

def check1_12():
    # 1.12 Ensure API keys are not created for a project (Not Scored)

    logging.info("Not supported - 1.12 Ensure API keys are not created for a project (Not Scored)")
    return None

def check1_13():
    # 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps (Not Scored)

    logging.info("Not supported - 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps (Not Scored)")
    return None

def check1_14():
    # 1.14 Ensure API keys are restricted to only APIs that application needs access (Not Scored)

    logging.info("Not supported - 1.14 Ensure API keys are restricted to only APIs that application needs access (Not Scored)")
    return None

def check1_15():
    # 1.15 Ensure API keys are rotated every 90 days (Not Scored)

    logging.info("Not supported - 1.15 Ensure API keys are rotated every 90 days (Not Scored)")
    return None

def run_checks():
    config_issues = []
    gcp_cis_utils.append_issue(config_issues, check1_1())
    gcp_cis_utils.append_issue(config_issues, check1_2())
    gcp_cis_utils.append_issue(config_issues, check1_3())
    gcp_cis_utils.append_issue(config_issues, check1_4())
    gcp_cis_utils.append_issue(config_issues, check1_5())
    gcp_cis_utils.append_issue(config_issues, check1_6())
    gcp_cis_utils.append_issue(config_issues, check1_7())
    gcp_cis_utils.append_issue(config_issues, check1_8())
    gcp_cis_utils.append_issue(config_issues, check1_9())
    gcp_cis_utils.append_issue(config_issues, check1_10())
    gcp_cis_utils.append_issue(config_issues, check1_11())
    gcp_cis_utils.append_issue(config_issues, check1_12())
    gcp_cis_utils.append_issue(config_issues, check1_13())
    gcp_cis_utils.append_issue(config_issues, check1_14())
    gcp_cis_utils.append_issue(config_issues, check1_15())
    return config_issues
