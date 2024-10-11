
# Remediation Report (copied from cis_reports.py)
cis_report_data = {
    "1.1": {
        "Description": "To apply least-privilege security principle, one can create service-level administrators in corresponding groups and assigning specific users to each service-level administrative group in a tenancy. This limits administrative access in a tenancy.<br><br>It means service-level administrators can only manage resources of a specific service.<br><br>Example policies for global/tenant level service-administrators\n<pre>\nAllow group VolumeAdmins to manage volume-family in tenancy\nAllow group ComputeAdmins to manage instance-family in tenancy\nAllow group NetworkAdmins to manage virtual-network-family in tenancy\n</pre>\nOrganizations have various ways of defining service-administrators. Some may prefer creating service administrators at a tenant level and some per department or per project or even per application environment (dev/test/production etc.). Either approach works so long as the policies are written to limit access given to the service-administrators.<br><br>Example policies for compartment level service-administrators <br><br><pre>Allow group NonProdComputeAdmins to manage instance-family in compartment dev\nAllow group ProdComputeAdmins to manage instance-family in compartment production\nAllow group A-Admins to manage instance-family in compartment Project-A\nAllow group A-Admins to manage volume-family in compartment Project-A\n</pre>",
        "Rationale": "Creating service-level administrators helps in tightly controlling access to Oracle Cloud Infrastructure (OCI) services to implement the least-privileged security principle.",
        "Impact": "",
        "Remediation": "Refer to the policy syntax document and create new policies if the audit results indicate that the required policies are missing.",
        "Recommendation": "",
        "Observation": "custom IAM policy that grants tenancy administrative access."
    },
    "1.2": {
        "Description": "There is a built-in OCI IAM policy enabling the Administrators group to perform any action within a tenancy. In the OCI IAM console, this policy reads:<br><br><pre>\nAllow group Administrators to manage all-resources in tenancy\n</pre><br><br>Administrators create more users, groups, and policies to provide appropriate access to other groups.<br><br>Administrators should not allow any-other-group full access to the tenancy by writing a policy like this:<br><br><pre>\nAllow group any-other-group to manage all-resources in tenancy\n</pre><br><br>The access should be narrowed down to ensure the least-privileged principle is applied.",
        "Rationale": "Permission to manage all resources in a tenancy should be limited to a small number of users in the 'Administrators' group for break-glass situations and to set up users/groups/policies when a tenancy is created.<br><br>No group other than 'Administrators' in a tenancy should need access to all resources in a tenancy, as this violates the enforcement of the least privilege principle.",
        "Impact": "",
        "Remediation": "Remove any policy statement that allows any group other than Administrators or any service access to manage all resources in the tenancy.",
        "Recommendation": "Evaluate if tenancy-wide administrative access is needed for the identified policy and update it to be more restrictive.",
        "Observation": "custom IAM policy that grants tenancy administrative access."
    },
    "1.3": {
        "Description": "Tenancy administrators can create more users, groups, and policies to provide other service administrators access to OCI resources.<br><br>For example, an IAM administrator will need to have access to manage\n resources like compartments, users, groups, dynamic-groups, policies, identity-providers, tenancy tag-namespaces, tag-definitions in the tenancy.<br><br>The policy that gives IAM-Administrators or any other group full access to 'groups' resources should not allow access to the tenancy 'Administrators' group.<br><br>The policy statements would look like:<br><br><pre>\nAllow group IAMAdmins to inspect users in tenancy\nAllow group IAMAdmins to use users in tenancy where target.group.name != 'Administrators'\nAllow group IAMAdmins to inspect groups in tenancy\nAllow group IAMAdmins to use groups in tenancy where target.group.name != 'Administrators'\n</pre><br><br><b>Note:</b> You must include separate statements for 'inspect' access, because the target.group.name variable is not used by the ListUsers and ListGroups operations",
        "Rationale": "These policy statements ensure that no other group can manage tenancy administrator users or the membership to the 'Administrators' group thereby gain or remove tenancy administrator access.",
        "Impact": "",
        "Remediation": "Verify the results to ensure that the policy statements that grant access to use or manage users or groups in the tenancy have a condition that excludes access to Administrators group or to users in the Administrators group.",
        "Recommendation": "Evaluate if tenancy-wide administrative access is needed for the identified policy and update it to be more restrictive.",
        "Observation": "custom IAM policy that grants tenancy administrative access."
    },
    "1.4": {
        "Description": "Password policies are used to enforce password complexity requirements. IAM password policies can be used to ensure password are at least a certain length and are composed of certain characters.<br><br>It is recommended the password policy require a minimum password length 14 characters and contain 1 non-alphabetic\ncharacter (Number or 'Special Character').",
        "Rationale": "In keeping with the overall goal of having users create a password that is not overly weak, an eight-character minimum password length is recommended for an MFA account, and 14 characters for a password only account. In addition, maximum password length should be made as long as possible based on system/software capabilities and not restricted by policy.<br><br>In general, it is true that longer passwords are better (harder to crack), but it is also true that forced password length requirements can cause user behavior that is predictable and undesirable. For example, requiring users to have a minimum 16-character password may cause them to choose repeating patterns like fourfourfourfour or passwordpassword that meet the requirement but aren't hard to guess. Additionally, length requirements increase the chances that users will adopt other insecure practices, like writing them down, re-using them or storing them unencrypted in their documents. <br><br>Password composition requirements are a poor defense against guessing attacks. Forcing users to choose some combination of upper-case, lower-case, numbers, and special characters has a negative impact. It places an extra burden on users and many\nwill use predictable patterns (for example, a capital letter in the first position, followed by lowercase letters, then one or two numbers, and a “special character” at the end). Attackers know this, so dictionary attacks will often contain these common patterns and use the most common substitutions like, $ for s, @ for a, 1 for l, 0 for o.<br><br>Passwords that are too complex in nature make it harder for users to remember, leading to bad practices. In addition, composition requirements provide no defense against common attack types such as social engineering or insecure storage of passwords.",
        "Impact": "",
        "Remediation": "Update the password policy such as minimum length to 14, password must contain expected special characters and numeric characters.",
        "Recommendation": "It is recommended the password policy require a minimum password length 14 characters and contain 1 non-alphabetic character (Number or 'Special Character').",
        "Observation": "password policy/policies that do not enforce sufficient password complexity requirements."
    },
    "1.5": {
        "Description": "IAM password policies can require passwords to be rotated or expired after a given number of days. It is recommended that the password policy expire passwords after 365 and are changed immediately based on events.",
        "Rationale": "Excessive password expiration requirements do more harm than good, because these requirements make users select predictable passwords, composed of sequential words and numbers that are closely related to each other. In these cases, the next password can be predicted based on the previous one (incrementing a number used in the password for example). Also, password expiration requirements offer no containment benefits because attackers will often use credentials as soon as they compromise them. Instead, immediate password changes should be based on key events including, but not limited to:<br><br>1. Indication of compromise<br>2. Change of user roles<br>3. When a user leaves the organization.<br><br>Not only does changing passwords every few weeks or months frustrate the user, it's been suggested that it does more harm than good, because it could lead to bad practices by the user such as adding a character to the end of their existing password.<br><br>In addition, we also recommend a yearly password change. This is primarily because for all their good intentions users will share credentials across accounts. Therefore, even if a breach is publicly identified, the user may not see this notification, or forget they have an account on that site. This could leave a shared credential vulnerable indefinitely. Having an organizational policy of a 1-year (annual) password expiration is a reasonable compromise to mitigate this with minimal user burden.",
        "Impact": "",
        "Remediation": "Update the password policy by setting number of days configured in Expires after to 365.",
        "Recommendation": "Evaluate password rotation policies are inline with your organizational standard.",
        "Observation": "password policy/policies that do require rotation."
    },
    "1.6": {
        "Description": "IAM password policies can prevent the reuse of a given password by the same user. It is recommended the password policy prevent the reuse of passwords.",
        "Rationale": "Enforcing password history ensures that passwords are not reused in for a certain period of time by the same user. If a user is not allowed to use last 24 passwords, that window of time is greater. This helps maintain the effectiveness of password security.",
        "Impact": "",
        "Remediation": "Update the number of remembered passwords in previous passwords remembered setting to 24 in the password policy.",
        "Recommendation": "Evaluate password reuse policies are inline with your organizational standard.",
        "Observation": "password policy/policies that do prevent reuse."
    },
    "1.7": {
        "Description": "Multi-factor authentication is a method of authentication that requires the use of more than one factor to verify a user's identity.<br><br>With MFA enabled in the IAM service, when a user signs in to Oracle Cloud Infrastructure, they are prompted for their user name and password, which is the first factor (something that they know). The user is then prompted to provide a second verification code from a registered MFA device, which is the second factor (something that they have). The two factors work together, requiring an extra layer of security to verify the user's identity and complete the sign-in process.<br><br>OCI IAM supports two-factor authentication using a password (first factor) and a device that can generate a time-based one-time password (TOTP) (second factor).<br><br>See [OCI documentation](https://docs.cloud.oracle.com/en-us/iaas/Content/Identity/Tasks/usingmfa.htm) for more details.",
        "Rationale": "Multi factor authentication adds an extra layer of security during the login process and makes it harder for unauthorized users to gain access to OCI resources.",
        "Impact": "",
        "Remediation": "Each user must enable MFA for themselves using a device they will have access to every time they sign in. An administrator cannot enable MFA for another user but can enforce MFA by identifying the list of non-complaint users, notifying them or disabling access by resetting password for non-complaint accounts.",
        "Recommendation": "Evaluate if local users are required. For Break Glass accounts ensure MFA is in place.",
        "Observation": "users with Password access but not MFA."
    },
    "1.8": {
        "Description": "API keys are used by administrators, developers, services and scripts for accessing OCI APIs directly or via SDKs/OCI CLI to search, create, update or delete OCI resources.<br><br>The API key is an RSA key pair. The private key is used for signing the API requests and the public key is associated with a local or synchronized user's profile.",
        "Rationale": "It is important to secure and rotate an API key every 90 days or less as it provides the same level of access that a user it is associated with has.<br><br>In addition to a security engineering best practice, this is also a compliance requirement. For example, PCI-DSS Section 3.6.4 states, \"Verify that key-management procedures include a defined cryptoperiod for each key type in use and define a process for key changes at the end of the defined crypto period(s).\"",
        "Impact": "",
        "Remediation": "Delete any API Keys with a date of 90 days or older under the Created column of the API Key table.",
        "Recommendation": "Evaluate if APIs Keys are still used/required and rotate API Keys It is important to secure and rotate an API key every 90 days or less as it provides the same level of access that a user it is associated with has.",
        "Observation": "user(s) with APIs that have not been rotated with 90 days."
    },
    "1.9": {
        "Description": "Object Storage provides an API to enable interoperability with Amazon S3. To use this Amazon S3 Compatibility API, you need to generate the signing key required to authenticate with Amazon S3.<br><br>This special signing key is an Access Key/Secret Key pair. Oracle generates the Customer Secret key to pair with the Access Key.",
        "Rationale": "It is important to secure and rotate an customer secret key every 90 days or less as it provides the same level of object storage access that a user is associated with has.",
        "Impact": "",
        "Remediation": "Delete any Access Keys with a date of 90 days or older under the Created column of the Customer Secret Keys.",
        "Recommendation": "Evaluate if Customer Secret Keys are still used/required and rotate the Keys accordingly.",
        "Observation": "users with Customer Secret Keys that have not been rotated with 90 days."
    },
    "1.10": {
        "Description": "Auth tokens are authentication tokens generated by Oracle. You use auth tokens to authenticate with APIs that do not support the Oracle Cloud Infrastructure signature-based authentication. If the service requires an auth token, the service-specific documentation instructs you to generate one and how to use it.",
        "Rationale": "It is important to secure and rotate an auth token every 90 days or less as it provides the same level of access to APIs that do not support the OCI signature-based authentication as the user associated to it.",
        "Impact": "",
        "Remediation": "Delete any auth token with a date of 90 days or older under the Created column of the Auth Tokens.",
        "Recommendation": "Evaluate if Auth Tokens are still used/required and rotate Auth tokens.",
        "Observation": "user(s) with auth tokens that have not been rotated in 90 days."
    },
    "1.11": {
        "Description": "Users can create and manage their database password in their IAM user profile and use that password to authenticate to databases in their tenancy. An IAM database password is a different password than an OCI Console password. Setting an IAM database password allows an authorized IAM user to sign in to one or more Autonomous Databases in their tenancy. An IAM database password is a different password than an OCI Console password. Setting an IAM database password allows an authorized IAM user to sign in to one or more Autonomous Databases in their tenancy.",
        "Rationale": "It is important to secure and rotate an IAM Database password 90 days or less as it provides the same access the user would have a using a local database user.",
        "Impact": "",
        "Remediation": "Delete any database password with a date of 90 days or older under the Created column of the Database Password.",
        "Recommendation": "Evaluate if database password are still used/required and rotate database passwords.",
        "Observation": "user(s) with Database passwords that have not been rotated in 90 days."
    },
    "1.12": {
        "Description": "Tenancy administrator users have full access to the organization's OCI tenancy. API keys associated with user accounts are used for invoking the OCI APIs via custom programs or clients like CLI/SDKs. The clients are typically used for performing day-to-day operations and should never require full tenancy access. Service-level administrative users with API keys should be used instead.",
        "Rationale": "For performing day-to-day operations tenancy administrator access is not needed.\nService-level administrative users with API keys should be used to apply privileged security principle.",
        "Impact": "",
        "Remediation": "For each tenancy administrator user who has an API key,select API Keys from the menu and delete any associated keys from the API Keys table.",
        "Recommendation": "Evaluate if a user with API Keys requires Administrator access and use a least privilege approach.",
        "Observation": "users with Administrator access and API Keys."
    },
    "1.13": {
        "Description": "All OCI IAM local user accounts have an email address field associated with the account. It is recommended to specify an email address that is valid and current.<br><br>If you have an email address in your user profile, you can use the Forgot Password link on the sign on page to have a temporary password sent to you.",
        "Rationale": "Having a valid and current email address associated with an OCI IAM local user account allows you to tie the account to identity in your organization. It also allows that user to reset their password if it is forgotten or lost.",
        "Impact": "",
        "Remediation": "Update the current email address in the email text box on exch non compliant user.",
        "Recommendation": "Add emails to users to allow them to use the 'Forgot Password' feature and uniquely identify the user. For service accounts it could be a mail alias.",
        "Observation": "user(s) without an email."
    },
    "1.14": {
        "Description": "OCI instances, OCI database and OCI functions can access other OCI resources either via an OCI API key associated to a user or by being including in a Dynamic Group that has an IAM policy granting it the required access. Access to OCI Resources refers to making API calls to another OCI resource like Object Storage, OCI Vaults, etc.",
        "Rationale": "Dynamic Groups reduces the risks related to hard coded credentials. Hard coded API keys can be shared and require rotation which can open them up to being compromised. Compromised credentials could allow access to OCI services outside of the expected radius.",
        "Impact": "For an OCI instance that contains embedded credential audit the scripts and environment variables to ensure that none of them contain OCI API Keys or credentials.",
        "Remediation": "Create Dynamic group and Enter Matching Rules to that includes the instances accessing your OCI resources. Refer:\"https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingdynamicgroups.htm\".",
        "Recommendation": "Evaluate how your instances, functions, and autonomous database interact with other OCI services.",
        "Observation": "Dynamic Groups reduces the risks related to hard coded credentials. Hard coded API keys can be shared and require rotation which can open them up to being compromised. Compromised credentials could allow access to OCI services outside of the expected radius."
    },
    "1.15": {
        "Description": "To apply the separation of duties security principle, one can restrict service-level administrators from being able to delete resources they are managing. It means service-level administrators can only manage resources of a specific service but not delete resources for that specific service.<br><br>Example policies for global/tenant level for block volume service-administrators:\n<pre>\nAllow group VolumeUsers to manage volumes in tenancy where request.permission!='VOLUME_DELETE'\nAllow group VolumeUsers to manage volume-backups in tenancy where request.permission!='VOLUME_BACKUP_DELETE'\n</pre><br>Example policies for global/tenant level for file storage system service-administrators:<br><pre>\nAllow group FileUsers to manage file-systems in tenancy where request.permission!='FILE_SYSTEM_DELETE'\nAllow group FileUsers to manage mount-targets in tenancy where request.permission!='MOUNT_TARGET_DELETE'\nAllow group FileUsers to manage export-sets in tenancy where request.permission!='EXPORT_SET_DELETE'\n</pre><br><br>Example policies for global/tenant level for object storage system service-administrators:<br><pre>\nAllow group BucketUsers to manage objects in tenancy where request.permission!='OBJECT_DELETE'\nAllow group BucketUsers to manage buckets in tenancy where request.permission!='BUCKET_DELETE'\n</pre>",
        "Rationale": "Creating service-level administrators without the ability to delete the resource they are managing helps in tightly controlling access to Oracle Cloud Infrastructure (OCI) services by implementing the separation of duties security principle.", "Impact": "",
        "Remediation": "Add the appropriate where condition to any policy statement that allows the storage service-level to manage the storage service.",
        "Recommendation": "To apply a separation of duties security principle, it is recommended to restrict service-level administrators from being able to delete resources they are managing.",
        "Observation": "IAM Policies that give service administrator the ability to delete service resources."
    },
    "2.1": {
        "Description": "Security lists provide stateful or stateless filtering of ingress/egress network traffic to OCI resources on a subnet level. It is recommended that no security group allows unrestricted ingress access to port 22.",
        "Rationale": "Removing unfettered connectivity to remote console services, such as Secure Shell (SSH), reduces a server's exposure to risk.",
        "Impact": "For updating an existing environment, care should be taken to ensure that administrators currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or 3389 through another network security group or security list.",
        "Remediation": "For each security list in the returned results, click the security list name. Either edit the ingress rule to be more restrictive, delete the ingress rule or click on the VCN and terminate the security list as appropriate.",
        "Recommendation": "Review the security lists. If they are not used(attached to a subnet) they should be deleted if possible or empty. For attached security lists it is recommended to restrict the CIDR block to only allow access to Port 22 from known networks.",
        "Observation": "Security lists that allow internet access to port 22. (Note this does not necessarily mean external traffic can reach a compute instance)."
    },
    "2.2": {
        "Description": "Security lists provide stateful or stateless filtering of ingress/egress network traffic to OCI resources on a subnet level. It is recommended that no security group allows unrestricted ingress access to port 3389.",
        "Rationale": "Removing unfettered connectivity to remote console services, such as Remote Desktop Protocol (RDP), reduces a server's exposure to risk.",
        "Impact": "For updating an existing environment, care should be taken to ensure that administrators currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or 3389 through another network security group or security list.",
        "Remediation": "For each security list in the returned results, click the security list name. Either edit the ingress rule to be more restrictive, delete the ingress rule or click on the VCN and terminate the security list as appropriate.",
        "Recommendation": "Review the security lists. If they are not used(attached to a subnet) they should be deleted if possible or empty. For attached security lists it is recommended to restrict the CIDR block to only allow access to Port 3389 from known networks.",
        "Observation": "Security lists that allow internet access to port 3389. (Note this does not necessarily mean external traffic can reach a compute instance)."
    },
    "2.3": {
        "Description": "Network security groups provide stateful filtering of ingress/egress network traffic to OCI resources. It is recommended that no security group allows unrestricted ingress access to port 22.",
        "Rationale": "Removing unfettered connectivity to remote console services, such as Secure Shell (SSH), reduces a server's exposure to risk.",
        "Impact": "For updating an existing environment, care should be taken to ensure that administrators currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or 3389 through another network security group or security list.",
        "Remediation": "Using the details returned from the audit procedure either Remove the security rules or Update the security rules.",
        "Recommendation": "Review the network security groups. If they are not used(attached to a subnet) they should be deleted if possible or empty. For attached security lists it is recommended to restrict the CIDR block to only allow access to Port 3389 from known networks.",
        "Observation": "Network security groups that allow internet access to port 22. (Note this does not necessarily mean external traffic can reach a compute instance)."
    },
    "2.4": {
        "Description": "Network security groups provide stateful filtering of ingress/egress network traffic to OCI resources. It is recommended that no security group allows unrestricted ingress access to port 3389.",
        "Rationale": "Removing unfettered connectivity to remote console services, such as Remote Desktop Protocol (RDP), reduces a server's exposure to risk.",
        "Impact": "For updating an existing environment, care should be taken to ensure that administrators currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or 3389 through another network security group or security list.",
        "Remediation": "Using the details returned from the audit procedure either Remove the security rules or Update the security rules.",
        "Recommendation": "Review the network security groups. If they are not used(attached to a subnet) they should be deleted if possible or empty. For attached network security groups it is recommended to restrict the CIDR block to only allow access to Port 3389 from known networks.",
        "Observation": "Network security groups that allow internet access to port 3389. (Note this does not necessarily mean external traffic can reach a compute instance)."
    },
    "2.5": {
        "Description": "A default security list is created when a Virtual Cloud Network (VCN) is created. Security lists provide stateful filtering of ingress and egress network traffic to OCI resources. It is recommended no security list allows unrestricted ingress access to Secure Shell (SSH) via port 22.",
        "Rationale": "Removing unfettered connectivity to remote console services, such as SSH on port 22, reduces a server's exposure to unauthorized access.",
        "Impact": "For updating an existing environment, care should be taken to ensure that administrators currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or 3389 through another security group.",
        "Remediation": "Select Default Security List for <VCN Name> and Remove the Ingress Rule with Source 0.0.0.0/0, IP Protocol 22 and Destination Port Range 22.",
        "Recommendation": "Create specific custom security lists with workload specific rules and attach to subnets.",
        "Observation": "Default Security lists that allow more traffic then ICMP."
    },
    "2.6": {
        "Description": "Oracle Integration (OIC) is a complete, secure, but lightweight integration solution that enables you to connect your applications in the cloud. It simplifies connectivity between your applications and connects both your applications that live in the cloud and your applications that still live on premises. Oracle Integration provides secure, enterprise-grade connectivity regardless of the applications you are connecting or where they reside. OIC instances are created within an Oracle managed secure private network with each having a public endpoint. The capability to configure ingress filtering of network traffic to protect your OIC instances from unauthorized network access is included. It is recommended that network access to your OIC instances be restricted to your approved corporate IP Addresses or Virtual Cloud Networks (VCN)s.",
        "Rationale": "Restricting connectivity to OIC Instances reduces an OIC instance's exposure to risk.",
        "Impact": "When updating ingress filters for an existing environment, care should be taken to ensure that IP addresses and VCNs currently used by administrators, users, and services to access your OIC instances are included in the updated filters.",
        "Remediation": "For each OIC instance in the returned results, select the OIC Instance name,edit the Network Access to be more restrictive.",
        "Recommendation": "It is recommended that OIC Network Access is restricted to your corporate IP Addresses or VCNs for OIC Instances.",
        "Observation": "OIC Instances that allow unfiltered public ingress traffic (Authentication and authorization is still required)."
    },
    "2.7": {
        "Description": "Oracle Analytics Cloud (OAC) is a scalable and secure public cloud service that provides a full set of capabilities to explore and perform collaborative analytics for you, your workgroup, and your enterprise. OAC instances provide ingress filtering of network traffic or can be deployed with in an existing Virtual Cloud Network VCN. It is recommended that all new OAC instances be deployed within a VCN and that the Access Control Rules are restricted to your corporate IP Addresses or VCNs for existing OAC instances.",
        "Rationale": "Restricting connectivity to Oracle Analytics Cloud instances reduces an OAC instance's exposure to risk.",
        "Impact": "When updating ingress filters for an existing environment, care should be taken to ensure that IP addresses and VCNs currently used by administrators, users, and services to access your OAC instances are included in the updated filters. Also, these changes will temporarily bring the OAC instance offline.",
        "Remediation": "For each OAC instance in the returned results, select the OAC Instance name edit the Access Control Rules by clicking +Another Rule and add rules as required.",
        "Recommendation": "It is recommended that all new OAC instances be deployed within a VCN and that the Access Control Rules are restricted to your corporate IP Addresses or VCNs for existing OAC instances.",
        "Observation": "OAC Instances that allow unfiltered public ingress traffic (Authentication and authorization is still required)."
    },
    "2.8": {
        "Description": "Oracle Autonomous Database Shared (ADB-S) automates database tuning, security, backups, updates, and other routine management tasks traditionally performed by DBAs. ADB-S provide ingress filtering of network traffic or can be deployed within an existing Virtual Cloud Network (VCN). It is recommended that all new ADB-S databases be deployed within a VCN and that the Access Control Rules are restricted to your corporate IP Addresses or VCNs for existing ADB-S databases.",
        "Rationale": "Restricting connectivity to ADB-S Databases reduces an ADB-S database's exposure to risk.",
        "Impact": "When updating ingress filters for an existing environment, care should be taken to ensure that IP addresses and VCNs currently used by administrators, users, and services to access your ADB-S instances are included in the updated filters.",
        "Remediation": "For each ADB-S database in the returned results, select the ADB-S database name edit the Access Control Rules by clicking +Another Rule and add rules as required.",
        "Recommendation": "It is recommended that all new ADB-S databases be deployed within a VCN and that the Access Control Rules are restricted to your corporate IP Addresses or VCNs for existing ADB-S databases.",
        "Observation": "ADB-S Instances that allow unfiltered public ingress traffic (Authentication and authorization is still required)."
    },
    "3.1": {
        "Description": "Compute Instances that utilize Legacy MetaData service endpoints (IMDSv1) are susceptible to potential SSRF attacks. To bolster security measures, it is strongly advised to reconfigure Compute Instances to adopt Instance Metadata Service v2, aligning with the industry's best security practices.",
        "Rationale": "Enabling Instance Metadata Service v2 enhances security and grants precise control over metadata access. Transitioning from IMDSv1 reduces the risk of SSRF attacks, bolstering system protection.  IMDv1 poses security risks due to its inferior security measures and limited auditing capabilities. Transitioning to IMDv2 ensures a more secure environment with robust security features and improved monitoring capabilities.",
        "Impact": "If you disable IMDSv1 on an instance that does not support IMDSv2, you might not be able to connect to the instance when you launch it.",
        "Remediation": "For each instance select the instance name, under the Instance Details section, next to Instance Metadata Service, click Edit and for the Instance metadata service, select the Version 2 only option.",
        "Recommendation": "It is recommended that all OCI instances use Instance Metadata Service version 2 (IMDSv2).",
        "Observation": "Instances that allow Instance Metadata Service v1."
    },
    "3.2": {
        "Description": "Shielded Instances with Secure Boot enabled prevents unauthorized boot loaders and operating systems from booting. This prevent rootkits, bootkits, and unauthorized software from running before the operating system loads. Secure Boot verifies the digital signature of the system's boot software to check its authenticity. The digital signature ensures the operating system has not been tampered with and is from a trusted source. When the system boots and attempts to execute the software, it will first check the digital signature to ensure validity. If the digital signature is not valid, the system will not allow the software to run. Secure Boot is a feature of UEFI(Unified Extensible Firmware Interface) that only allows approved operating systems to boot up.",
        "Rationale": "A Threat Actor with access to the operating system may seek to alter boot components to persist malware or rootkits during system initialization. Secure Boot helps ensure that the system only runs authentic software by verifying the digital signature of all boot components.",
        "Impact": " To enable you have to terminate the instance and create a new one. Also, Shielded instances do not support live migration. During an infrastructure maintenance event, Oracle Cloud Infrastructure live migrates supported VM instances from the physical VM host that needs maintenance to a healthy VM host with minimal disruption to running instances. If you enable Secure Boot on an instance, the instance cannot be migrated, because the hardware TPM is not migratable. This may result in an outage because the TPM can't be migrate from a unhealthy host to healthy host.",
        "Remediation": "Terminate the old instance. Create a new instance and ensure on Secure Boot is toggled on under the Security section.",
        "Recommendation": "",
        "Observation": "Instances that don't enable Secure Boot."
    },
    "3.3": {
        "Description": "The Block Volume service provides the option to enable in-transit encryption for paravirtualized volume attachments on virtual machine (VM) instances.",
        "Rationale": "All the data moving between the instance and the block volume is transferred over an internal and highly secure network. If you have specific compliance requirements related to the encryption of the data while it is moving between the instance and the block volume, you should enable the in-transit encryption option.",
        "Impact": "In-transit encryption for boot and block volumes is only available for virtual machine (VM) instances launched from platform images, along with bare metal instances that use the following shapes: BM.Standard.E3.128, BM.Standard.E4.128, BM.DenseIO.E4.128. It is not supported on other bare metal instances.",
        "Remediation": "Terminate the old instance. Create a new instance and ensure Use in-transit encryption is toggled on under the Boot volume section.",
        "Recommendation": "",
        "Observation": "Instances that don't enable in-transit encryption."
    },
    "4.1": {
        "Description": "Using default tags is a way to ensure all resources that support tags are tagged during creation. Tags can be based on static values or based on computed values. It is recommended to setup default tags early on to ensure all created resources will get tagged.\nTags are scoped to Compartments and are inherited by Child Compartments. The recommendation is to create default tags like “CreatedBy” at the Root Compartment level to ensure all resources get tagged.\nWhen using Tags it is important to ensure that Tag Namespaces are protected by IAM Policies otherwise this will allow users to change tags or tag values.\nDepending on the age of the OCI Tenancy there may already be Tag defaults setup at the Root Level and no need for further action to implement this action.",
        "Rationale": "In the case of an incident having default tags like “CreatedBy” applied will provide info on who created the resource without having to search the Audit logs.",
        "Impact": "There is no performance impact when enabling the above described features",
        "Remediation": "Update the root compartments tag default link.In the Tag Defaults table verify that there is a Tag with a value of \"${iam.principal.names}\" and a Tag Key Status of Active. Also create a Tag key definition by providing a Tag Key, Description and selecting 'Static Value' for Tag Value Type.",
        "Recommendation": "",
        "Observation": "default tags are used on resources."
    },
    "4.2": {
        "Description": "Notifications provide a multi-channel messaging service that allow users and applications to be notified of events of interest occurring within OCI. Messages can be sent via eMail, HTTPs, PagerDuty, Slack or the OCI Function service. Some channels, such as eMail require confirmation of the subscription before it becomes active.",
        "Rationale": "Creating one or more notification topics allow administrators to be notified of relevant changes made to OCI infrastructure.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Create a Topic in the notifications service under the appropriate compartment and add the subscriptions with current email address and correct protocol.",
        "Recommendation": "",
        "Observation": "notification topic and subscription for receiving monitoring alerts are configured."
    },
    "4.3": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when Identity Providers are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments. It is recommended to create the Event rule at the root compartment level.",
        "Rationale": "OCI Identity Providers allow management of User ID / passwords in external systems and use of those credentials to access OCI resources. Identity Providers allow users to single sign-on to OCI console and have other OCI credentials like API Keys.\nMonitoring and alerting on changes to Identity Providers will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Create a Rule Condition in the Events services by selecting Identity in the Service Name Drop-down and selecting Identity Provider – Create, Identity Provider - Delete and Identity Provider – Update. In the Actions section select Notifications as Action Type and selct the compartment and topic to be used.",
        "Recommendation": "",
        "Observation": "notifications have been configured for Identity Provider changes."
    },
    "4.4": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when Identity Provider Group Mappings are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments. It is recommended to create the Event rule at the root compartment level",
        "Rationale": "IAM Policies govern access to all resources within an OCI Tenancy. IAM Policies use OCI Groups for assigning the privileges. Identity Provider Groups could be mapped to OCI Groups to assign privileges to federated users in OCI. Monitoring and alerting on changes to Identity Provider Group mappings will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Find and click the Rule that handles Idp Group Mapping Changes. Click the Edit Rule button and verify that the RuleConditions section contains a condition for the Service Identity and Event Types: Idp Group Mapping – Create, Idp Group Mapping – Delete, and Idp Group Mapping – Update and confirm Action Type contains: Notifications and that a valid Topic is referenced.",
        "Recommendation": "",
        "Observation": "notifications have been configured for Identity Provider Group Mapping changes."
    },
    "4.5": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when IAM Groups are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "IAM Groups control access to all resources within an OCI Tenancy.\n Monitoring and alerting on changes to IAM Groups will help in identifying changes to satisfy least privilege principle.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Create a Rule Condition by selecting Identity in the Service Name Drop-down and selecting Group – Create, Group – Delete and Group – Update. In the Actions section select Notifications as Action Type and selct the compartment and topic to be used.",
        "Recommendation": "",
        "Observation": "notifications have been configured for IAM Group changes."
    },
    "4.6": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when IAM Policies are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "IAM Policies govern access to all resources within an OCI Tenancy.\n Monitoring and alerting on changes to IAM policies will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Create a Rule Condition by selecting Identity in the Service Name Drop-down and selecting Policy – Change Compartment, Policy – Create, Policy - Delete and Policy – Update. In the Actions section select Notifications as Action Type and selct the compartment and topic to be used.",
        "Recommendation": "",
        "Observation": "notifications have been configured for IAM Policy changes."
    },
    "4.7": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when IAM Users are created, updated, deleted, capabilities updated, or state updated. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Users use or manage Oracle Cloud Infrastructure resources.\n Monitoring and alerting on changes to Users will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Edit Rule that handles IAM User Changes and verify that the Rule Conditions section contains a condition for the Service Identity and Event Types: User – Create, User – Delete, User – Update, User Capabilities – Update, User State – Update.",
        "Recommendation": "",
        "Observation": "notifications have been configured for user changes."
    },
    "4.8": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when Virtual Cloud Networks are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Virtual Cloud Networks (VCNs) closely resembles a traditional network.\n Monitoring and alerting on changes to VCNs will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Edit Rule that handles VCN Changes and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: VCN – Create, VCN - Delete, and VCN – Update.",
        "Recommendation": "",
        "Observation": "notifications have been configured for VCN changes."
    },
    "4.9": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when route tables are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Route tables control traffic flowing to or from Virtual Cloud Networks and Subnets.\n Monitoring and alerting on changes to route tables will help in identifying changes these traffic flows.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Edit Rule that handles Route Table Changes and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: Route Table – Change Compartment, Route Table – Create, Route Table - Delete, and Route Table – Update.",
        "Recommendation": "",
        "Observation": "notifications have been configured for changes to route tables."
    },
    "4.10": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when security lists are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Security Lists control traffic flowing into and out of Subnets within a Virtual Cloud Network.\n Monitoring and alerting on changes to Security Lists will help in identifying changes to these security controls.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Edit Rule that handles Security List Changes and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: Security List – Change Compartment, Security List – Create, Security List - Delete, and Security List – Update.",
        "Recommendation": "",
        "Observation": "notifications have been configured for security list changes."
    },
    "4.11": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when network security groups are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Network Security Groups control traffic flowing between Virtual Network Cards attached to Compute instances.\n Monitoring and alerting on changes to Network Security Groups will help in identifying changes these security controls.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Edit Rule that handles Network Security Group changes and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: Network Security Group – Change Compartment, Network Security Group – Create, Network Security Group - Delete, and Network Security Group – Update.",
        "Recommendation": "",
        "Observation": "notifications have been configured for changes on Network Service Groups."
    },
    "4.12": {
        "Description": "It is recommended to setup an Event Rule and Notification that gets triggered when Network Gateways are created, updated, deleted, attached, detached, or moved. This recommendation includes Internet Gateways, Dynamic Routing Gateways, Service Gateways, Local Peering Gateways, and NAT Gateways. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Network Gateways act as routers between VCNs and the Internet, Oracle Services Networks, other VCNS, and on-premise networks.\n Monitoring and alerting on changes to Network Gateways will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Edit Rule that handles Network Gateways Changes and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: DRG – Create, DRG - Delete, DRG - Update, DRG Attachment – Create, DRG Attachment – Delete, DRG Attachment - Update, Internet Gateway – Create, Internet Gateway – Delete, Internet Gateway - Update, Internet Gateway – Change Compartment, Local Peering Gateway – Create, Local Peering Gateway – Delete End, Local Peering Gateway - Update, Local Peering Gateway – Change Compartment, NAT Gateway – Create, NAT Gateway – Delete, NAT Gateway - Update, NAT Gateway – Change Compartment,Compartment, Service Gateway – Create, Service Gateway – Delete Begin, Service Gateway – Delete End, Service Gateway – Update, Service Gateway – Attach Service, Service Gateway – Detach Service, Service Gateway – Change Compartment.",
        "Recommendation": "",
        "Observation": "notifications have been configured for changes on network gateways."
    },
    "4.13": {
        "Description": "VCN flow logs record details about traffic that has been accepted or rejected based on the security list rule.",
        "Rationale": "Enabling VCN flow logs enables you to monitor traffic flowing within your virtual network and can be used to detect anomalous traffic.",
        "Impact": "Enabling VCN flow logs will not affect the performance of your virtual network but it will generate additional use of object storage that should be controlled via object lifecycle management.<br><br>By default, VCN flow logs are stored for 30 days in object storage. Users can specify a longer retention period.",
        "Remediation": "Enable Flow Logs (all records) on Virtual Cloud Networks (subnets) under the relevant resource compartment. Before hand create Log group if not exist in the Log services.",
        "Recommendation": "",
        "Observation": "VCNs have no flow logging configured."
    },
    "4.14": {
        "Description": "Cloud Guard detects misconfigured resources and insecure activity within a tenancy and provides security administrators with the visibility to resolve these issues. Upon detection, Cloud Guard can suggest, assist, or take corrective actions to mitigate these issues. Cloud Guard should be enabled in the root compartment of your tenancy with the default configuration, activity detectors and responders.",
        "Rationale": "Cloud Guard provides an automated means to monitor a tenancy for resources that are configured in an insecure manner as well as risky network activity from these resources.",
        "Impact": "There is no performance impact when enabling the above described features, but additional IAM policies will be required.",
        "Remediation": "Enable the cloud guard by selecting the services in the menu and provide appropriate reporting region and other configurations.",
        "Recommendation": "",
        "Observation": "Cloud Guard has not been configured in the root compartment of the tenancy."
    },
    "4.15" : {
        "Description": "Cloud Guard detects misconfigured resources and insecure activity within a tenancy and provides security administrators with the visibility to resolve these issues. Upon detection, Cloud Guard generates a Problem. It is recommended to setup an Event Rule and Notification that gets triggered when Oracle Cloud Guard Problems are created, dismissed or remediated. Event Rules are compartment scoped and will detect events in child compartments. It is recommended to create the Event rule at the root compartment level.",
        "Rationale": "Cloud Guard provides an automated means to monitor a tenancy for resources that are configured in an insecure manner as well as risky network activity from these resources. Monitoring and alerting on Problems detected by Cloud Guard will help in identifying changes to the security posture.",
        "Impact": "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.",
        "Remediation": "Create a Rule Condition by selecting Cloud Guard in the Service Name Drop-down and selecting Detected – Problem, Remediated – Problem and Dismissed - Problem. In the Actions section select Notifications as Action Type and selct the compartment and topic to be used.",
        "Recommendation": "",
        "Observation": "notifications have been configured for Cloud Guard Problems."
    },
    "4.16": {
        "Description": "Oracle Cloud Infrastructure Vault securely stores master encryption keys that protect your encrypted data. You can use the Vault service to rotate keys to generate new cryptographic material. Periodically rotating keys limits the amount of data encrypted by one key version.",
        "Rationale": "Rotating keys annually limits the data encrypted under one key version. Key rotation thereby reduces the risk in case a key is ever compromised.",
        "Impact": "",
        "Remediation": "Select the security service and select vault. Ensure the date of each Master Encryption Key under the Created column of the Master Encryption key is no more than 365 days old.",
        "Recommendation": "",
        "Observation": "customer-managed keys are older than one year."
    },
    "4.17": {
        "Description": "Object Storage write logs will log all write requests made to objects in a bucket.",
        "Rationale": "Enabling an Object Storage write log, the 'requestAction' property would contain values of 'PUT', 'POST', or 'DELETE'. This will provide you more visibility into changes to objects in your buckets.",
        "Impact": "There is no performance impact when enabling the above described features, but will generate additional use of object storage that should be controlled via object lifecycle management.<br><br>By default, Object Storage logs are stored for 30 days in object storage. Users can specify a longer retention period.",
        "Remediation": "To the relevant bucket enable log by providing Write Access Events from the Log Category. Beforehand create log group if required.",
        "Recommendation": "",
        "Observation": "object stores have no write level logging enabled."
    },
    "5.1.1": {
        "Description": "A bucket is a logical container for storing objects. It is associated with a single compartment that has policies that determine what action a user can perform on a bucket and on all the objects in the bucket. It is recommended that no bucket be publicly accessible.",
        "Rationale": "Removing unfettered reading of objects in a bucket reduces an organization's exposure to data loss.",
        "Impact": "For updating an existing bucket, care should be taken to ensure objects in the bucket can be accessed through either IAM policies or pre-authenticated requests.",
        "Remediation": "Edit the visibility into 'private' for each Bucket.",
        "Recommendation": "",
        "Observation": "object storage buckets are publicly visible."
    },
    "5.1.2": {
        "Description": "Oracle Object Storage buckets support encryption with a Customer Managed Key (CMK). By default, Object Storage buckets are encrypted with an Oracle managed key.",
        "Rationale": "Encryption of Object Storage buckets with a Customer Managed Key (CMK) provides an additional level of security on your data by allowing you to manage your own encryption key lifecycle management for the bucket.",
        "Impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master Key. In addition, you must authorize Object Storage service to use keys on your behalf.<br><br>Required Policy:\n<pre>\nAllow service objectstorage-&lt;region_name>, to use keys in compartment &ltcompartment-id> where target.key.id = '&lt;key_OCID>'<br><br></pre>",
        "Remediation": "Assign Master encryption key to Encryption key in every Object storage under Bucket name by clicking assign and select vault.",
        "Recommendation": "",
        "Observation": "object store buckets do not use Customer-Managed Keys (CMK)."
    },
    "5.1.3": {
        "Description": "A bucket is a logical container for storing objects. Object versioning is enabled at the bucket level and is disabled by default upon creation. Versioning directs Object Storage to automatically create an object version each time a new object is uploaded, an existing object is overwritten, or when an object is deleted. You can enable object versioning at bucket creation time or later.",
        "Rationale": "Versioning object storage buckets provides for additional integrity of your data. Management of data integrity is critical to protecting and accessing protected data. Some customers want to identify object storage buckets without versioning in order to apply their own data lifecycle protection and management policy.",
        "Impact": "",
        "Remediation": "Enable Versioning by clicking on every bucket by editing the bucket configuration.",
        "Recommendation": "",
        "Observation": "object store buckets have no versioning enabled."
    },
    "5.2.1": {
        "Description": "Oracle Cloud Infrastructure Block Volume service lets you dynamically provision and manage block storage volumes. By default, the Oracle service manages the keys that encrypt this block volume. Block Volumes can also be encrypted using a customer managed key.",
        "Rationale": "Encryption of block volumes provides an additional level of security for your data. Management of encryption keys is critical to protecting and accessing protected data. Customers should identify block volumes encrypted with Oracle service managed keys in order to determine if they want to manage the keys for certain volumes and then apply their own key lifecycle management to the selected block volumes.",
        "Impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master Key. In addition, you must authorize the Block Volume service to use the keys you create.\nRequired IAM Policy:\n<pre>\nAllow service blockstorage to use keys in compartment &ltcompartment-id> where target.key.id = '&lt;key_OCID>'\n</pre>",
        "Remediation": "For each block volumes from the result, assign the encryption key by Selecting the Vault Compartment and Vault, select the Master Encryption Key Compartment and Master Encryption key, click Assign.",
        "Recommendation": "",
        "Observation": "block volumes are not encrypted with a Customer-Managed Key."
    },
    "5.2.2": {
        "Description": "When you launch a virtual machine (VM) or bare metal instance based on a platform image or custom image, a new boot volume for the instance is created in the same compartment. That boot volume is associated with that instance until you terminate the instance. By default, the Oracle service manages the keys that encrypt this boot volume. Boot Volumes can also be encrypted using a customer managed key.",
        "Rationale": "Encryption of boot volumes provides an additional level of security for your data. Management of encryption keys is critical to protecting and accessing protected data. Customers should identify boot volumes encrypted with Oracle service managed keys in order to determine if they want to manage the keys for certain boot volumes and then apply their own key lifecycle management to the selected boot volumes.",
        "Impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master Key. In addition, you must authorize the Boot Volume service to use the keys you create.\nRequired IAM Policy:\n<pre>\nAllow service Bootstorage to use keys in compartment &ltcompartment-id> where target.key.id = '&lt;key_OCID>'\n</pre>",
        "Remediation": "For each boot volumes from the result, assign the encryption key by Selecting the Vault Compartment and Vault, select the Master Encryption Key Compartment and Master Encryption key, click Assign.",
        "Recommendation": "",
        "Observation": "boot volumes are not encrypted with a Customer-Managed Key."
    },
    "5.3.1": {
        "Description": "Oracle Cloud Infrastructure File Storage service (FSS) provides a durable, scalable, secure, enterprise-grade network file system. By default, the Oracle service manages the keys that encrypt FSS file systems. FSS file systems can also be encrypted using a customer managed key.",
        "Rationale": "Encryption of FSS systems provides an additional level of security for your data. Management of encryption keys is critical to protecting and accessing protected data. Customers should identify FSS file systems that are encrypted with Oracle service managed keys in order to determine if they want to manage the keys for certain FSS file systems and then apply their own key lifecycle management to the selected FSS file systems.",
        "Impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master Key. In addition, you must authorize the File Storage service to use the keys you create.\nRequired IAM Policy:\n<pre>\nAllow service FssOc1Prod to use keys in compartment &ltcompartment-id> where target.key.id = '&lt;key_OCID>'\n</pre>",
        "Remediation": "For each file storage system from the result, assign the encryption key by Selecting the Vault Compartment and Vault, select the Master Encryption Key Compartment and Master Encryption key, click Assign.",
        "Recommendation": "",
        "Observation": "file storage services (FSS) are not encrypted with a Customer-Managed Key."
    },
    "6.1": {
        "Description": "When you sign up for Oracle Cloud Infrastructure, Oracle creates your tenancy, which is the root compartment that holds all your cloud resources. You then create additional compartments within the tenancy (root compartment) and corresponding policies to control access to the resources in each compartment.<br><br>Compartments allow you to organize and control access to your cloud resources. A compartment is a collection of related resources (such as instances, databases, virtual cloud networks, block volumes) that can be accessed only by certain groups that have been given permission by an administrator.",
        "Rationale": "Compartments are a logical group that adds an extra layer of isolation, organization and authorization making it harder for unauthorized users to gain access to OCI resources.",
        "Impact": "Once the compartment is created an OCI IAM policy must be created to allow a group to resources in the compartment otherwise only group with tenancy access will have access.",
        "Remediation": "Create the new compartment under the root compartment.",
        "Recommendation": "",
        "Observation": "Only the root compartment is used in the tenancy."
    },
    "6.2": {
        "Description": "When you create a cloud resource such as an instance, block volume, or cloud network, you must specify to which compartment you want the resource to belong. Placing resources in the root compartment makes it difficult to organize and isolate those resources.",
        "Rationale": "Placing resources into a compartment will allow you to organize and have more granular access controls to your cloud resources.",
        "Impact": "Placing a resource in a compartment will impact how you write policies to manage access and organize that resource.",
        "Remediation": "For each item in the returned results, select Move Resource or More Actions then Move Resource and select compartment except root and choose new then move resources.",
        "Recommendation": "",
        "Observation": "resources are created in the root compartment."
    }
}
