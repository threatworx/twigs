=====
twigs
=====


.. image:: https://img.shields.io/pypi/v/twigs.svg
        :target: https://pypi.python.org/pypi/twigs

.. image:: https://readthedocs.org/projects/twigs/badge/?version=latest
        :target: https://twigs.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status




ThreatWatch Information Gathering Script


* Free software: GNU General Public License v3
* Documentation: https://twigs.readthedocs.io.


Features
--------

twigs.py - A python script to discover various types of assets (cloud-based, Linux hosts, containers, repositories and more).

Note:
1. twigs requires python 2.7 It is recommended to use virtual environments to create isolated Python environments and reduce dependency conflicts. Please use the following command:
python -m virtualenv --python=/usr/bin/python2.7 twigs_env_2_7
2. twigs requires pygit2 package. Mac OS X users will need to perform additional steps as mentioned here [https://www.pygit2.org/install.html#installing-on-os-x] since pygit2 is not available on Mac OS X as a binary wheels package.

$ python twigs.py --help
usage: twigs.py [-h] [-v] [--handle HANDLE] [--token TOKEN] [--instance INSTANCE] [--out OUT] [--no_scan] [--email_report] {aws,azure,docker,file,host,opensource,servicenow} ...

ThreatWatch Information Gathering Script (twigs) to discover assets like hosts, cloud instances, containers and opensource projects

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --handle HANDLE       The ThreatWatch registered email id/handle of the
                        user. Note this can set as "TW_HANDLE" environment
                        variable
  --token TOKEN         The ThreatWatch API token of the user. Note this can
                        be set as "TW_TOKEN" environment variable
  --instance INSTANCE   The ThreatWatch instance. Note this can be set as 
                        "TW_INSTANCE" environment variable
  --out OUT             Specify name of the CSV file to hold the exported
                        asset information. Defaults to out.csv
  --no_scan             Do not initiate a baseline assessment
  --email_report        After impact refresh is complete email scan report to
                        self

modes:
  Discovery modes supported

  {aws,azure,docker,file,host,nmap,repo,servicenow} 
    aws                 Discover AWS instances
    azure               Discover Azure instances
    docker              Discover docker instances
    file                Discover inventory from file
    host                Discover linux host assets
    nmap                Fingerprint assets using nmap. Requires nmap to be installed.
    repo                Discover project repository as asset
    servicenow          Discover inventory from ServiceNow instance

Mode: aws
$ python twigs.py aws --help
usage: twigs.py aws [-h] --aws_account AWS_ACCOUNT --aws_access_key AWS_ACCESS_KEY --aws_secret_key AWS_SECRET_KEY --aws_region AWS_REGION --aws_s3_bucket AWS_S3_BUCKET [--enable_tracking_tags]

optional arguments:
  -h, --help            show this help message and exit
  --aws_account AWS_ACCOUNT
                        AWS account ID
  --aws_access_key AWS_ACCESS_KEY
                        AWS access key
  --aws_secret_key AWS_SECRET_KEY
                        AWS secret key
  --aws_region AWS_REGION
                        AWS region
  --aws_s3_bucket AWS_S3_BUCKET
                        AWS S3 inventory bucket
  --enable_tracking_tags
                        Enable recording AWS specific information (like AWS
                        Account ID, etc.) as asset tags

Mode: azure
$ python twigs.py azure --help
usage: twigs.py azure [-h]  --azure_tenant_id AZURE_TENANT_ID --azure_application_id AZURE_APPLICATION_ID --azure_application_key AZURE_APPLICATION_KEY [--azure_subscription AZURE_SUBSCRIPTION] [--azure_resource_group AZURE_RESOURCE_GROUP] [--azure_workspace AZURE_WORKSPACE] [--enable_tracking_tags]

optional arguments:
  -h, --help            show this help message and exit
  --azure_tenant_id AZURE_TENANT_ID
                        Azure Tenant ID
  --azure_application_id AZURE_APPLICATION_ID
                        Azure Application ID
  --azure_application_key AZURE_APPLICATION_KEY
                        Azure Application Key
  --azure_subscription AZURE_SUBSCRIPTION
                        Azure Subscription. If not specified, then available
                        values will be displayed
  --azure_resource_group AZURE_RESOURCE_GROUP
                        Azure Resource Group. If not specified, then available
                        values will be displayed
  --azure_workspace AZURE_WORKSPACE
                        Azure Workspace. If not specified, then available
                        values will be displayed
  --enable_tracking_tags
                        Enable recording Azure specific information (like
                        Azure Tenant ID, etc.) as asset tags

Mode: docker
$ python twigs.py docker --help
usage: twigs.py docker [-h] --image IMAGE [--assetid ASSETID] [--assetname ASSETNAME]

optional arguments:
  -h, --help            show this help message and exit
  --image IMAGE         The docker image (repo:tag) which needs to be
                        inspected. If tag is not given, "latest" will be
                        assumed.
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset

Mode: file
$ python twigs.py file --help
usage: twigs.py file [-h] --in IN [--assetid ASSETID] [--assetname ASSETNAME] [--type {OpenSource}]

optional arguments:
  -h, --help            show this help message and exit
  --in IN               Absolute path to single input inventory file or a
                        directory containing CSV files. Supported file formats
                        are: PDF & CSV
  --assetid ASSETID     A unique ID to be assigned to the discovered asset.
                        Defaults to input filename if not specified. Applies
                        only for PDF files.
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset.
                        Defaults to assetid is not specified. Applies only for
                        PDF files.
  --type TYPE           Type of asset. Defaults to repo if not specified.
                        Applies only for PDF files.

Mode: host
$ python twigs.py host --help
usage: twigs.py host [-h] [--remote_hosts_csv REMOTE_HOSTS_CSV] [--host_list HOST_LIST] [--secure] [--password PASSWORD] [--assetid ASSETID] [--assetname ASSETNAME]

optional arguments:
  -h, --help            show this help message and exit
  --remote_hosts_csv REMOTE_HOSTS_CSV
                        CSV file containing details of remote hosts. CSV file
                        column header [1st row] should be: hostname,userlogin,
                        userpwd,privatekey,assetid,assetname. Note "hostname"
                        column can contain hostname, IP address, CIDR range.
  --host_list HOST_LIST
                        Same as the option: remote_hosts_csv. A file
                        (currently in CSV format) containing details of remote
                        hosts. CSV file column header [1st row] should be: hos
                        tname,userlogin,userpwd,privatekey,assetid,assetname.
                        Note "hostname" column can contain hostname, IP
                        address, CIDR range.
  --secure              Use this option to encrypt clear text passwords in the
                        host list file
  --password PASSWORD   A password use to encrypt / decrypt login information
                        from the host list file
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset

Mode: nmap
$ python twigs.py nmap --help
usage: twigs.py nmap [-h] --hosts HOSTS

optional arguments:
  -h, --help     show this help message and exit
  --hosts HOSTS  A hostname, IP address or CIDR range

Mode: repo
$ python twigs.py repo --help
usage: twigs.py repo [-h] --repo REPO [--type {pip,ruby,yarn,nuget,npm,maven,gradle,dll}] [--level {shallow,deep}] [--assetid ASSETID] [--assetname ASSETNAME] [--secrets_scan] [--enable_entropy] [--regex_rules_file REGEX_RULES_FILE] [--check_common_passwords] [--common_passwords_file COMMON_PASSWORDS_FILE] [--include_patterns INCLUDE_PATTERNS] [--include_patterns_file INCLUDE_PATTERNS_FILE] [--exclude_patterns EXCLUDE_PATTERNS] [--exclude_patterns_file EXCLUDE_PATTERNS_FILE] [--mask_secret] [--no_code]

optional arguments:
  -h, --help            show this help message and exit
  --repo REPO           Local path or git repo url for project
  --type TYPE           Type of open source component to scan for {pip,ruby,yarn,nuget,npm,maven,gradle,dll}. Defaults to all supported types if not specified
  --level LEVEL         Possible values {shallow, deep}. Shallow restricts discovery to 1st level dependencies only. Deep discovers dependencies at all levels. Defaults to shallow discovery if not specified
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset
  --secrets_scan        Perform a scan to look for secrets in the code
  --enable_entropy      Identify entropy based secrets
  --regex_rules_file REGEX_RULES_FILE
                        Path to JSON file specifying regex rules
  --check_common_passwords
                        Look for top common passwords.
  --common_passwords_file COMMON_PASSWORDS_FILE
                        Specify your own common passwords file. One password per line in file
  --include_patterns INCLUDE_PATTERNS
                        Specify patterns which indicate files to be included in the secrets scan. Separate multiple patterns with comma.
  --include_patterns_file INCLUDE_PATTERNS_FILE
                        Specify file containing include patterns which indicate files to be included in the secrets scan. One pattern per line in file.
  --exclude_patterns EXCLUDE_PATTERNS
                        Specify patterns which indicate files to be excluded in the secrets scan. Separate multiple patterns with comma.
  --exclude_patterns_file EXCLUDE_PATTERNS_FILE
                        Specify file containing exclude patterns which indicate files to be excluded in the secrets scan. One pattern per line in file.
  --mask_secret         Mask identified secret before storing for reference in ThreatWatch.
  --no_code             Disable storing code for reference in ThreatWatch.

Mode: servicenow
$ python twigs.py servicenow --help
usage: twigs.py servicenow [-h] --snow_user SNOW_USER --snow_user_pwd SNOW_USER_PWD --snow_instance SNOW_INSTANCE [--enable_tracking_tags]

optional arguments:
  -h, --help            show this help message and exit
  --snow_user SNOW_USER
                        User name of ServiceNow account
  --snow_user_pwd SNOW_USER_PWD
                        User password of ServiceNow account
  --snow_instance SNOW_INSTANCE
                        ServiceNow Instance name
  --enable_tracking_tags
                        Enable recording ServiceNow specific information (like
                        ServiceNow instance name, etc.) as asset tags

Note: For Windows hosts, you can use provided PowerShell script (windows_discovery.ps1) for discovery. It requires PowerShell 3.0 or higher.

usage: .\\windows_discovery.ps1 -?

windows_discovery.ps1 [-handle] <string> [-token] <string> [-instance] <string> [[-assetid] <string>] [[-assetname] <string>] [<CommonParamete rs>]

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
