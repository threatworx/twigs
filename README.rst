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

Note - twigs requires python 2.7 It is recommended to use virtual environments to create isolated Python environments and reduce dependency conflicts. Please use the following command:
python -m virtualenv --python=/usr/bin/python2.7 twigs_env_2_7

$ python twigs.py --help
usage: twigs.py [-h] [-v] [--handle HANDLE] [--token TOKEN] [--instance INSTANCE] [--out OUT] [--scan {quick,regular,full}] [--email_report] [--purge_assets] {aws,azure,docker,file,host,opensource,servicenow} ...

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
  --scan SCAN           Perform impact refresh for asset(s) by specifying one
                        of the scan options {quick,regular,full}
                        Perform impact refresh for asset(s)
  --email_report        After impact refresh is complete email scan report to
                        self
  --purge_assets        Purge the asset(s) after impact refresh is complete
                        and scan report is emailed to self

modes:
  Discovery modes supported

  {aws,azure,docker,file,host,repo,servicenow}
    aws                 Discover AWS instances
    azure               Discover Azure instances
    docker              Discover docker instances
    file                Discover inventory from file
    host                Discover linux host assets
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
  --in IN               Absolute path to input inventory file. Supported file
                        format is: PDF
  --assetid ASSETID     A unique ID to be assigned to the discovered asset.
                        Defaults to input filename if not specified
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset.
                        Defaults to assetid is not specified
  --type TYPE           Type of asset. Defaults to OpenSource if not specified

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

Mode: repo
$ python twigs.py repo --help
usage: twigs.py repo [-h] --repo REPO [--type {pip,ruby,yarn,nuget,npm,maven,gradle,dll}] [--assetid ASSETID] [--assetname ASSETNAME]

optional arguments:
  -h, --help            show this help message and exit
  --repo REPO           Local path or git repo url for project
  --type TYPE           Type of open source component to scan for {pip,ruby,yarn,nuget,npm,maven,gradle,dll}. Defaults to all supported types if not specified
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset

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
