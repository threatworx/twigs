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

twigs.py - A python script to discover various types of assets (cloud-based, Linux hosts, containers, open source and more).

Note - twigs requires python 2.7 It is recommended to use virtual environments to create isolated Python environments and reduce dependency conflicts. Please use the following command:
python -m virtualenv --python=/usr/bin/python2.7 twigs_env_2_7

$ python twigs.py --help
usage: twigs.py [-h] --handle HANDLE --token TOKEN [--instance INSTANCE]
                   {aws,opensource,host,docker} ...

ThreatWatch Information Gathering Script (twigs) to discover assets like hosts, cloud instances, containers and opensource projects

optional arguments:
  -h, --help            show this help message and exit
  --handle HANDLE       The ThreatWatch registered email id/handle of the user
  --token TOKEN         The ThreatWatch API token of the user
  --instance INSTANCE   The ThreatWatch instance. Defaults to ThreatWatch
                        Cloud SaaS.

modes:
  Discovery modes supported

  {aws,opensource,host,docker}
    aws                 Discover AWS instances
    opensource          Discover open source assets
    host                Discover linux host assets
    docker              Discover docker instances

Mode: aws
$ python twigs.py aws --help
usage: twigs.py aws [-h] --aws_account AWS_ACCOUNT --aws_access_key
                       AWS_ACCESS_KEY --aws_secret_key AWS_SECRET_KEY
                       --aws_region AWS_REGION --aws_s3_bucket AWS_S3_BUCKET

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

Mode: opensource
$ python twigs.py opensource --help
usage: twigs.py opensource [-h] --repo REPO --type
                              {python,ruby,nodejs,dotnet,yarn}
                              [--assetid ASSETID] [--assetname ASSETNAME]

optional arguments:
  -h, --help            show this help message and exit
  --repo REPO           Local path or git repo url for project
  --type {python,ruby,nodejs,dotnet,yarn}
                        Type of open source component to scan for
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset

Mode: host
$ python twigs.py host --help
usage: twigs.py host [-h] [--assetid ASSETID] [--assetname ASSETNAME]

optional arguments:
  -h, --help            show this help message and exit
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset

Mode: docker
$ python twigs.py docker --help
usage: twigs.py docker [-h] --image IMAGE [--assetid ASSETID]
                          [--assetname ASSETNAME]

optional arguments:
  -h, --help            show this help message and exit
  --image IMAGE         The docker image (repo:tag) which needs to be
                        inspected. If tag is not given, "latest" will be
                        assumed.
  --assetid ASSETID     A unique ID to be assigned to the discovered asset
  --assetname ASSETNAME
                        A name/label to be assigned to the discovered asset

Note: For Windows hosts, you can use provided PowerShell script (windows_discovery.ps1) for discovery. It requires PowerShell 3.0 or higher.

usage: .\\windows_discovery.ps1 -?

windows_discovery.ps1 [-tw_handle] <string> [-tw_api_key] <string> [[-tw_instance] <string>] [-asset_id] <string> [<CommonParameters>]

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
