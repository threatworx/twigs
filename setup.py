#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages
import sys

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['boto3', 'setuptools', 'requests', 'requirements_parser', 'pysnow', 'ipaddress==1.0.22', 'pefile==2019.4.18', 'paramiko==2.6.0', 'cryptography==3.3.2', 'toml==0.10.2', 'pyvmomi==7.0.3', 'scp==0.13.3', 'pyyaml>5.1', 'psutil', 'ipaddress', 'oci-cli==3.43.1', 'pytz', 'pywinrm==0.5.0']
if sys.platform != 'win32':
    requirements.append('python-crontab==2.5.1')

setup_requirements = [ ]

test_requirements = [ ]

setup(
    author="Paresh Borkar",
    author_email='opensource@threatwatch.io',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description="ThreatWorx Information Gathering Script",
    install_requires=requirements,
    license="GNU General Public License v3",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='twigs',
    name='twigs',
    packages=find_packages(include=['twigs', 'twigs.dast_plugins', 'twigs.azure_cis_tool', 'twigs.gcp_cis_tool', 'twigs.oci_cis_tool']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/threatworx/twigs',
    version='1.2.44',
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'twigs=twigs.twigs:main',
        ],
    },
)
