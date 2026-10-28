#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
import os
import sys
import re


class build_py_with_powershell(build_py):
    """Also packages powershell/ShadowAI.psm1, which twigs/windows.py sends to
    Windows hosts over WinRM. It lives outside the twigs package because
    twigs.ps1 shares it, so it is copied in at build time."""

    def run(self):
        build_py.run(self)
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'powershell', 'ShadowAI.psm1')
        dest_dir = os.path.join(self.build_lib, 'twigs')
        self.mkpath(dest_dir)
        self.copy_file(src, os.path.join(dest_dir, 'ShadowAI.psm1'))


with open('twigs/__init__.py') as version_file:
    version = re.search(r"^__version__ = ['\"]([^'\"]+)['\"]",
                        version_file.read(), re.M).group(1)

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['boto3', 'setuptools', 'requests', 'requirements_parser', 'pysnow', 'ipaddress==1.0.22', 'pefile==2019.4.18', 'paramiko==2.6.0', 'cryptography==3.3.2', 'toml==0.10.2', 'pyvmomi==7.0.3', 'scp==0.13.3', 'pyyaml>5.1', 'psutil', 'ipaddress', 'oci-cli==3.43.1', 'pytz', 'pywinrm==0.5.0', 'trustmodel', 'dnspython', 'dnstwist', 'tldextract', 'builtwith', 'beautifulsoup4', 'mmh3']
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
    package_data={'twigs.easm': ['data/*.txt']},
    keywords='twigs',
    name='twigs',
    packages=find_packages(include=['twigs', 'twigs.dast_plugins', 'twigs.azure_cis_tool', 'twigs.gcp_cis_tool', 'twigs.oci_cis_tool', 'twigs.easm']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/threatworx/twigs',
    version=version,
    zip_safe=False,
    cmdclass={'build_py': build_py_with_powershell},
    entry_points={
        'console_scripts': [
            'twigs=twigs.twigs:main',
        ],
    },
)
