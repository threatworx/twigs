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

# Dependencies are deliberately unpinned so that pip resolves the newest
# versions compatible with the running Python. Only add a bound with a comment
# explaining which release it works around.
requirements = [
    'boto3', 'setuptools', 'requests', 'requirements_parser', 'pysnow',
    'pefile', 'paramiko', 'cryptography', 'toml', 'scp', 'pyyaml', 'psutil',
    'oci-cli', 'pytz', 'pywinrm', 'trustmodel', 'dnspython', 'dnstwist',
    'tldextract', 'builtwith', 'beautifulsoup4', 'mmh3',
    # pyvmomi 9.x requires Python 3.10+ but does not declare it, so pip would
    # install it on older Pythons where it fails to import.
    'pyvmomi<9; python_version<"3.10"',
    'pyvmomi; python_version>="3.10"',
]
if sys.platform != 'win32':
    requirements.append('python-crontab')

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
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    description="ThreatWorx Information Gathering Script",
    install_requires=requirements,
    python_requires='>=3.8',
    license="GNU General Public License v3",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    package_data={'twigs.easm': ['data/*.txt'], 'twigs.passive': ['README.md', 'signatures/*.yaml', 'data/*.yaml', 'zeek/*.zeek', 'zeek/medical/*']},
    keywords='twigs',
    name='twigs',
    packages=find_packages(include=['twigs', 'twigs.dast_plugins', 'twigs.azure_cis_tool', 'twigs.gcp_cis_tool', 'twigs.oci_cis_tool', 'twigs.easm', 'twigs.passive']),
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
