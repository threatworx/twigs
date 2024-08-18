import sys
import os
import subprocess
import tempfile
import traceback
import re
from xml.dom import minidom
try:
    from urllib.parse import urlparse
except (ImportError,ValueError):
    from urlparse import urlparse
import socket
import logging
import yaml
from . import fingerprint 
from . import ssl_audit 
from .dast_plugins import zap as zap 

def get_inventory(args):
    if args.planfile:
        with open(args.planfile) as f:
            plan = yaml.safe_load(f)
            url = plan['env']['contexts'][0]['urls'][0]
            args.url = url

    v = urlparse(args.url)
    if not v.scheme or not v.netloc:
        logging.error("Invalid input url "+args.url)
        exit(1)

    hostname = v.hostname
    hostip = socket.gethostbyname(hostname)

    asset_id = args.url.replace('/','').replace(':','-')

    # get port number to pass to nmap_scan for selective ssl_audit for only that port
    url_port = None
    if v.scheme == "https":
        url_port = '' if v.port is None else str(v.port)

    asset_data_list = []
    if args.run_nmap:
        logging.info("Starting OS/Service detection for "+hostname)
        asset_data_list = fingerprint.nmap_scan(args, hostname)
    if len(asset_data_list) != 0:
        asset_data = asset_data_list[0]
    else:
        asset_data = {}
        asset_data['config_issues'] = [] 
    asset_data['id'] = asset_id
    asset_data['name'] = args.url
    asset_data['type'] = 'Web Application'
    asset_data['owner'] = args.handle
    asset_tags = ["DISCOVERY_TYPE:Unauthenticated"]
    asset_data['tags'] = asset_tags

    zap_issues = zap.run_zap(args, asset_id)
    asset_data['config_issues'] = asset_data['config_issues'] + zap_issues

    if url_port is not None and (not args.run_nmap or url_port not in ["", "8443"]) and not args.no_ssl_audit:

        if url_port == '':
            ssl_audit_url = "https://" + hostname + "/"
        else:
            ssl_audit_url = "https://" + hostname + ":" + url_port + "/"
        logging.info("Running SSL audit for "+ssl_audit_url)
        ssl_audit_findings = ssl_audit.run_ssl_audit(ssl_audit_url, asset_id)
        if not args.include_info:
            flist = []
            for f in ssl_audit_findings:
                if f['rating'] != '1':
                    flist.append(f)
            ssl_audit_findings = flist
        asset_data['config_issues'] = asset_data['config_issues'] + ssl_audit_findings if 'config_issues' in asset_data else ssl_audit_findings

    if ('products' not in asset_data or len(asset_data['products']) == 0) and len(asset_data['config_issues']) == 0:
        logging.warning("Nothing to report for: "+args.url)
        return None
    return [ asset_data ]
