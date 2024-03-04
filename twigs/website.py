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
from . import fingerprint 
from . import ssl_audit 
from .dast_plugins import zap as zap 

def get_inventory(args):
    v = urlparse(args.url)
    if not v.scheme or not v.netloc:
        logging.error("Invalid input url "+args.url)
        exit(1)

    hostname = v.hostname
    hostip = socket.gethostbyname(hostname)

    asset_id = args.url.replace('/','').replace(':','-')

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
    
    if ('products' not in asset_data or len(asset_data['products']) == 0) and len(asset_data['config_issues']) == 0:
        logging.warning("Nothing to report for: "+args.url)
        return None
    return [ asset_data ]
