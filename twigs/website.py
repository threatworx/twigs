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

CLEANR = re.compile('<.*?>')

def _get_rating(risk):
    if risk == '0':
        return '1'
    if risk == '1':
        return '2'
    if risk == '2':
        return '3'
    if risk == '3':
        return '5'

def get_all_text(node):
        if node.nodeType ==  node.TEXT_NODE:
            return node.data.strip()
        else:
            text_string = ""
            for child_node in node.childNodes:
                alltext = get_all_text(child_node)
                if alltext != '':
                    text_string = text_string + alltext + '\n'
            return text_string

def run_zap(args, assetid):
    findings = []

    logging.info("Starting web application scan for "+args.url)
    z_path = tempfile.NamedTemporaryFile()
    zap_cmd = "zaproxy -cmd -quickurl "+args.url+" -quickout "+z_path.name+" 2>/dev/null"
    try:
        out = subprocess.check_output([zap_cmd], shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Error running zaproxy...unable to run web app scan")
        logging.error("Please make sure zaproxy command is installed and in your $PATH")
        return findings

    fp = open(z_path.name, mode='r')
    if fp == None:
        return findings
    contents = fp.read()
    fp.close()
    xmldoc = None
    try:
        xmldoc = minidom.parseString(contents)
    except Exception:
        logging.error("Unable to parse %s", z_path.name)
        logging.error(traceback.format_exc())
        return findings
    
    allitems = xmldoc.getElementsByTagName('alertitem')
    for item in allitems:
        rating = item.getElementsByTagName('riskcode')[0].firstChild.data.strip()
        confidence = item.getElementsByTagName('confidence')[0].firstChild.data.strip()
        if rating > '2' and confidence < '3':
            continue
        issue = {}
        pid = item.getElementsByTagName('pluginid')[0].firstChild.data.strip()
        issue['twc_id'] = 'zap-'+pid
        issue['twc_title'] = item.getElementsByTagName('name')[0].firstChild.data.strip()

        issue['rating'] = _get_rating(rating)
        issue['asset_id'] = assetid
        issue['object_id'] = args.url 
        issue['object_meta'] = args.url 
        issue['type'] = 'WebApp'
        desc = item.getElementsByTagName('desc')[0].firstChild.data.strip()
        solution = item.getElementsByTagName('solution')[0].firstChild
        if solution != None:
            solution = solution.data.strip()
        else:
            solution = ''
        if solution != '':
            desc = desc + '\nSolution:\n' + solution + '\n'
        refs = item.getElementsByTagName('reference')[0].firstChild
        if refs != None:
            refs = refs.data.strip()
        else:
            refs = ''
        if refs != '':
            refs = refs.replace('http','\nhttp')
            desc = desc + '\nReferences:\n' + refs + '\n' 
        instances = item.getElementsByTagName('instances')
        if len(instances) > 0:
            desc = desc + '\nDetailed findings:\n'
        for i in instances:
            desc = desc + '\n' + get_all_text(i) + '\n'
        desc = re.sub(CLEANR, '', desc)
        issue['details'] = desc
        findings.append(issue)

    return findings

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
    asset_data = asset_data_list[0]
    asset_data['id'] = asset_id
    asset_data['name'] = args.url
    asset_data['type'] = 'Web Application'
    asset_data['owner'] = args.handle

    logging.info("Running SSL audit for "+args.url)
    ssl_audit_findings = ssl_audit.run_ssl_audit(args.url, asset_id)
    if not args.include_info:
        flist = []
        for f in ssl_audit_findings:
            if f['rating'] != '1':
                flist.append(f)
        ssl_audit_findings = flist

    zap_issues = run_zap(args, asset_id)
    asset_data['config_issues'] = asset_data['config_issues'] + zap_issues + ssl_audit_findings
    return [ asset_data ]
