import sys
import os
import subprocess
import tempfile
import traceback
import re
from xml.dom import minidom
import yaml
import uuid
import json
try:
    from urllib.parse import urlparse
except (ImportError,ValueError):
    from urlparse import urlparse
import logging
import shutil

class SingleQuoted(str):
  pass

def represent_single_quoted(dumper, data):
  return dumper.represent_scalar(yaml.resolver.BaseResolver.DEFAULT_SCALAR_TAG,
      data, style="'")

yaml.add_representer(SingleQuoted, represent_single_quoted)

CLEANR = re.compile('<.*?>')

def _get_rating(risk):
    if risk == '0':
        return '1'
    if risk == '1':
        return '2'
    if risk == '2':
        return '3'
    if risk == '3' or risk == '4':
        return '5'

def get_all_text_json(instance):
    itext = ""
    for key in instance:
        itext += key + ": " + instance[key] + "\n"
    return itext

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

    zapcli = shutil.which("zaproxy")
    if not zapcli:
        zapcli = shutil.which("zap.sh")
    
    if not zapcli:
        logging.error("'zaproxy' or 'zap.sh' CLI not found")
        logging.error("Please make sure zaproxy command is installed and in your $PATH")
        return findings

    report_file = None
    zap_cmd = zapcli + " -cmd -port 8081 "
    if args.planfile != None:
        logging.info("Starting web application scan for plan "+args.planfile)
        with open(args.planfile) as f:
            plan = yaml.safe_load(f)
            for e in plan['jobs']:
                if 'reportDir' in e['parameters']:
                    report_file = tempfile.NamedTemporaryFile(suffix='.json')
                    report_file = report_file.name
                    e['parameters']['reportDir'] = SingleQuoted(os.path.dirname(report_file))
                    e['parameters']['template'] = SingleQuoted("traditional-json")
                    e['parameters']['reportFile'] = SingleQuoted(os.path.basename(report_file))
            newplanfile = tempfile.NamedTemporaryFile()
            with open(newplanfile.name, "w") as npf:
                yaml.dump(plan, npf, default_flow_style=False, encoding='utf-8')
            zap_cmd = zap_cmd + " -autorun " + newplanfile.name + " 2>/dev/null"
    elif args.url != None:
        logging.info("Starting web application scan for "+args.url)
        z_path = tempfile.NamedTemporaryFile()
        zap_cmd = zap_cmd + " -quickurl "+args.url+" -quickout "+z_path.name+" 2>/dev/null"
        report_file = z_path.name

    try:
        logging.debug("ZAP command [%s]", zap_cmd)
        out = subprocess.check_output([zap_cmd], shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        logging.error("Error running zaproxy...unable to run web app scan")
        logging.error(traceback.format_exc())
        return findings

    if report_file == None:
        logging.error("Report file not available. Nothing to process")
        return findings

    fp = open(report_file, mode='r')
    if fp == None:
        return findings
    contents = fp.read()
    fp.close()

    if args.planfile != None:
        jsondoc = None
        jsondoc = json.loads(contents)
        for site in jsondoc['site']:
            for alert in site['alerts']:
                rating = alert['riskcode']
                confidence = alert['confidence']
                issue = {}
                pid = alert['pluginid']
                issue['twc_id'] = 'zap-'+pid
                issue['twc_title'] = alert['name']
                issue['rating'] = _get_rating(rating)
                issue['asset_id'] = assetid
                issue['object_id'] = args.url 
                issue['object_meta'] = args.url 
                issue['type'] = 'DAST'
                desc = alert['desc']
                solution = alert['solution']
                if solution != None:
                    solution = solution.strip()
                else:
                    solution = ''
                if solution != '':
                    desc = desc + '\nSolution:\n' + solution + '\n'
                refs = alert['reference']
                if refs != None:
                    refs = refs.strip()
                else:
                    refs = ''
                if refs != '':
                    refs = refs.replace('http','\nhttp')
                    desc = desc + '\nReferences:\n' + refs + '\n' 
                instances = alert['instances']
                if len(instances) > 0:
                    desc = desc + '\nDetailed findings:\n'
                for i in instances:
                    desc = desc + '\n' + get_all_text_json(i) + '\n'
                desc = re.sub(CLEANR, '', desc)
                issue['details'] = desc
                findings.append(issue)
    else:
        xmldoc = None
        try:
            xmldoc = minidom.parseString(contents)
        except Exception:
            logging.error("Unable to parse %s", report_file)
            logging.error(traceback.format_exc())
            return findings
    
        allitems = xmldoc.getElementsByTagName('alertitem')
        for item in allitems:
            rating = item.getElementsByTagName('riskcode')[0].firstChild.data.strip()
            confidence = item.getElementsByTagName('confidence')[0].firstChild.data.strip()
            issue = {}
            pid = item.getElementsByTagName('pluginid')[0].firstChild.data.strip()
            issue['twc_id'] = 'zap-'+pid
            issue['twc_title'] = item.getElementsByTagName('name')[0].firstChild.data.strip()

            issue['rating'] = _get_rating(rating)
            issue['asset_id'] = assetid
            issue['object_id'] = args.url 
            issue['object_meta'] = args.url 
            issue['type'] = 'DAST'
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
