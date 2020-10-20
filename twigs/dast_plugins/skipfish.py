import sys
import re
import os
import shutil
import stat
import subprocess
import logging
import json
import tempfile
import traceback

issue_list = {
  "10101": "SSL certificate issuer information",
  "10201": "New HTTP cookie added",
  "10202": "New 'Server' header value seen",
  "10203": "New 'Via' header value seen",
  "10204": "New 'X-*' header value seen",
  "10205": "New 404 signature seen",

  "10401": "Resource not directly accessible",
  "10402": "HTTP authentication required",
  "10403": "Server error triggered",
  "10404": "Directory listing enabled",
  "10405": "Hidden files / directories",

  "10501": "All external links",
  "10502": "External URL redirector",
  "10503": "All e-mail addresses",
  "10504": "Links to unknown protocols",
  "10505": "Unknown form field (can't autocomplete)",
  "10601": "HTML form (not classified otherwise)",
  "10602": "Password entry form - consider brute-force",
  "10603": "File upload form",
  "10701": "User-supplied link rendered on a page",
  "10801": "Incorrect or missing MIME type (low risk)",
  "10802": "Generic MIME used (low risk)",
  "10803": "Incorrect or missing charset (low risk)",
  "10804": "Conflicting MIME / charset info (low risk)",
  "10901": "Numerical filename - consider enumerating",
  "10902": "OGNL-like parameter behavior",
  "10909": "Signature match (informational)",

  "20101": "Resource fetch failed",
  "20102": "Limits exceeded, fetch suppressed",
  "20201": "Directory behavior checks failed (no brute force)",
  "20202": "Parent behavior checks failed (no brute force)",
  "20203": "IPS filtering enabled",
  "20204": "IPS filtering disabled again",
  "20205": "Response varies randomly, skipping checks",
  "20301": "Node should be a directory, detection error?",

  "30101": "HTTP credentials seen in URLs",
  "30201": "SSL certificate expired or not yet valid",
  "30202": "Self-signed SSL certificate",
  "30203": "SSL certificate host name mismatch",
  "30204": "No SSL certificate data found",
  "30205": "Weak SSL cipher negotiated",
  "30206": "Host name length mismatch (name string has null byte)",
  "30301": "Directory listing restrictions bypassed",
  "30401": "Redirection to attacker-supplied URLs",
  "30402": "Attacker-supplied URLs in embedded content (lower risk)",
  "30501": "External content embedded on a page (lower risk)",
  "30502": "Mixed content embedded on a page (lower risk)",
  "30503": "HTTPS form submitting to a HTTP URL",
  "30601": "HTML form with no apparent XSRF protection",
  "30602": "JSON response with no apparent XSSI protection",
  "30603": "Auth form leaks credentials via HTTP GET",
  "30701": "Incorrect caching directives (lower risk)",
  "30801": "User-controlled response prefix (BOM / plugin attacks)",
  "30901": "HTTP header injection vector",
  "30909": "Signature match detected",

  "40101": "XSS vector in document body",
  "40102": "XSS vector via arbitrary URLs",
  "40103": "HTTP response header splitting",
  "40104": "Attacker-supplied URLs in embedded content (higher risk)",
  "40105": "XSS vector via injected HTML tag attribute",
  "40201": "External content embedded on a page (higher risk)",
  "40202": "Mixed content embedded on a page (higher risk)",
  "40301": "Incorrect or missing MIME type (higher risk)",
  "40302": "Generic MIME type (higher risk)",
  "40304": "Incorrect or missing charset (higher risk)",
  "40305": "Conflicting MIME / charset info (higher risk)",
  "40401": "Interesting file",
  "40402": "Interesting server message",
  "40501": "Directory traversal / file inclusion possible",
  "40601": "Incorrect caching directives (higher risk)",
  "40701": "Password form submits from or to non-HTTPS page",
  "40909": "Signature match detected (higher risk)",

  "50101": "Server-side XML injection vector",
  "50102": "Shell injection vector",
  "50103": "Query injection vector",
  "50104": "Format string vector",
  "50105": "Integer overflow vector",
  "50106": "File inclusion",
  "50107": "Remote file inclusion",
  "50201": "SQL query or similar syntax in parameters",
  "50301": "PUT request accepted",
  "50909": "Signature match detected (high risk)"
}



def on_rm_error( func, path, exc_info):
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

def get_object_id(pdir):
    oid = None 
    if os.path.exists(pdir+'/request.dat'):
        f = open(pdir+'/request.dat')
        oid = f.read()
        oid = oid.split()[1]
        f.close()
    return oid 

def tw_open(in_file, in_encoding):
    if sys.version_info[0] < 3:
        f = open(in_file)
    else:
        f = open(in_file, encoding=in_encoding)
    return f

def get_payload(pdir, encoding):
    out = ''
    if os.path.exists(pdir+'/request.dat'):
        f = tw_open(pdir+'/request.dat', encoding)
        out = out + '\nREQUEST\n'+f.read()
        f.close()
    if os.path.exists(pdir+'/response.dat'):
        f = tw_open(pdir+'/response.dat', encoding)
        out = out + '\nRESPONSE\n'+f.read()
        f.close()
    out = re.sub(r'[^\x00-\x7F]+','', out)
    return out

def parse_skipout(skipout, args):
    logging.info("Analyzing results")
    findings = []
    for root, dirs, files in os.walk(skipout):
        for file in files:
            if file == 'issue_index.js':
                issuefile = (os.path.join(root, file))
                f = open(issuefile, 'r')
                contents = f.read()
                contents = contents.replace('var issue = ','').strip()
                contents = contents.replace("'",'"').strip()
                contents = contents.replace("\\",'\\\\').strip()
                contents = contents[:-1]
                iarr = json.loads(contents)
                if len(iarr) > 0:
                    for i in iarr:
                        issue = {}
                        issue['asset_id'] = args.assetid
                        issue['twc_id'] = 'SKIPFISH-' + str(i['type'])
                        issue['twc_title'] = issue_list[str(i['type'])]
                        issue['rating'] = str(i['type'])[0]
                        oid = get_object_id(os.path.join(root, i['dir'])) 
                        if oid == None:
                            oid = str(hash(i['dir']))
                        issue['object_id'] = oid
                        issue['type'] = 'DAST'
                        issue['object_meta'] = ''
                        issue['details'] = get_payload(os.path.join(root, i['dir']), args.encoding)
                        findings.append(issue)
                f.close()
    return findings

def run(args):
    SKIPFISH = "/usr/bin/skipfish"

    if not os.path.isfile(SKIPFISH) or not os.access(SKIPFISH, os.X_OK):
        logging.error('skipfish not found')
        sys.exit(1) 

    logging.warn("Running skipfish plugin. This could take a while")
    path = tempfile.mkdtemp()
    rparams = " -MEU -uv -o "+path 
    logging.warn("Using reporting options: "+rparams)
    logging.warn("Please do not override the reporting options")

    params = args.args
    if params != None:
        params = " " + params + " " + rparams + " " + args.url
    else:
        params = " " + rparams + " " + args.url
    #logging.info("skipfish command line: "+SKIPFISH + " " + params)
    cmdarr = [SKIPFISH + " " + params]
    try:
        out = subprocess.check_output(cmdarr, shell=True)
    except subprocess.CalledProcessError:
        logging.error("Error running skipfish")
        shutil.rmtree(path, onerror = on_rm_error)
        return None 
    logging.info("skipfish run completed")

    findings = parse_skipout(path, args)
    shutil.rmtree(path, onerror = on_rm_error)

    return findings
