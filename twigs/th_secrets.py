import os
import sys
import json
import logging
import shutil
import tempfile
import subprocess
import traceback
import mmap
from . import utils as lib_utils

TH_BIN = shutil.which("trufflehog")
if TH_BIN is None:
    TH_BIN = "/usr/local/bin/trufflehog"

def scan_for_secrets(args, local_path, base_path):
    secret_records = []
    # create exclude file

    tmpfile = tempfile.NamedTemporaryFile(mode='w+')
    tmpfile.write("echo '.git/*' > /tmp/exclude")
    tmpfile.flush()  # Ensure content is written to disk

    th_cmd = TH_BIN + ' filesystem '+local_path+' --exclude_paths '+tmpfile.name+' --json'
    out = None
    try:
        logging.debug("Running TH command "+th_cmd)
        #out = subprocess.check_output([th_cmd], shell=True, stderr=subprocess.DEVNULL)
        out = subprocess.check_output([th_cmd], shell=True)
        out = out.decode(args.encoding)
    except subprocess.CalledProcessError:
        traceback.print_exc()
        logging.error("Error running TH command")
        return [] 

    if not out or out == '':
        return []

    for line in out.splitlines():
        logging.debug(line)
        lj = json.loads(line)
        if 'SourceMetadata' in lj:
            secret_record = { }
            file_path = lj['SourceMetadata']['Data']['Filesystem']['file'][len(base_path)+1:]
            secret_record['filename'] = file_path
            line_no = lj['SourceMetadata']['Data']['Filesystem']['line']
            secret_record['line_no'] = line_no
            secret_record['discovered_using'] = 'TruffleHog'
            secret_record['regex'] = lj['DetectorName']
            if lj['Verified']:
                secret_record['rating'] = 5
            else:
                secret_record['rating'] = 3

            if args.no_code:
                secret_record['line_content'] = ''
                secret_record['before_content'] = ''
                secret_record['after_content'] = ''
            else:
                fd = open(lj['SourceMetadata']['Data']['Filesystem']['file'], 'r')
                if sys.platform == 'win32':
                    mm_file = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
                else:
                    mm_file = mmap.mmap(fd.fileno(), 0, prot=mmap.PROT_READ)
                lines = mm_file.read(-1)
                lines = lines.decode(args.encoding)
                lines = lines.split('\n')
                fd.close()

                if line_no >= 2 and line_no < len(lines):
                    before_content = lib_utils.ascii_string(lines[line_no-3]) + '\n' + lib_utils.ascii_string(lines[line_no-2])
                elif line_no == 1 and line_no < len(lines):
                    before_content = lib_utils.ascii_string(lines[line_no-2])
                else:
                    before_content = ''
                if line_no < len(lines) - 2:
                    after_content = lib_utils.ascii_string(lines[line_no]) + '\n' + lib_utils.ascii_string(lines[line_no+1])
                elif line_no == len(lines) - 2:
                    after_content = lib_utils.ascii_string(lines[line_no])
                else:
                    after_content = ''

                secret_record['before_content'] = before_content 
                secret_record['after_content'] = after_content 
                if not args.mask_secret and line_no < len(lines):
                    secret_record['line_content'] = lines[line_no-1]
                else:
                    secret_record['line_content'] = lj['Redacted']
            secret_records.append(secret_record)

    return secret_records

