import sys
import subprocess
import os
import logging

from . import check1 as check1
from . import check2 as check2
from . import check3 as check3
from . import check4 as check4
from . import check5 as check5
from . import check6 as check6
from . import check7 as check7
from . import gcp_cis_utils as gcp_cis_utils

def run_tests(args):
    gcp_cis_utils.set_encoding(args.encoding)
    gcp_cis_utils.set_expanded(args.expanded)
    config_issues = []
    p_not_found = []
    if args.projects:
        allprojs = gcp_cis_utils.get_all_projects()
        projs = args.projects.split(',')
        gcp_cis_utils._projects = []
        for p in projs:
            if p in allprojs:
                gcp_cis_utils._projects.append(p)
            else:
                p_not_found.append(p)

    if len(p_not_found) > 0:
        logging.error("Following project IDs were not found")
        logging.error(p_not_found)
        logging.error("Please provide correct project IDs and rerun")
        sys.exit(1)

    config_issues.extend(check1.run_checks())
    config_issues.extend(check2.run_checks())
    config_issues.extend(check3.run_checks())
    config_issues.extend(check4.run_checks())
    config_issues.extend(check5.run_checks())
    config_issues.extend(check6.run_checks())
    config_issues.extend(check7.run_checks())
    #print config_issues
    return config_issues

# run_tests()
