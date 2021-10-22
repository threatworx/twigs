import sys
import subprocess
import os
import logging
import json

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
    if args.custom_ratings:
        if os.path.isfile(args.custom_ratings):
            with open(args.custom_ratings,"r") as fd:
                try:
                    temp_cr = json.load(fd)
                    custom_rating_dict = { }
                    for rating in temp_cr:
                        if rating not in ["1", "2", "3", "4", "5"]:
                            logging.error("Invalid rating [%s] specified in custom rating JSON file [%s]", rating, args.custom_ratings)
                            sys.exit(1)
                        tests = temp_cr[rating]
                        for test in tests:
                            custom_rating_dict[test] = rating
                    gcp_cis_utils.set_custom_ratings(custom_rating_dict)
                except ValueError as ve:
                    logging.error('Unable to load JSON file %s', args.custom_ratings)
                    logging.error(ve)
                    sys.exit(1)
        else:
            logging.error('Unable to access JSON file %s', args.custom_ratings)
            logging.error('Please check it exists and is accessible')
            sys.exit(1)

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
