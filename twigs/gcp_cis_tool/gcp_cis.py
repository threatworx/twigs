import sys
import subprocess
import os

import check1
import check2
import check3
import check4
import check5
import check6
import check7

def run_tests():
    config_issues = []
    config_issues.extend(check1.run_checks())
    config_issues.extend(check2.run_checks())
    config_issues.extend(check3.run_checks())
    config_issues.extend(check4.run_checks())
    config_issues.extend(check5.run_checks())
    config_issues.extend(check6.run_checks())
    config_issues.extend(check7.run_checks())
    print config_issues
    return config_issues

# run_tests()
