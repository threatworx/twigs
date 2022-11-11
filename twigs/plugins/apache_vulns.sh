#!/bin/bash

SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`
ROOT_FOLDER="$1"

# find apache/httpd versions
VERSIONS=''
VEROUT=`apache2 -v 2> /dev/null | grep "version:" | cut -d"/" -f2 | cut -d " " -f1`
if [ $? = 0 ]; then
	VERSIONS=`echo "$VERSIONS $VEROUT"`
fi
VEROUT=`httpd -v 2> /dev/null | grep "version:" | cut -d"/" -f2 | cut -d " " -f1`
if [ $? = 0 ]; then
	VERSIONS=`echo "$VERSIONS $VEROUT"`
fi

#check each version for known vulns
for v in $VERSIONS
do
	if [[ $v = 2.2.3 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2007-1741"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache server $v"
		echo "VULNERABLE_PRODUCT:apache server 2.2.3"
		echo "ANALYSIS:apache server $v is vulnerable to CVE-2017-1741"
		echo "RECOMMENDATION:Upgrade to version 2.2.4 or later"
		echo ""

		echo "TYPE:IMPACT"
		echo "VULN:CVE-2007-1742"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache server $v"
		echo "VULNERABLE_PRODUCT:apache server 2.2.3"
		echo "ANALYSIS:apache server $v is vulnerable to CVE-2017-1742"
		echo "RECOMMENDATION:Upgrade to version 2.2.4 or later"
		echo ""

		echo "TYPE:IMPACT"
		echo "VULN:CVE-2007-1743"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache server $v"
		echo "VULNERABLE_PRODUCT:apache server 2.2.3"
		echo "ANALYSIS:apache server $v is vulnerable to CVE-2017-1742"
		echo "RECOMMENDATION:Upgrade to version 2.2.4 or later"
		echo ""
	fi
	if [[ $v = 2.2.6 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2007-6514"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache server $v"
		echo "VULNERABLE_PRODUCT:apache server 2.2.6"
		echo "ANALYSIS:apache server $v is vulnerable to CVE-2017-6514"
		echo "RECOMMENDATION:Upgrade to version 2.2.6 or later"
		echo ""
	fi
done
