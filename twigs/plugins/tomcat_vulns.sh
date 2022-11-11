#!/bin/bash

SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`
ROOT_FOLDER="$1"

# find all tomcat versions
VERSIONS=''
VERFILES=`find $ROOT_FOLDER -path "*/tomcat*/bin/version.sh"`
for v in $VERFILES
do
	echo $v
	VEROUT=`$v | grep "version:" | cut -d"/" -f2`
	VERSIONS=`echo "$VERSIONS $VEROUT"`
done

#check each version for known vulns
for v in $VERSIONS
do
	if [[ $v = 9* && $v < "9.0.36" ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2022-42252"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat <9.0.68"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2022-42252"
		echo "RECOMMENDATION:Upgrade to version 9.0.68 or later"
		echo ""
	fi
	if [[ $v < "9.0.36" ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2020-11996"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat <9.0.36"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2020-11996"
		echo "RECOMMENDATION:Upgrade to version 9.0.36 or later"
		echo ""
	fi
	if [[ $v = 10.0.0-M* && $v < "10.0.0-M10" ]] || [[ $v = 9* && $v < "9.0.40" ]] || [[ $v = 8.5* && $v < "8.5.60" ]] || [[ $v = 7* && $v < "7.0.107" ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2021-24122"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat <7.0.107"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2021-24122"
		echo "RECOMMENDATION:Upgrade to version 7.0.107, 8.5.60, 9.0.40, 10.0.0-M10 or later"
		echo ""
	fi
	if [[ $v = 10* && $v < "10.0.6" ]] || [[ $v = 9* && $v < "9.0.46" ]] || [[ $v = 8* && $v < "8.5.66" ]] || [[ $v = 7* && $v < "7.0.109" ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2021-30640"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat 7.0.x <= 7.0.108 / 8.5.x <= 8.5.65 / 9.0.x
<= 9.0.45 / 10.0.x <= 10.0.5"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2021-30640"
		echo "RECOMMENDATION:Upgrade to version 7.0.109, 8.5.66, 9.0.46, 10.0.6 or later"
		echo ""

	fi
done
