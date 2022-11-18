#!/bin/bash

SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`
. $SCRIPTPATH/common.sh
ROOT_FOLDER="$1"

# find all tomcat versions
VERSIONS=''
VERFILES=`find $ROOT_FOLDER -path "*/tomcat*/bin/version.sh"`
for v in $VERFILES
do
	VEROUT=`$v 2>/dev/null | grep "version:" | cut -d"/" -f2`
	VERSIONS=`echo "$VERSIONS $VEROUT"`
done

#check each version for known vulns
for v in $VERSIONS
do
	vercomp $v 8.5.53
	vout8=$?
	vercomp $v 9.0.68
	vout9=$?
	vercomp $v 10.0.27
	vout10=$?
	vercomp $v 10.1.1
	vout101=$?
	if [[ $v = 8* && $vout8 = 2 ]] || [[ $v = 9* && $vout9 = 2 ]] || [[ $v = 10* && $vout10 = 2 ]] || [[ $v = 10.1* && $vout101 = 2 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2022-42252"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat >=8.5.0 <=8.5.52 or >=9.x <9.0.68 or >10.x <10.0.27 or >=10.1.x <10.1.1"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2022-42252"
		echo "RECOMMENDATION:Upgrade to version 8.5.53 or 9.0.68 or 10.0.27 or 10.1.1 or later respective versions"
		echo ""
	fi
	vercomp $v 8.5.56
	vout8=$?
	vercomp $v 9.0.36 
	vout9=$?
	if [[ $v = 8* && $vout8 = 2 ]] || [[ $v = 9* && $vout9 = 2 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2020-11996"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat >=8.5.0 <=8.5.55 or >=9.x <9.0.36"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2020-11996"
		echo "RECOMMENDATION:Upgrade to version 9.0.36 or later"
		echo ""
	fi
	vercomp $v 7.0.107
	vout7=$?
	vercomp $v 8.5.60
	vout8=$?
	vercomp $v 9.0.40
	vout9=$?
	if [[ $v = 7* && $vout7 = 2 ]] || [[ $v = 8.5* && $vout8 = 2  ]] || [[ $v = 9* && $vout9 = 2 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2021-24122"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat >=7.x <=7.0.106 or <=8.5.0 >=8.5.59 or >=9.0.1 <=9.0.39"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2021-24122"
		echo "RECOMMENDATION:Upgrade to version 7.0.107, 8.5.60, 9.0.40 or later"
		echo ""
	fi
	vercomp $v 7.0.109
	vout7=$?
	vercomp $v 8.5.66
	vout8=$?
	vercomp $v 9.0.46
	vout9=$?
	vercomp $v 10.0.6
	vout10=$?
	if [[ $v = 7* && $vout7 = 2 ]] || [[ $v = 8.5* && $vout8 = 2  ]] || [[ $v = 9* && $vout9 = 2 ]] || [[ $v = 10* && $vout10 = 2  ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2021-30640"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:apache tomcat $v"
		echo "VULNERABLE_PRODUCT:apache tomcat 7.0.x <= 7.0.108 / 8.5.x <= 8.5.65 / 9.0.x <= 9.0.45 / 10.0.x <= 10.0.5"
		echo "ANALYSIS:apache tomcat $v is vulnerable to CVE-2021-30640"
		echo "RECOMMENDATION:Upgrade to version 7.0.109, 8.5.66, 9.0.46, 10.0.6 or later"
		echo ""
	fi
done
