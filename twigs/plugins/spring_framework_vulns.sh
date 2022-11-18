#!/bin/bash


SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`
. $SCRIPTPATH/common.sh
ROOT_FOLDER="$1"

# find all spring framework versions
SPRING_JARS=`find $ROOT_FOLDER -name 'spring-core-*.jar'`

#check each version for known vulns
for s in $SPRING_JARS
do
	v=`echo $s | grep -Po '(?<=spring-core-)\d.\d.\d'`
	vercomp $v 5.2.20
	vout1=$?
	vercomp $v 5.3.17
	vout2=$?
	#if [[ $v = 5.2* && $v < "5.2.20" ]] || [[ $v = 5.3* && $v < "5.3.17" ]]; then
	if [[ $v = 5.2* && $vout1 = 2  ]] || [[ $v = 5.3* && $vout2 = 2 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:CVE-2022-22950"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:spring framework $v"
		echo "VULNERABLE_PRODUCT:spring framework <5.2.20 | <5.3.17"
		echo "ANALYSIS:spring framework $v is vulnerable to CVE-2022-22950"
		echo "RECOMMENDATION:Upgrade to Spring Framework version 5.2.20 or 5.3.17 or later"
		echo ""
	fi
done
