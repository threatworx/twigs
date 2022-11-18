#!/bin/bash

SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`
. $SCRIPTPATH/common.sh
ROOT_FOLDER="$1"
CVE="CVE-2017-12626"
VULN_VERSION="3.17"

POI_JARS=`find $ROOT_FOLDER -name 'poi-*.jar' -type f`
for POI_JAR in $POI_JARS
do
	BASENAME=`basename $POI_JAR`
	v=`echo $BASENAME | cut -c 5- | head --bytes -5`
	vercomp $v 3.18
	vout=$?
	if [[ $v = 3* && $vout = 2 ]]; then
		echo "TYPE:IMPACT"
		echo "VULN:$CVE"
		echo "PERCENTAGE:100"
		echo "AFFECTED_PRODUCT:$POI_JAR"
		echo "VULNERABLE_PRODUCT:$BASENAME"
		echo "ANALYSIS:poi jar found at [$POI_JAR] is vulnerable to $CVE"
		echo "RECOMMENDATION:Upgrade to version 3.18 or later"
		echo ""
	fi
done
