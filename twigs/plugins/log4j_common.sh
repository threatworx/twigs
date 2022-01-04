#!/bin/sh

check_log4j_vuln()
{
	ROOT_FOLDER="$1"
	shift
	CVE="$1"
	shift
	VULN_VERSIONS="$*"
	LOG4J_FILES=`find $ROOT_FOLDER -name 'log4j-core-*.jar' -type f`
	for LOG4J_FILE in $LOG4J_FILES
	do
		for VULN_VERSION in $VULN_VERSIONS
		do
			BASENAME=`basename $LOG4J_FILE`
			LOG4J_VERSION=`echo $BASENAME | cut -c 12- | cut -c -6`
			if [ $LOG4J_VERSION = $VULN_VERSION ]; then
				echo "TYPE:IMPACT"
				echo "VULN:$CVE"
				echo "PERCENTAGE:100"
				echo "AFFECTED_PRODUCT:$BASENAME"
				echo "VULNERABLE_PRODUCT:$LOG4J_FILE"
				echo "ANALYSIS:Log4J Jar found on host at [$LOG4J_FILE] is vulnerable to $CVE"
				echo "RECOMMENDATION:Upgrade to latest version of Log4J Jar"
				echo ""
			fi
		done
	done
}

