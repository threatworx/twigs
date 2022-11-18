#!/bin/sh

SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`

check_embedded_log4j_vuln_version()
{
	WAR_JAR_FILE="$1"
	shift
	LOG4J_FILE="$1"
	shift
	CVE="$1"
	shift
	VULN_VERSIONS="$*"
	BASENAME=`basename $LOG4J_FILE`
	LOG4J_VERSION=`echo $BASENAME | cut -c 12- | sed 's/.jar$//'`
	for VULN_VERSION in $VULN_VERSIONS
	do
		if [ $LOG4J_VERSION = $VULN_VERSION ]; then
			echo "TYPE:IMPACT"
			echo "VULN:$CVE"
			echo "PERCENTAGE:100"
			echo "AFFECTED_PRODUCT:$WAR_JAR_FILE"
			echo "VULNERABLE_PRODUCT:$BASENAME"
			echo "ANALYSIS:Log4J Jar found in [$WAR_JAR_FILE] is vulnerable to $CVE"
			echo "RECOMMENDATION:Upgrade to latest version of Log4J Jar"
			echo ""
		fi
	done
}

check_log4j_vuln_version()
{
	LOG4J_FILE="$1"
	shift
	CVE="$1"
	shift
	VULN_VERSIONS="$*"
	BASENAME=`basename $LOG4J_FILE`
	LOG4J_VERSION=`echo $BASENAME | cut -c 12- | sed 's/.jar$//'`
	for VULN_VERSION in $VULN_VERSIONS
	do
		if [ $LOG4J_VERSION = $VULN_VERSION ]; then
			echo "TYPE:IMPACT"
			echo "VULN:$CVE"
			echo "PERCENTAGE:100"
			echo "AFFECTED_PRODUCT:$LOG4J_FILE"
			echo "VULNERABLE_PRODUCT:$BASENAME"
			echo "ANALYSIS:Log4J Jar found at [$LOG4J_FILE] is vulnerable to $CVE"
			echo "RECOMMENDATION:Upgrade to latest version of Log4J Jar"
			echo ""
		fi
	done
}

check_log4j_vulns()
{
	ROOT_FOLDER="$1"
	CVE_2021_44228_LOG4J_VERSIONS="2.0-beta9 2.0-rc1 2.0-rc2 2.0.1 2.0.2 2.0 2.1 2.2 2.3 2.4 2.5 2.6 2.6.1 2.6.2 2.7 2.8 2.8.1 2.8.2 2.9.0 2.9.1 2.10.0 2.11.0 2.11.1 2.12.0 2.12.1 2.13.0 2.13.1 2.13.2 2.13.3 2.14.0 2.14.1"
	CVE_2021_44832_LOG4J_VERSIONS="2.0-beta7 2.0-beta8 2.0-beta9 2.0-rc1 2.0-rc2 2.0.1 2.0.2 2.0 2.1 2.2 2.3 2.3.1 2.4 2.4.1 2.5 2.6 2.6.1 2.6.2 2.7 2.8 2.8.1 2.8.2 2.9.0 2.9.1 2.10.0 2.11.0 2.11.1 2.12.0 2.12.1 2.12.2 2.12.3 2.13.0 2.13.1 2.13.2 2.13.3 2.14.0 2.14.1 2.15.0 2.16.0 2.17.0"
	CVE_2021_45046_LOG4J_VERSIONS="2.0-beta9 2.0-rc1 2.0-rc2 2.0.1 2.0.2 2.0 2.1 2.2 2.3 2.4 2.5 2.6.1 2.6.2 2.7 2.8 2.8.1 2.8.2 2.9.0 2.9.1 2.10.0 2.11.0 2.11.1 2.12.0 2.12.1 2.13.0 2.13.1 2.13.2 2.13.3 2.14.0 2.14.1 2.15.0"
	CVE_2021_45105_LOG4J_VERSIONS="2.0-beta9 2.0-rc1 2.0-rc2 2.0.1 2.0.2 2.0 2.1 2.2 2.3 2.4 2.4.1 2.5 2.6 2.6.1 2.6.2 2.7 2.8 2.8.1 2.8.2 2.9.0 2.9.1 2.10.0 2.11.0 2.11.1 2.12.0 2.12.1 2.12.2 2.13.0 2.13.1 2.13.2 2.13.3 2.14.0 2.14.1 2.15.0 2.16.0"
	LOG4J_FILES=`find $ROOT_FOLDER -name 'log4j-core-*.jar' -type f`
	for LOG4J_FILE in $LOG4J_FILES
	do
		check_log4j_vuln_version "$LOG4J_FILE" "CVE-2021-44228" $CVE_2021_44228_LOG4J_VERSIONS
		check_log4j_vuln_version "$LOG4J_FILE" "CVE-2021-44832" $CVE_2021_44832_LOG4J_VERSIONS
		check_log4j_vuln_version "$LOG4J_FILE" "CVE-2021-45046" $CVE_2021_45046_LOG4J_VERSIONS
		check_log4j_vuln_version "$LOG4J_FILE" "CVE-2021-45105" $CVE_2021_45105_LOG4J_VERSIONS
	done
	WAR_FILES=`find $ROOT_FOLDER -name "*.war" -type f`
	for WAR_FILE in $WAR_FILES
	do
		LOG4J_FILES=`jar -tf $WAR_FILE | grep 'log4j-core-.*\.jar'`
		for LOG4J_FILE in $LOG4J_FILES
		do
			check_embedded_log4j_vuln_version "$WAR_FILE" "$LOG4J_FILE" "CVE-2021-44228" $CVE_2021_44228_LOG4J_VERSIONS
			check_embedded_log4j_vuln_version "$WAR_FILE" "$LOG4J_FILE" "CVE-2021-44832" $CVE_2021_44832_LOG4J_VERSIONS
			check_embedded_log4j_vuln_version "$WAR_FILE" "$LOG4J_FILE" "CVE-2021-45046" $CVE_2021_45046_LOG4J_VERSIONS
			check_embedded_log4j_vuln_version "$WAR_FILE" "$LOG4J_FILE" "CVE-2021-45105" $CVE_2021_45105_LOG4J_VERSIONS
		done
	done
}

check_log4j_vulns "$1"
