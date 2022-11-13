#!/bin/sh

check_embedded_log4j_vuln()
{
	ROOT_FOLDER="$1"
	shift
	CVE="$1"
	shift
	WAR_JAR_PATTERN="$1"
	shift
	VULN_VERSIONS="$*"
	WAR_JAR_FILES=`find $ROOT_FOLDER -name "$WAR_JAR_PATTERN" -type f`
	for WAR_JAR_FILE in $WAR_JAR_FILES
	do
		LOG4J_FILES=`jar -tf $WAR_JAR_FILE | grep 'log4j-core-.*\.jar'`
		for LOG4J_FILE in $LOG4J_FILES
		do
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
		done
	done
}

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
			LOG4J_VERSION=`echo $BASENAME | cut -c 12- | sed 's/.jar$//'`
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
	done
	check_embedded_log4j_vuln $ROOT_FOLDER $CVE "*.war" $VULN_VERSIONS
	check_embedded_log4j_vuln $ROOT_FOLDER $CVE "*.jar" $VULN_VERSIONS
}

