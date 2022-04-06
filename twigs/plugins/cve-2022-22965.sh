#!/bin/sh

ROOT_FOLDER=$1
UNPACK_TOOL=
which jar > /dev/null 2>&1
if [ $? -eq 0 ]; then
	UNPACK_TOOL="jar"
else
	which unzip > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		UNPACK_TOOL="unzip"
	fi
fi
if [ -z "$UNPACK_TOOL" ]; then
       exit 0
fi
AFFECTED_JAVA_VERSION=0
if [ $ROOT_FOLDER != "/" ]; then
	AFFECTED_JAVA_VERSION=1
else
	which java > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		JAVA_VERSION=`java --version | head -1 | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+"`
		MAJOR_JV=`echo $JAVA_VERSION | cut -f 1 -d.`
		if [ $MAJOR_JV -ge 9 ]; then
			AFFECTED_JAVA_VERSION=1
		fi
	fi
fi

if [ $AFFECTED_JAVA_VERSION -eq 0 ]; then
	exit 0
fi

TOMCAT_PRESENT=0
CATALINA_JAR_COUNT=`find $ROOT_FOLDER -name 'catalina.jar' -type f | wc -l`
if [ $CATALINA_JAR_COUNT -gt 0 ]; then
	TOMCAT_PRESENT=1
fi

if [ $TOMCAT_PRESENT -eq 0 ]; then
	exit 0
fi

WAR_FILES=`find $ROOT_FOLDER -name '*.war' -type f`
for WAR_FILE in $WAR_FILES
do
	TEMP_DIR=$(mktemp -d)

	if [ "$UNPACK_TOOL" = "jar" ]; then
		cd $TEMP_DIR > /dev/null 2>&1
		jar xf $WAR_FILE > /dev/null 2>&1
		cd - > /dev/null 2>&1
	else
		unzip $WAR_FILE -d $TEMP_DR > /dev/null 2>&1
	fi

	JAR_FILES=`find $TEMP_DIR -name '*.jar' -type f`
	for JAR_FILE in $JAR_FILES
	do
		VULNERABLE=0
		BASENAME=`basename $JAR_FILE`
		PATTERN=`echo $BASENAME | grep -E -o "^spring-webmvc-[0-9]+\.[0-9]+\.[0-9]"`
		if [ "$PATTERN" != "" ]; then
			JF_VERSION=`echo $PATTERN | cut -f3 -d-`
			V1=`echo $JF_VERSION | cut -f1 -d.`
			V2=`echo $JF_VERSION | cut -f2 -d.`
			V3=`echo $JF_VERSION | cut -f3 -d.`
			if [ $V1 -eq 5 ] && [ $V2 -eq 3 ] && [ $V3 -le 17 ]; then
				VULNERABLE=1
			elif [ $V1 -eq 5 ] && [ $V2 -eq 2 ] && [ $V3 -le 19 ]; then
				VULNERABLE=1
		       	elif [ $V1 -le 5 ]; then
		 		VULNERABLE=1		
			fi
		fi
		if [ $VULNERABLE -eq 1 ]; then
			echo "TYPE:IMPACT"
			echo "VULN:CVE-2022-22965"
			echo "PERCENTAGE:100"
			echo "AFFECTED_PRODUCT:$BASENAME"
			echo "VULNERABLE_PRODUCT:$BASENAME"
			echo "ANALYSIS:[$BASENAME] JAR found in WAR [$WAR_FILE] is vulnerable to CVE-2022-22965"
			TEMP_BASENAME=`echo $BASENAME | cut -f1-2 -d-`
			echo "RECOMMENDATION:Upgrade to latest version of [$TEMP_BASENAME] JAR contained in WAR [$WAR_FILE]"
			echo ""
		fi
	done
	rm -rf $TEMP_DIR
done
