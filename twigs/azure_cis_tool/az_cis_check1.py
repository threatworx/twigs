import os
import json
import logging
import requests
import sys
from . import az_cis_utils as az_cis_utils

def check11(subid):
    logging.info("Processing 11...")
    
    try:
        query11=('az account get-access-token --subscription %s --query [accessToken]' % subid)
        #score11=['<font color="red">Failed</font>',0]
        json_cis=az_cis_utils.query_az(query11)
        access_token=json_cis[0]
        headers = {"Authorization": 'Bearer ' + access_token}
        request1 = ('https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2017-05-01' % subid)
        request2 = ('https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleassignments?api-version=2017-10-01-preview' % subid)
        try:
            json_output1 = requests.get(request1, headers=headers).json()
            json_output2 = requests.get(request2, headers=headers).json()
            for j in range(len(json_output2['value'])):
                pType=json_output2['value'][j]['properties']['principalType']
                pid=json_output2['value'][j]['properties']['principalId']
                rid=json_output2['value'][j]['properties']['roleDefinitionId']
                for i in range(len(json_output1['value'])):
                    rolename=json_output1['value'][i]['properties']['roleName']
                    nameB=json_output1['value'][i]['name']
                    if ("Owner" in rolename or "Admin" in rolename  or "Contributor" in rolename and nameB in rid):
                        query111=('az ad user list --query "[?objectId==\'%s\'][userPrincipalName]"' % pid)
                        #json_cis2=az_cis_utils.query_az(query111)
                        #upn=json_cis2[0][0]
                        #print(upn)
                        unkScore=['<font color="orange">UNKNOWN </font>',0]
                        chk="No Supported"
                        return [chk,unkScore]                        
        except Exception as e:
            logging.error("Exception in check11: %s %s" %(type(e), str(e.args)))
            unkScore=['<font color="orange">UNKNOWN </font>',0]
            chk="Failed to make API call"
            return [chk,unkScore]
    except Exception as e:
        logging.error("Exception in check11: %s %s" %(type(e), str(e.args)))
        unkScore=['<font color="orange">UNKNOWN </font>',0]
        chk="Failed to Query"
        return [chk,unkScore]

def check12():
    logging.info("Processing 12...")
    return ["Check not available with azure CLI"]

def check13():
    logging.info("Processing 13...")
    st13=""
    passvalue13 = 0
    totalvalue13 = 0
    score13=""
    passed13='<font color="green">Passed </font>'
    try:
        query13='az ad user list --query "[?userType==\'Guest\']"'
        #query13=""
        json_cis=az_cis_utils.query_az(query13)
        if (len(json_cis)>0):
            #iteration through roles
            passed13='<font color="red">Failed </font>'
            totalvalue13 = len(json_cis)
            st13=("%d Guest users Found" % totalvalue13)
        else:
            st13="No Guest users Found"
            passvalue13 = 1
            totalvalue13 = 1
        
        score13=[st13,passvalue13,totalvalue13,passed13]
        return score13
    except Exception as e:
        logging.error("Exception in check13: %s %s" %(type(e), str(e.args)))
        st13="Failed to query users"
        passed13='<font color="orange">UNKNOWN </font>'
        totalvalue13 = 1
        score13=[st13,passvalue13,totalvalue13,passed13]
        return score13


def check14():
    logging.info("Processing 14...")
    return ["Check not available with azure CLI"]

def check15():
    logging.info("Processing 15...")
    return ["Check not available with azure CLI"]

def check16():
    logging.info("Processing 16...")
    return ["Check not available with azure CLI"]

def check17():
    logging.info("Processing 17...")
    return ["Check not available with azure CLI"]

def check18():
    logging.info("Processing 18...")
    return ["Check not available with azure CLI"]

def check19():
    logging.info("Processing 19...")
    return ["Check not available with azure CLI"]

def check110():
    logging.info("Processing 110...")
    return ["Check not available with azure CLI"]

def check111():
    logging.info("Processing 111...")
    return ["Check not available with azure CLI"]

def check112():
    logging.info("Processing 112...")
    return ["Check not available with azure CLI"]

def check113():
    logging.info("Processing 113...")
    return ["Check not available with azure CLI"]

def check114():
    logging.info("Processing 114...")
    return ["Check not available with azure CLI"]

def check115():
    logging.info("Processing 115...")
    return ["Check not available with azure CLI"]

def check116():
    logging.info("Processing 116...")
    return ["Check not available with azure CLI"]

def check117():
    logging.info("Processing 117...")
    return ["Check not available with azure CLI"]

def check118():
    logging.info("Processing 118...")
    return ["Check not available with azure CLI"]

def check119():
    logging.info("Processing 119...")
    return ["Check not available with azure CLI"]

def check120():
    logging.info("Processing 120...")
    return ["Check not available with azure CLI"]

def check121():
    logging.info("Processing 121...")
    return ["Check not available with azure CLI"]

def check122():
    logging.info("Processing 122...")
    return ["Check not available with azure CLI"]

def check123():
    logging.info("Processing 123...")
    st123=""
    passvalue123 = 0
    failvalue123 = 0
    totalvalue123 = 0
    score123=""
    passed123='<font color="green">Passed </font>'
    try:
        query123='az role definition list --query [*][roleName,assignableScopes,permissions[].actions]'
        json_cis=az_cis_utils.query_az(query123)
        if (len(json_cis)>0):
            #iteration through roles
            for i in range(len(json_cis)):
                role = json_cis[i][0]
                scope= json_cis[i][1][0]
                actions = json_cis[i][2][0]
                #iteration through actions
                if (len(actions)>0):
                    for j in range(len(actions)):
                        if (scope=="/"  and actions[j]=="*"):
                            st123=st123+('Role <b>%s</b> with unrestricted access <br>\n' % role)
                            passed123='<font color="red">Failed </font>'
                            failvalue123=failvalue123+1
                    totalvalue123 = totalvalue123+1
                    passvalue123 = totalvalue123 - failvalue123
                else:
                    st123=st123+('No actions found for role <b>%s</b> with unrestricted access <br>\n' % role)
        else:
            st123="Roles not found"
        score123=[st123,passvalue123,totalvalue123,passed123]
        return score123
    except Exception as e:
        logging.error("Exception in check123: %s %s" %(type(e), str(e.args)))
        st123="Failed to query definition role"
        passed123='<font color="orange">UNKNOWN </font>'
        totalvalue123 = 1
        score123=[st123,passvalue123,totalvalue123,passed123]
        return score123
