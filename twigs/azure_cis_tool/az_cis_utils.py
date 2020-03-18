import os
import json
import logging
import requests

def query_az(query):
    if os.name == 'nt':
        query = query + " 2>NUL"
    else:
        query = query + " 2>/dev/null"
    json_cis=os.popen(query).read()
    return json.loads(json_cis)

def get_subscriptions():
    logging.info("Retrieving subscriptions...")
    subid=[]
    cloudname=[]
    subname=[]
    try:
        querysub='az account list --query [*].[id,cloudName,name]'
        json_cis=query_az(querysub)
        if len(json_cis) == 0:
            return None
        #with open('subtest.txt') as f:
        #    json_cis = json.load(f)
        #iteration through Storage Account
        for i in range(len(json_cis)):
            subid.append(json_cis[i][0])
            cloudname.append(json_cis[i][1])
            subname.append(json_cis[i][2])
        return [subid,cloudname,subname]
    except Exception as e:
        logging.error('Failing ' + str(e))
        return None
