import sys
import json
import boto3
import codecs
import os
import logging
import argparse
import requests

RELEVANT_BUCKET_OBJECT_KEYS = ['AWS:WindowsUpdate', 'AWS:Application', 'AWS:InstanceInformation']

class AWS(object):
    def __init__(self, params):
        self.bucket = params['bucket']
        self.account_id = params['account_id']
        self.access_key = params['access_key']
        self.secret_key = params['secret_key']
        self.region = params['region']

    def auth(self, url, user, passwd):
        raise NotImplementedError("Subclass must implement abstract method")

    def oauth(self, url, user, passwd):
        raise NotImplementedError("Subclass must implement abstract method")

class EC2Impl(AWS):
    def __init__(self, params):
        super(EC2Impl, self).__init__(params)
        self.populate_bucket_object_list()

    def auth(self):
        raise NotImplementedError("Not implemented")

    def oauth(self, url, user, passwd):
        raise NotImplementedError("Not implemented")

    def configure():
        #write to the file(s), ~/.aws/config and ~/.aws/credentials
        raise NotImplementedError("Not implemented")

    def populate_bucket_object_list(self):
        logging.info("Obtainining asset inventory details from S3 bucket (this might take some time)...")
        self.bucket_object_list = []
        session = boto3.session.Session(aws_access_key_id=self.access_key,aws_secret_access_key=self.secret_key,region_name=self.region)
        s3 = session.resource('s3')
        self.s3_bucket = s3.Bucket(self.bucket)
        for obj in self.s3_bucket.objects.all():
            for b_key in RELEVANT_BUCKET_OBJECT_KEYS:
                if b_key in obj.key:
                    self.bucket_object_list.append(obj)
        #print "S3_relevant_bucket_object_array_len: %s" % (str(len(self.bucket_object_list)))
        #print "S3_relevant_bucket_objecgt: %s" % (self.bucket_object_list)

    def windows_patch_inventory(self, host):
        for obj in self.bucket_object_list:
            if 'AWS:WindowsUpdate' in obj.key and host in obj.key:
                splits = obj.key.rsplit('/')
                prefix = splits[0].split(':')[1]
                fname = '/tmp/' + prefix + '-' +  splits[-1]
                if os.path.isfile(fname) == False:
                    self.s3_bucket.download_file(obj.key,fname)
                try:
                    data = []
                    with codecs.open(fname,'rU','utf-8') as f:
               	        for line in f:
                            data.append(json.loads(line))
                    patches = []
                    for i in range(len(data)):
                        patch = {}
                        patch['url'] = ''
                        patch['id'] = data[i]['HotFixId']
                        patch['product'] = ''
                        patch['description'] = ''
                        patches.append(patch)
                    return patches
                except ValueError:
                    logging.error("JSON parsing failed for [%s]", fname)
                try:
                    os.remove(fname)
                except OSError:
                    logging.error("Failed to cleanup file [%s]", fname)
        return None

    def product_inventory(self, host, host_type):
        for obj in self.bucket_object_list:
            if 'AWS:Application' in obj.key and host in obj.key:
                splits = obj.key.rsplit('/')
                prefix = splits[0].split(':')[1]
                fname = '/tmp/' + prefix + '-' +  splits[-1]
                if os.path.isfile(fname) == False:
                    self.s3_bucket.download_file(obj.key,fname)
                try:
                    data = []
                    with codecs.open(fname,'rU','utf-8') as f:
               	        for line in f:
                            data.append(json.loads(line))
                    products = []
                    for i in range(len(data)):
                        if "Windows" in host_type:
                            pname = data[i]['Name']
                            pversion = data[i]['Version']
                            products.append(pname+' '+pversion)
                        elif host_type == "Amazon Linux AMI":
                            pname = data[i]['Name']
                            pver = data[i]['Version']
                            prpm = data[i]['PackageId']
                            parch = data[i]['Architecture']
                            index = prpm.rfind('-')
                            temp = prpm[index:-8]
                            product_name = pname+' '+pver+temp+"."+parch
                            #print "[%s][%s] ==> [%s]" % (pname, prpm, product_name)
                            products.append(product_name)
                    return products
                except ValueError:
                    logging.error("JSON parsing failed for [%s]", fname)
                try:
                    os.remove(fname)
                except OSError:
                    logging.error("Failed to cleanup file [%s]", fname)
        return None
      
    def asset_inventory(self, email):
        logging.info("Compiling asset inventory...")
        assets = []
        for obj in self.bucket_object_list:
            if 'AWS:InstanceInformation' in obj.key:
                splits = obj.key.rsplit('/')
                prefix = splits[0].split(':')[1]
                fname = '/tmp/' + prefix + '-' +  splits[-1]
                self.s3_bucket.download_file(obj.key,fname)
                try:
                    data = []
                    with codecs.open(fname,'rU','utf-8') as f:
                        s = f.read()
                        #print s
                        data.append(json.loads(s))
                    asset = {}
                    asset['id'] = data[0]['resourceId']
                    asset['name'] = data[0]['ComputerName']
                    logging.info("Found asset [%s] in AWS inventory", asset['name'])
                    asset['type'] = data[0]['PlatformName']
                    asset['owner'] = email
                    if 'Linux' in asset['type']:
                        asset['tags'] = [ 'Linux' ]
                    elif 'Windows' in asset['type']:
                        asset['tags'] = [ 'Windows' ]
                    logging.info("Retrieving product details for [%s]", asset['name'])
                    asset['products'] = self.product_inventory(asset['id'], asset['type'])
                    logging.info("Retrieving patch details for [%s]", asset['name'])
                    asset['patches'] = self.windows_patch_inventory(asset['id'])
                    assets.append(asset)
                except ValueError:
                    logging.error("JSON parsing failed for [%s]", fname)
                try:
                    os.remove(fname)
                except OSError:
                    logging.error("Failed to cleanup file [%s]", fname)
        logging.info("Total %s assets found in inventory...",str(len(assets)))
        return assets
         
def inventory(args):
    asset_url = "https://" + args.instance + "/api/v2/assets/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"
    params =  {}
    params['account_id'] = args.aws_account
    params['access_key'] = args.aws_access_key
    params['secret_key'] = args.aws_secret_key
    params['region'] = args.aws_region
    params['bucket'] = args.aws_s3_bucket
    aws =  EC2Impl(params)
    assets = aws.asset_inventory(args.handle)
    logging.info("Processing assets...")
    for asset in assets:
        #print asset
        resp = requests.get(asset_url + asset['id'] + "/" + auth_data)
        if resp.status_code != 200:
            # asset does not exist so create one with POST
            resp = requests.post(asset_url + auth_data, json=asset)
            if resp.status_code == 200:
                logging.info("Successfully created asset [%s]...", asset['name'])
            else:
                logging.error("Failed to create new asset: %s", json.dumps(asset))
                logging.error("Response details: %s", resp.content)
        else:
            # asset exists so update it with PUT
            resp = requests.put(asset_url + asset['id'] + "/" + auth_data, json=asset)
            if resp.status_code == 200:
                logging.info("Successfully updated asset [%s]...", asset['name'])
            else:
                logging.error("Failed to updated existing asset [%s]...", asset['name'])
                logging.error("Response details: %s", resp.content)
