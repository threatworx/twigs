import sys
import json
import boto3
import codecs
import os
import logging
import tempfile

RELEVANT_BUCKET_OBJECT_KEYS = ['AWS:WindowsUpdate', 'AWS:Application', 'AWS:InstanceInformation']

class AWS(object):
    def __init__(self, params):
        self.bucket = params['bucket']
        self.account_id = params['account_id']
        self.access_key = params['access_key']
        self.secret_key = params['secret_key']
        self.region = params['region']
        self.enable_tracking_tags = params['enable_tracking_tags']

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
                fname = tempfile.gettempdir() + os.path.sep + 'WindowsUpdate-' +  splits[-1]
                if os.path.isfile(fname) == True:
                    os.remove(fname)
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
                fname = tempfile.gettempdir() + os.path.sep + 'Application-' +  splits[-1]
                if os.path.isfile(fname) == True:
                    os.remove(fname)
                self.s3_bucket.download_file(obj.key,fname)
                try:
                    data = []
                    with codecs.open(fname,'rU','utf-8') as f:
               	        for line in f:
                            data.append(json.loads(line))
                    # print(data)
                    products = []
                    for i in range(len(data)):
                        if "Windows" in host_type:
                            pname = data[i]['Name']
                            pversion = data[i]['Version']
                            products.append(pname+' '+pversion)
                        elif host_type in ["Amazon Linux AMI", "Red Hat", "CentOS"]:
                            pname = data[i]['Name']
                            pver = data[i]['Version']
                            prpm = data[i]['PackageId']
                            parch = data[i]['Architecture']
                            index = prpm.rfind('-')
                            temp = prpm[index:-8]
                            product_name = pname+' '+pver+temp+"."+parch
                            #print "[%s][%s] ==> [%s]" % (pname, prpm, product_name)
                            products.append(product_name)
                        elif host_type == "Ubuntu":
                            pname = data[i]['Name']
                            pver = data[i]['Version']
                            parch = data[i]['Architecture']
                            product_name = pname+' '+pver
                            #print "[%s][%s] ==> [%s]" % (pname, prpm, product_name)
                            products.append(product_name)
                        elif host_type == "Suse":
                            pname = data[i]['Name']
                            pver = data[i]['Version']
                            prel = data[i]['Release']
                            parch = data[i]['Architecture']
                            product_name = pname+' '+pver+'-'+prel+'.'+parch
                            products.append(product_name)
                    return products
                except ValueError:
                    logging.error("JSON parsing failed for [%s]", fname)
                try:
                    os.remove(fname)
                except OSError:
                    logging.error("Failed to cleanup file [%s]", fname)
        return None

    def get_asset_type(self, platformName):
        if platformName == "Amazon Linux":
            return "Amazon Linux AMI"
        elif "windows" in platformName.lower():
            return "Windows"
        elif platformName == "SLES":
            return "Suse"
        elif "centos" in platformName.lower():
            return "CentOS"
        elif "red hat" in platformName.lower():
            return "Red Hat"
        return platformName
      
    def asset_inventory(self, email):
        logging.info("Compiling asset inventory...")
        assets = []
        for obj in self.bucket_object_list:
            if 'AWS:InstanceInformation' in obj.key:
                splits = obj.key.rsplit('/')
                fname = tempfile.gettempdir() + os.path.sep + 'InstanceInformation-' +  splits[-1]
                if os.path.isfile(fname) == True:
                    os.remove(fname)
                self.s3_bucket.download_file(obj.key,fname)
                try:
                    data = []
                    with codecs.open(fname,'rU','utf-8') as f:
                        s = f.read()
                        #print s
                        data.append(json.loads(s))
                    if data[0].get('InstanceStatus') == 'Terminated':
                        # skip instances which are not running
                        continue
                    asset = {}
                    asset['id'] = data[0]['resourceId']
                    asset['name'] = data[0]['ComputerName']
                    logging.info("Found asset [%s] in AWS inventory", asset['name'])
                    asset['type'] = self.get_asset_type(data[0]['PlatformName'])
                    asset['owner'] = email
                    asset['tags'] = []
                    os_release = None
                    if 'Linux' in asset['type']:
                        asset['tags'].append('Linux')
                    elif 'Ubuntu' in asset['type']:
                        asset['tags'].append('Linux')
                        os_release = asset['type'] + " " + data[0]['PlatformVersion']
                    elif 'Windows' in asset['type']:
                        asset['tags'].append('Windows')
                        os_release = data[0]['PlatformName']
                    elif asset['type'] == 'Suse':
                        asset['tags'].append('Linux')
                        pv = data[0]['PlatformVersion']
                        if "." in pv:
                            os_version = data[0]['PlatformVersion'].split('.')[0]
                            sp_level = data[0]['PlatformVersion'].split('.')[1]
                        else:
                            os_version = data[0]['PlatformVersion']
                            sp_level = '0'
                        if sp_level != '0':
                            os_release = "SUSE Linux Enterprise Server %s SP%s" % (os_version,sp_level)
                        else:
                            os_release = "SUSE Linux Enterprise Server %s" % (os_version)
                    elif asset['type'] == 'CentOS':
                        asset['tags'].append('Linux')
                    elif asset['type'] == 'Red Hat':
                        asset['tags'].append('Linux')

                    if os_release is not None:
                        asset['tags'].append("OS_RELEASE:" + os_release)
                    if self.enable_tracking_tags == True:
                        asset['tags'].append("SOURCE:AWS:"+self.account_id)
                    else:
                        asset['tags'].append("SOURCE:AWS")
                    logging.info("Retrieving product details for [%s]", asset['name'])
                    asset['products'] = self.product_inventory(asset['id'], asset['type'])
                    asset['tags'].append(asset['type'])
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
         
def get_inventory(args):
    params =  {}
    params['account_id'] = args.aws_account
    params['access_key'] = args.aws_access_key
    params['secret_key'] = args.aws_secret_key
    params['region'] = args.aws_region
    params['bucket'] = args.aws_s3_bucket
    params['enable_tracking_tags'] = args.enable_tracking_tags
    aws =  EC2Impl(params)
    assets = aws.asset_inventory(args.handle)
    return assets
