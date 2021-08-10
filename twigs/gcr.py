import sys
import os
import subprocess
import logging
import json

from . import utils
from .gcp_cis_tool import gcp_cis_utils
from . import docker

def get_latest_tag(imagename):
    tcmd = "container images list-tags "+imagename+" --sort-by=~timestamp"
    t_json = gcp_cis_utils.run_gcloud_cmd(tcmd)
    if t_json:
        if len(t_json[0]['tags']) != 0:
            return ':' + t_json[0]['tags'][-1]
        else:
            return '@' + t_json[0]['digest']
    return None

def get_digest(imagename):
    tcmd = "container images describe "+imagename
    t_json = gcp_cis_utils.run_gcloud_cmd(tcmd)
    if t_json:
        return t_json['image_summary']['digest']

def get_inventory(args):
    allassets = [] 
    if args.repository is None and args.image is None:
        logging.error("Either fully qualified image name (with repository and tag / digest) or repository url needs to be specified")
        return None
    gcp_cis_utils.set_encoding(args.encoding)
    if not args.image:
        ilist_cmd = "container images list --repository "+args.repository
        i_json = gcp_cis_utils.run_gcloud_cmd(ilist_cmd)
        logging.info("Found %d images in %s", len(i_json), args.repository)
        for i in i_json:
            tag = get_latest_tag(i['name'])
            if tag == None:
                logging.error("Unable to determine latest tag / digest for image. Skipping "+i['name'])
                continue
            logging.info("Using tag/digest '"+tag[1:]+"'")
            args.image = i['name'] + tag
            args.assetid = i['name'] + tag
            args.assetid = args.assetid.replace('/','-')
            args.assetid = args.assetid.replace(':','-')
            args.assetname = i['name'] + tag
            logging.info("Discovering image "+args.image)
            assets = docker.get_inventory(args, get_digest(args.image))
            if assets:
                allassets = allassets + assets
        for a in allassets:
            a['tags'].append('GCR')
        return allassets
    else:
        image = args.image.split('/')[-1]
        if ':' not in image and '@' not in image:
            tag = get_latest_tag(args.image)
            if tag == None:
                logging.error("Unable to determine latest tag / digest for image")
                return None 
            logging.info("Using tag/digest '"+tag[1:]+"'")
            args.image = args.image + tag
        args.assetid = args.image
        args.assetid = args.assetid.replace('/','-')
        args.assetid = args.assetid.replace(':','-')
        args.assetname = args.image
        logging.info("Discovering image "+args.image)
        assets = docker.get_inventory(args, get_digest(args.image))
        if assets != None:
            for a in assets:
                a['tags'].append('GCR')
        return assets 
