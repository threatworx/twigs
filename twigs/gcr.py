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
    gcp_cis_utils.set_encoding(args.encoding)
    if not args.image:
        repo_urls = []
        if args.repository is None:
            projects = gcp_cis_utils.get_all_projects()
            for p in projects:
                out_json = gcp_cis_utils.run_gcloud_cmd("artifacts repositories list --location='%s' --project '%s' --filter 'format:DOCKER'" % (args.location,p))
                for entry in out_json:
                    # entry['name'] looks like "projects/tw-prod-300218/locations/us-central1/repositories/pb-container-repo"
                    tokens = entry['name'].split('/')
                    repo_url = "%s-docker.pkg.dev/%s/%s" % (tokens[3], tokens[1], tokens[5])
                    repo_urls.append(repo_url)
        else:
            repo_urls.append(args.repository)
        for repo_url in repo_urls:
            ilist_cmd = "container images list --repository " + repo_url
            i_json = gcp_cis_utils.run_gcloud_cmd(ilist_cmd)
            logging.info("Found %d images in %s", len(i_json), repo_url)
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
