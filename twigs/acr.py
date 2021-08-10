import sys
import os
import subprocess
import logging
import json

from . import utils
from .gcp_cis_tool import gcp_cis_utils
from . import docker

g_encoding = None

def set_encoding(encoding):
    global g_encoding
    g_encoding = encoding

def get_encoding():
    global g_encoding
    return g_encoding

def run_az_cmd(cmd):
    cmd = 'az ' + cmd + ' --output json --only-show-errors'
    try:
        logging.debug("Running cmd [%s]", cmd)
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
        ret_json = json.loads(cmd_output)
    except subprocess.CalledProcessError:
        logging.error("Error running az command [%s]", cmd)
        sys.exit(1)
    except ValueError:
        logging.error("Error parsing JSON output for az command [%s]: %s", cmd, cmd_output)
        sys.exit(1)
    return ret_json

def get_latest_tag_with_digest(image_name, repository):
    tags_cmd = "acr repository show-tags --name " + repository + " --repository " + image_name + " --orderby time_desc --detail"
    t_json = run_az_cmd(tags_cmd)
    if len(t_json) > 0:
        for entry in t_json:
            if entry['name'] == "latest":
                return ":latest", entry['digest']
        return ":" + t_json[0]['name'], t_json[0]['digest']
    return None, None

def get_digest(image_name, repository):
    #remove tag from image_name
    image_name_tokens = image_name.split(':')
    image_name = image_name_tokens[0]
    image_tag = image_name_tokens[1]

    tags_cmd = "acr repository show-tags --name " + repository + " --repository " + image_name + " --orderby time_desc --detail"
    t_json = run_az_cmd(tags_cmd)
    if len(t_json) > 0:
        for entry in t_json:
            if entry['name'] == image_tag:
                return entry['digest']
    return None

def get_inventory(args):
    set_encoding(args.encoding)
    allassets = [] 
    if args.registry is None and args.image is None:
        logging.error("Either fully qualified image name (with repository and tag / digest) or repository url needs to be specified")
        return None
    if not args.image:
        logging.info("Starting discovery of images in ACR")
        getLoginServer_cmd = "acr show --name " + args.registry
        ret_json = run_az_cmd(getLoginServer_cmd)
        loginServer = ret_json['loginServer']
        ilist_cmd = "acr repository list --name " + args.registry
        i_json = run_az_cmd(ilist_cmd)
        logging.info("Found %d images in %s", len(i_json), args.registry)
        for i in i_json:
            tag, digest = get_latest_tag_with_digest(i, args.registry)
            if tag == None:
                logging.error("Unable to determine latest tag for image. Skipping %s",i)
                continue
            logging.info("Using tag/digest '"+tag[1:]+"'")
            image_name = loginServer + "/" + i + tag
            args.image = image_name
            args.assetid = image_name
            args.assetid = args.assetid.replace('/','-')
            args.assetid = args.assetid.replace(':','-')
            args.assetname = image_name
            logging.info("Discovering image "+args.image)
            assets = docker.get_inventory(args, digest)
            if assets:
                allassets = allassets + assets
        for a in allassets:
            a['tags'].append('ACR')
        return allassets
    else:
        tokens = args.image.split('.azurecr.io/')
        if len(tokens) != 2:
            logging.error("Invalid ACR image name specified. Please specify fully qualified image name ( like myregistry.azurecr.io/myimage[:mytag] )")
            return None
        repository = tokens[0]
        image_name = tokens[1]
        if ':' not in image_name:
            tag, digest = get_latest_tag_with_digest(image_name, repository)
            if tag == None:
                logging.error("Unable to determine latest tag / digest for image")
                return None 
            logging.info("Using tag/digest '"+tag[1:]+"'")
            args.image = args.image + tag
        else:
            digest = get_digest(image_name, repository)
        args.assetid = args.image
        args.assetid = args.assetid.replace('/','-')
        args.assetid = args.assetid.replace(':','-')
        args.assetname = args.image
        logging.info("Discovering image "+args.image)
        assets = docker.get_inventory(args, digest)
        if assets != None:
            for a in assets:
                a['tags'].append('ACR')
        return assets 

