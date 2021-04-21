import sys
import os
import subprocess
import logging
import json

from . import docker


g_encoding = None

def set_encoding(encoding):
    global g_encoding
    g_encoding = encoding

def get_encoding():
    global g_encoding
    return g_encoding

def get_repo_uri(repository, repositoryType):

    if repositoryType == 'private':
        repo_cmd = "ecr describe-repositories"
    else:
        repo_cmd = "ecr-public describe-repositories"

    t_json = run_aws_cmd(repo_cmd)

    if len(t_json) > 0:
        for i in t_json['repositories']:
            if i['repositoryName'] == repository:
                return i['repositoryUri']

def run_aws_cmd(cmd):
    cmd = 'aws --output json ' + cmd
    try:
        cmd_output = subprocess.check_output([cmd], shell=True, stdin=None, stderr=None)
        cmd_output = cmd_output.decode(get_encoding())
        ret_json = json.loads(cmd_output)

    except subprocess.CalledProcessError:
        logging.error("Error running aws  command [%s]", cmd)
        ret_json = { }
    except ValueError:
        logging.error("Error parsing JSON output for aws command [%s]: %s", cmd, cmd_output)
        ret_json = { }
    return ret_json


def get_inventory(args):
    set_encoding(args.encoding)
    allassets = []
    
    if args.repositoryUri is None and args.registryId is None:
        logging.error("Either  fully qualified image name (repositoryUri) or registry id (AWS account Id) needs to be specified.")
        return None
    if not args.repositoryUri: #search for all repositories and images under it
       
        logging.info("Starting discovery of images in ECR")
        if args.repositoryType == 'private':
            iRepo_cmd = "ecr describe-repositories"
        else:
            iRepo_cmd = "ecr-public describe-repositories"

        i_json_repos = run_aws_cmd(iRepo_cmd)

        if len(i_json_repos) > 0:
            logging.info("Found %d repositories in %s", len(i_json_repos), args.registryId)
            for repo in i_json_repos['repositories']:

                if args.repositoryType == 'private':
                    iImage_cmd = "ecr describe-images --repository-name " + repo['repositoryName']
                else:
                    iImage_cmd = "ecr-public describe-images --repository-name " + repo['repositoryName']

                i_json_images = run_aws_cmd(iImage_cmd)
                for image in i_json_images['imageDetails']:

                    if args.tag is None:
                        no_of_tags = len(image['imageTags'])
                        if 'latest' in image['imageTags']:
                            tag = ':' + 'latest'
                        else:
                            tag = ':' + image['imageTags'][no_of_tags -1]


                    logging.info("Using %s as a latest tag for the repository %s", tag,repo['repositoryName'])            
                    args.image = get_repo_uri(repo['repositoryName'],args.repositoryType) + tag
                    args.assetid = args.image
                    args.assetname = args.image
                    logging.info("Discovering image %s", args.image)
                    assets = docker.get_inventory(args)

                    if assets:
                        allassets.extend(assets)            
        for a in allassets:
            a['tags'].append('ECR')
            return allassets
    else:
        #particular image(s) in the repository        
        tokens = args.repositoryUri.split('.amazonaws.com/')
        uri = tokens[0]
        repo_name = tokens[1]

        if ':' not in repo_name:#get the latest tag for image, if available 'latest' otherwise most recent.
        
            if args.repositoryType == 'private':
                ilist_cmd = "ecr describe-images --repository-name " + repo_name 
            else:
                ilist_cmd = "ecr-public describe-images --repository-name " + repo_name
       
            i_json = run_aws_cmd(ilist_cmd)

            if len(i_json) > 0:

                for image in i_json['imageDetails']:
                    if args.tag is None:
                        no_of_tags = len(image['imageTags'])
                        if 'latest' in image['imageTags']:
                            tag = ':' + 'latest'
                        else:
                            tag = ':' + image['imageTags'][no_of_tags-1]
                
                    logging.info("Using %s as a latest tag for the repository %s", tag,repo_name)            
                    args.image = get_repo_uri(repo_name,args.repositoryType) + tag
                    args.assetid = args.image
                    args.assetname = args.image
                    logging.info("Discovering image %s", args.image)
                    assets = docker.get_inventory(args)

                    if assets:
                        allassets.extend(assets)            
            for a in allassets:
                a['tags'].append('ECR')
                return allassets
            else:
                logging.info("This repository has no images")
                return None
        else:#user has provided repositoryUri (image) with tag
            args.image = args.repositoryUri
            args.assetid = args.image
            args.assetname = args.image
            logging.info("Discovering image %s", args.image)
            assets = docker.get_inventory(args)

            if assets:
                for a in assets:
                    a['tags'].append('ECR')
                    return assets

        
