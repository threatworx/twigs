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

def get_image_digest(image_name, image_tag, repo_type):
    if repo_type == "private":
        repo_cmd = "ecr describe-images --repository-name %s --image-ids imageTag=%s" % (image_name, image_tag)
        t_json = run_aws_cmd(repo_cmd)

        if len(t_json) > 0:
            return t_json['imageDetails'][0]['imageDigest']
    return None

def get_inventory(args):
    set_encoding(args.encoding)
    allassets = []

    repositoryUri = args.image
    registryId = args.registry
    
    if repositoryUri is None and registryId is None:
        logging.error("Either  fully qualified image name (repositoryUri) or registry id (AWS account Id) needs to be specified.")
        return None
    if not repositoryUri: #search for all repositories and images under it
       
        if args.repository_type == 'private':
            iRepo_cmd = "ecr describe-repositories"
        else:
            iRepo_cmd = "ecr-public describe-repositories"

        i_json_repos = run_aws_cmd(iRepo_cmd)

        if len(i_json_repos) > 0: #if user supplies wrong registryId, case: supplied public repo but forgot to mention repository_type
            if i_json_repos['repositories'][0]['registryId'] not in registryId:
                logging.error("Please check registry ID and repository type")
                return None

        logging.info("Starting discovery of images in ECR")
        if len(i_json_repos) > 0:
            logging.info("Found %d repositories in %s", len(i_json_repos['repositories']), registryId)
            for repo in i_json_repos['repositories']:

                if args.repository_type == 'private':
                    iImage_cmd = "ecr describe-images --repository-name " + repo['repositoryName']
                else:
                    iImage_cmd = "ecr-public describe-images --repository-name " + repo['repositoryName']

                i_json_images = run_aws_cmd(iImage_cmd)
                for image in i_json_images['imageDetails']:

                    no_of_tags = len(image['imageTags'])
                    if 'latest' in image['imageTags']:
                        tag = ':' + 'latest'
                    else:
                        tag = ':' + image['imageTags'][no_of_tags -1]


                    logging.info("Using %s as a latest tag for the repository %s", tag,repo['repositoryName'])            
                    args.image = get_repo_uri(repo['repositoryName'],args.repository_type) + tag
                    args.assetid = args.image
                    args.assetid = args.assetid.replace('/','-')
                    args.assetid = args.assetid.replace(':','-')
                    args.assetname = args.image
                    logging.info("Discovering image %s", args.image)
                    assets = docker.get_inventory(args, image['imageDigest'])

                    if assets:
                        allassets.extend(assets)            
            for a in allassets:
                a['tags'].append('ECR')
            return allassets
    else:
        #particular image(s) in the repository


        if args.repository_type == 'private':

            tokens = repositoryUri.split('amazonaws.com/')
            if len(tokens) != 2:
                logging.error("Specify fully qualified repository name, if a tag is not mentioned then the 'latest' will be determined and all images under repository will be discovered")
                return None
            else:
                repo_name = tokens[1]
        else:

            tokens = repositoryUri.split('/')
            if len(tokens) != 3:

                logging.error("Specify fully qualified repository name, if a tag is not mentioned then the 'latest' will be determined and all images under repository will be discovered")
                return None
            else:
                repo_name = tokens[2]

        if ':' not in repo_name:#get the latest tag for image, if available 'latest' otherwise most recent.
        
            if args.repository_type == 'private':
                ilist_cmd = "ecr describe-images --repository-name " + repo_name 
            else:
                ilist_cmd = "ecr-public describe-images --repository-name " + repo_name
       
            i_json = run_aws_cmd(ilist_cmd)

            if len(i_json) > 0:

                for image in i_json['imageDetails']:
                    no_of_tags = len(image['imageTags'])
                    if 'latest' in image['imageTags']:
                        tag = ':' + 'latest'
                    else:
                        tag = ':' + image['imageTags'][no_of_tags-1]
                
                    logging.info("Using %s as a latest tag for the repository %s", tag,repo_name)            
                    args.image = get_repo_uri(repo_name,args.repository_type) + tag
                    args.assetid = args.image
                    args.assetid = args.assetid.replace('/','-')
                    args.assetid = args.assetid.replace(':','-')
                    args.assetname = args.image
                    logging.info("Discovering image %s", args.image)
                    assets = docker.get_inventory(args, image['imageDigest'])

                    if assets:
                        allassets.extend(assets)            
                for a in allassets:
                    a['tags'].append('ECR')
                return allassets
            else:
                logging.info("This repository has no images")
                return None
        else:#user has provided repositoryUri (image) with tag
            image_name = repo_name.split(':')[0]
            image_tag = repo_name.split(':')[1]
            digest = get_image_digest(image_name, image_tag, args.repository_type)
            args.image = repositoryUri
            args.assetid = args.image
            args.assetid = args.assetid.replace('/','-')
            args.assetid = args.assetid.replace(':','-')
            args.assetname = args.image
            logging.info("Discovering image %s", args.image)
            assets = docker.get_inventory(args, digest)

            if assets:
                for a in assets:
                    a['tags'].append('ECR')
                return assets

        
