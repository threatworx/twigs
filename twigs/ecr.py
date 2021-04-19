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

    #except ClientError as e:
     #   if e.response['Error']['Code'] == 'RepositoryNotFoundException':
      #      logging.error("Please make sure that repository exists and you are pointing to correct region",cmd,cmd_output)
       #     ret_json = { } 
    except subprocess.CalledProcessError:
        logging.error("Error running aws  command [%s]", cmd)
        ret_json = { }
    except ValueError:
        logging.error("Error parsing JSON output for aws command [%s]: %s", cmd, cmd_output)
        ret_json = { }
    return ret_json

def get_image_name_with_tag(tag,repository,repositoryType):

    if repositoryType == 'private':
        ilist_cmd = "ecr describe-images --repository-name " + repository
    else:
        ilist_cmd = "ecr-public describe-images --repository-name " + repository

    i_json = run_aws_cmd(ilist_cmd)

    if len(i_json['imageDetails']) > 0:
        i_uri = get_repo_uri(repository,repositoryType)

        for image in i_json['imageDetails']:
            if tag is None:
                no_of_tags = len(image['imageTags'])
                tag = ':' + image['imageTags'][no_of_tags-1]
                logging.info("Using %s as a latest tag for the repository %s", image['imageTags'][no_of_tags-1], repository)
            
                ret_image = i_uri + tag
            else:
                ret_image = i_uri + ':' + tag

        return ret_image
    
    else:
        return None



def get_inventory(args):
    set_encoding(args.encoding)
    allassets = []


    import pdb; pdb.set_trace()
    if args.repository is None and args.registryId is None:
        logging.error("Please specify repository name or registryId to be discovered")
        return None
    if not args.registryId:
        
        logging.info("Starting discovery of repository in ECR")

        if args.repositoryType == 'private':
            ilist_cmd = "ecr describe-images --repository-name " + args.repository
        else:
            ilist_cmd = "ecr-public describe-images --repository-name " + args.repository
       
        i_json = run_aws_cmd(ilist_cmd)

        if len(i_json) > 0:
            args.image = get_image_name_with_tag(args.tag,args.repository,args.repositoryType)

            if args.image is None:
                logging.info("This repository has no images")
                return None

            args.assetid = args.image


            #docker.py is already taking care of this, do we still need this code?
            args.assetid = args.assetid.replace('/','-')
            args.assetid = args.assetid.replace(':','-')
            args.assetname = args.image

            logging.info("Discovering image "+args.image)
            assets = docker.get_inventory(args)

            if assets != None:
                for a in assets:
                    a['tags'].append('ECR')
                return assets

        else:
            logging.error("Repository does not exist, please check the name and run the command again")
            return None
    else:

        final_assets= None 
        import pdb; pdb.set_trace()
        logging.info("Starting discovery for all repositories under AWS account")

        if args.repositoryType == 'private':
            ilist_cmd = "ecr describe-repositories"
        else:
            ilist_cmd = "ecr-public describe-repositories"

        i_json = run_aws_cmd(ilist_cmd)


        if len(i_json) > 0:
            logging.info("Found %d repositories in %s", len(i_json), args.registryId)

        if i_json['repositories'][0]['registryId'] == args.registryId: 
            for repos in i_json['repositories']:
                         
                args.image = get_image_name_with_tag(args.tag,repos['repositoryName'],args.repositoryType)

                
                if args.image is not None:
                    args.assetid = args.image
                
                    #docker.py is already taking care of this, do we still need this code?
                    args.assetid = args.assetid.replace('/','-')
                    args.assetid = args.assetid.replace(':','-')
                    args.assetname = args.image
                
                    logging.info("Discovering image "+args.image)
                    assets = docker.get_inventory(args)

                
                    if assets:
                        allassets = allassets + assets

            for a in allassets:
                a['tags'].append('ECR')
            return allassets
        
        else:
            loggin.info("Run AWS Configure to point it to the correct region and registryId (AccountID) ");
            return None
