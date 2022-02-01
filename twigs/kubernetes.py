import sys
import os
import subprocess
import logging
import json
import yaml

from . import utils
from .gcp_cis_tool import gcp_cis_utils
from . import docker

def get_deployment_name(yaml_json):
    if yaml_json.get('metadata') is None:
        return None
    namespace = yaml_json['metadata'].get('namespace')
    deployment_name = yaml_json['metadata'].get('name')
    return namespace, deployment_name

def get_list_of_containers(yaml_json):
    container_list = []
    if yaml_json.get('spec') is None:
        return container_list
    if yaml_json['spec'].get('template') is None:
        return container_list
    if yaml_json['spec']['template'].get('spec') is None:
        return container_list
    if yaml_json['spec']['template']['spec'].get('containers') is None:
        return container_list
    yaml_containers = yaml_json['spec']['template']['spec']['containers']
    for yaml_container in yaml_containers:
        yaml_container_image = yaml_container.get('image')
        if yaml_container_image is not None:
            container_list.append(yaml_container_image)
    return container_list

def get_inventory(args):
    allassets = [] 
    with open(args.deployment_yaml, 'r') as yaml_fd:
        yaml_jsons = yaml.load_all(yaml_fd)
        for yaml_json in yaml_jsons:
            namespace, deployment_name = get_deployment_name(yaml_json)
            asset_name = deployment_name if namespace is None else namespace + '-' + deployment_name
            logging.info("Processing Kubernetes deployment: %s", deployment_name)
            container_list = get_list_of_containers(yaml_json)
            if len(container_list) == 0:
                logging.warning("No containers referenced in deployment YAML")
                continue
            for container in container_list:
                logging.info("Discovering Kubernetes container: %s", container)
                digest = container.split('@')[1] if '@' in container else None
                args.image = container
                args.assetid = asset_name + '-' + container
                args.assetid = args.assetid.replace('/','-')
                args.assetid = args.assetid.replace(':','-')
                args.assetname = asset_name + '-' + container
                logging.info("Discovering image "+args.image)
                assets = docker.get_inventory(args, digest)
                if assets:
                    for a in assets:
                        if a.get('tags') is None:
                            a['tags'] = []
                        a['tags'].append('Kubernetes')
                        if namespace is not None:
                            a['tags'].append(namespace)
                        a['tags'].append(deployment_name)
                    allassets = allassets + assets

    return allassets
