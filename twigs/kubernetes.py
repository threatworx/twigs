import sys
import os
import subprocess
import logging
import json
import yaml
import uuid
import tempfile

from . import utils as lib_utils
from . import docker

def get_helm_command_path():
    HELM_CMD = os.environ.get('HELM_PATH')
    if HELM_CMD is None:
        HELM_CMD = "/usr/local/bin/helm"
    else:
        if os.path.isfile(HELM_CMD) == False:
            logging.error("Helm command not found at specified HELM_PATH [%s]", HELM_CMD)
            sys.exit(1)
        elif os.access(HELM_CMD, os.X_OK) == False:
            logging.error("Helm command file [%s] is not an executable", HELM_CMD)
            sys.exit(1)
    return HELM_CMD

def get_deployment_name(yaml_json):
    if yaml_json.get('metadata') is None:
        return None
    namespace = yaml_json['metadata'].get('namespace')
    deployment_name = yaml_json['metadata'].get('name')
    return namespace, deployment_name

def get_list_of_containers(yaml_json):
    kind = yaml_json.get('kind')
    init_container_list = []
    container_list = []
    if yaml_json.get('spec') is None:
        return container_list

    if kind == "Pod":
        if yaml_json['spec'].get('containers') is None:
            return init_container_list, container_list
        yaml_containers = yaml_json['spec']['containers']
        yaml_init_containers = yaml_json['spec'].get('initContainers')
    elif kind == "CronJob":
        if yaml_json['spec'].get('jobTemplate') is None:
            return init_container_list, container_list
        if yaml_json['spec']['jobTemplate'].get('spec') is None:
            return init_container_list, container_list
        if yaml_json['spec']['jobTemplate']['spec'].get('template') is None:
            return init_container_list, container_list
        if yaml_json['spec']['jobTemplate']['spec']['template'].get('spec') is None:
            return init_container_list, container_list
        if yaml_json['spec']['jobTemplate']['spec']['template']['spec'].get('containers') is None:
            return init_container_list, container_list
        yaml_containers = yaml_json['spec']['jobTemplate']['spec']['template']['spec']['containers']
        yaml_init_containers = yaml_json['spec']['jobTemplate']['spec']['template']['spec'].get('initContainers')
    else:
        if yaml_json['spec'].get('template') is None:
            return init_container_list, container_list
        if yaml_json['spec']['template'].get('spec') is None:
            return init_container_list, container_list
        if yaml_json['spec']['template']['spec'].get('containers') is None:
            return init_container_list, container_list
        yaml_containers = yaml_json['spec']['template']['spec']['containers']
        yaml_init_containers = yaml_json['spec']['template']['spec'].get('initContainers')

    if yaml_init_containers is not None:
        for yaml_init_container in yaml_init_containers:
            yaml_init_container_image = yaml_init_container.get('image')
            if yaml_init_container_image is not None:
                init_container_list.append(yaml_init_container_image)

    for yaml_container in yaml_containers:
        yaml_container_image = yaml_container.get('image')
        if yaml_container_image is not None:
            container_list.append(yaml_container_image)

    return init_container_list, container_list

def discover_containers(args, container_list, asset_name, namespace, deployment_name, kind, extra_tags = []):
    allassets = []
    if len(container_list) == 0:
        return allassets;
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
                a['tags'].append('KubernetesCluster')
                if namespace is not None:
                    a['tags'].append(namespace)
                a['tags'].append(deployment_name)
                a['tags'].append(kind)
                for extra_tag in extra_tags:
                    a['tags'].append(extra_tag)
            allassets = allassets + assets
    return allassets

def discover_assets_from_yaml(args, k8s_yaml, asset_name_override=None):
    allassets = [] 
    with open(k8s_yaml, 'r') as yaml_fd:
        yaml_jsons = yaml.load_all(yaml_fd, Loader=yaml.FullLoader)
        if yaml_jsons is None:
            logging.error("Unable to load YAML")
            return allassets
        for yaml_json in yaml_jsons:
            if yaml_json is None:
                continue
            kind = yaml_json.get('kind')
            if kind is None or kind == "" or kind not in ["Deployment", "ReplicaSet", "Pod", "PodTemplate", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicationController"]:
                # only process those 'kind' with container image
                continue
            namespace, deployment_name = get_deployment_name(yaml_json)
            extra_tags = []
            if asset_name_override is not None:
                asset_name = asset_name_override
                extra_tags = ["HelmChart"]
            else:
                asset_name = deployment_name if namespace is None else namespace + '-' + deployment_name
            logging.info("Processing Kubernetes workload resource: %s", kind)
            init_container_list, container_list = get_list_of_containers(yaml_json)
            if len(init_container_list) == 0 and len(container_list) == 0:
                logging.warning("No containers referenced in %s YAML", kind)
                continue
            allassets = allassets + discover_containers(args, container_list, asset_name, namespace, deployment_name, kind, extra_tags)
            extra_tags.append("InitContainer")
            allassets = allassets + discover_containers(args, init_container_list, asset_name, namespace, deployment_name, kind, extra_tags)

    return allassets

def run_helm_command(cmdarr, encoding):
    try:
        logging.debug("Running command %s", cmdarr)
        out = subprocess.check_output(cmdarr, shell=True)
        return out.decode(encoding)
    except subprocess.CalledProcessError as e:
        logging.error("Error running Helm command")
        logging.debug("[helm] command: %s", cmdarr[0])
        logging.debug("Output of [helm] command: %s", e.output)
        return None

def discover_assets_from_helm_chart(args, helm_chart):
    allassets = []
    hc_name = None
    hc_version = None
    hc_type = None
    temp_template = uuid.uuid4().hex
    temp_template = tempfile.gettempdir() + os.path.sep + temp_template + ".yaml"
    if os.path.isfile(temp_template):
        os.remove(temp_template)
    HELM_CMD = get_helm_command_path()
    cmdarr = [ HELM_CMD + " show chart " + helm_chart + " > " + temp_template ]
    cmd_output = run_helm_command(cmdarr, args.encoding)
    if cmd_output is None:
        logging.error("Unable to get Chart.yaml")
        return allassets
    with open(temp_template, 'r') as chart_yaml_fd:
        yaml_json = yaml.load(chart_yaml_fd, Loader=yaml.FullLoader)
        if yaml_json is None:
            logging.error("Unable to load Chart.yaml")
            return allassets
        hc_name = yaml_json['name']
        hc_version = yaml_json['version']
        hc_type = yaml_json.get('type')
        if hc_type is None:
            hc_type = 'applicaton'
    asset_name_override = hc_name + ':' + hc_version
    if hc_type == 'library':
        logging.warn("Helm Chart [%s] is of library type...Skipping it", asset_name_override)
        return allassets
    logging.info("Processing Helm Chart [%s]", asset_name_override)
    if os.path.isfile(temp_template):
        os.remove(temp_template)
    cmdarr = [ HELM_CMD + " template " + helm_chart + " > " + temp_template ]
    cmd_output = run_helm_command(cmdarr, args.encoding)
    if cmd_output is None:
        logging.error("Unable to get Helm chart template YAML")
        os.remove(temp_template)
        return allassets
    allassets = discover_assets_from_yaml(args, temp_template, asset_name_override)
    if os.path.isfile(temp_template):
        os.remove(temp_template)

    logging.info("Done processing Helm Chart [%s]", asset_name_override)
    return allassets

def get_inventory(args):
    if args.deployment_yaml:
        return discover_assets_from_yaml(args, args.deployment_yaml)
    elif args.helm_chart:
        return discover_assets_from_helm_chart(args, args.helm_chart)
    return []
