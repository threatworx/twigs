import sys
import os
import subprocess
import logging
import json

from . import utils
from . import oci_utils
from . import docker

def get_inventory(args):
    allassets = [] 
    oci_utils.set_encoding(args.encoding)

    tenancy_namespace = oci_utils.get_tenancy_namespace(args)
    compartment_name_dict = oci_utils.get_compartment_name_dict(args)
    compartments = oci_utils.get_compartments(args)
    region_with_prefix = ".%s." % args.region
    for compartment in compartments:
        logging.info("Processing compartment [%s]", compartment_name_dict[compartment])
        if args.repository is not None and len(args.repository) > 0:
            oci_cmd = "artifacts container image list --compartment-id '%s' --repository-name '%s' --all" % (compartment, args.repository)
        else:
            oci_cmd = "artifacts container image list --compartment-id '%s' --all" % compartment
        images_json = oci_utils.run_oci_cmd(oci_cmd, args)
        images_json = images_json['data']['items']
        logging.info("Found [%s] container image(s)" % len(images_json))
        for image in images_json:
            if region_with_prefix not in image['id']:
                # image belongs to different region so skip it
                continue
            image_url = "ocir.%s.oci.oraclecloud.com/%s/%s:%s" % (args.region, tenancy_namespace, image['repository-name'], image['version'])
            args.image = image_url
            args.assetid = image_url
            args.assetid = args.assetid.replace('/','-')
            args.assetid = args.assetid.replace(':','-')
            args.assetname = image_url
            logging.info("Discovering image "+args.image)
            assets = docker.get_inventory(args, image['digest'])
            if assets:
                allassets = allassets + assets
    for a in allassets:
        a['tags'].append('OCR')
    return allassets

