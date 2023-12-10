import os
import logging
import json

from . import utils

SUPPORTED_SBOM_FORMATS_FOR_STANDARD = {
        "cyclonedx": ["json"],
        "spdx": ["tagvalue", "json"],
        "threatworx": ["json", "csv"] # keep this one last
}
SUPPORTED_SBOM_STANDARDS = list(SUPPORTED_SBOM_FORMATS_FOR_STANDARD.keys())

def upload_sbom(args):
    sbom_standard = args.standard
    sbom_format = args.format
    sbom_abs_path = os.path.abspath(args.input)

    if sbom_standard not in SUPPORTED_SBOM_STANDARDS:
        logging.error("Unsupported SBOM standard [%s]", sbom_standard)
        return False

    supported_sbom_formats = SUPPORTED_SBOM_FORMATS_FOR_STANDARD[sbom_standard]
    if sbom_format not in supported_sbom_formats:
        logging.error("Unsupported format [%s] for SBOM standard [%s]", sbom_format, sbom_standard)
        return False

    if os.path.isfile(sbom_abs_path) == False:
        logging.error("Unable to access SBOM file [%s]", sbom_abs_path)
        return False

    json_data = { }
    json_data['sbom_standard'] = sbom_standard
    json_data['sbom_format'] = sbom_format
    if args.assetid:
        json_data['asset_id'] = args.assetid
    if args.assetname:
        json_data['asset_name'] = args.assetname
    if args.org:
        json_data['org'] = args.org
    if args.tag:
        json_data['tags'] = args.tag
    if args.comment:
        json_data['comment'] = args.comment

    sbom_upload_url = "https://" + args.instance + "/api/v2/assets/sbom/"
    auth_data = "?handle=" + args.handle + "&token=" + args.token + "&format=json"

    files = [
        ('sbom_artifact', ('sbom_artifact', open(sbom_abs_path, 'rb') )),
        ('data', ('data', json.dumps(json_data), 'application/json')),
    ]
    logging.info("Uploading SBOM artifact [%s]", sbom_abs_path)
    resp = utils.requests_post_files(sbom_upload_url + auth_data, files)
    if resp is not None and resp.status_code == 200:
        logging.info("Successfully uploaded SBOM artifact")
        return True
    else:
        logging.error("Uploading SBOM artifact failed")
        logging.error(resp.text)
        return False

