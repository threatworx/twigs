import os
import logging

from . import sbom_cyclonedx
from . import sbom_spdx
from . import sbom_tw

SUPPORTED_SBOM_FORMATS_FOR_STANDARD = {
        "cyclonedx": ["json"],
        "spdx": ["tagvalue"],
        "threatworx": ["json", "csv"] # keep this one last
}
SUPPORTED_SBOM_STANDARDS = list(SUPPORTED_SBOM_FORMATS_FOR_STANDARD.keys())

def get_inventory(args):
    assets = []
    sbom_standard = args.standard
    sbom_format = args.format
    sbom_abs_path = os.path.abspath(args.input)

    if sbom_standard not in SUPPORTED_SBOM_STANDARDS:
        logging.error("Unsupported SBOM standard [%s]", sbom_standard)
        return assets

    supported_sbom_formats = SUPPORTED_SBOM_FORMATS_FOR_STANDARD[sbom_standard]
    if sbom_format not in supported_sbom_formats:
        logging.error("Unsupported format [%s] for SBOM standard [%s]", sbom_format, sbom_standard)
        return assets
    
    if os.path.isfile(sbom_abs_path) == False:
        logging.error("Unable to access SBOM file [%s]", sbom_abs_path)
        return assets

    logging.info("Processing SBOM artifact [%s]", sbom_abs_path)
    if sbom_standard == "cyclonedx":
        if sbom_format == "json":
            assets = sbom_cyclonedx.process_json(sbom_abs_path, args)
    elif sbom_standard == "spdx":
        if sbom_format == "tagvalue":
            assets = sbom_spdx.process_tagvalue(sbom_abs_path, args)
    elif sbom_standard == "threatworx":
        if sbom_format == "json":
            assets = sbom_tw.process_json(sbom_abs_path, args)
        elif sbom_format == "csv":
            assets = sbom_tw.process_csv(sbom_abs_path, args)
    logging.info("Done processing SBOM artifact")

    return assets
