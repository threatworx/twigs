import os
import json
import logging

SUPPORTED_SBOM_STANDARDS = ["cyclonedx"]
SUPPORTED_SBOM_FORMATS_FOR_STANDARD = {
        "cyclonedx": ["json"]
}

def get_asset_id(args):
    asset_id = None
    if args.assetid == None or args.assetid.strip() == "":
        tokens = [args.handle.split('@')[0]]
        tokens.append(os.path.basename(os.path.normpath(args.input)).replace('.','-'))
        asset_id = "-".join(tokens)
    else:
        asset_id = args.assetid
    asset_id = asset_id.replace(' ','-')
    asset_id = asset_id.replace('/','-')
    asset_id = asset_id.replace(':','-')
    return asset_id

def get_technology(component):
    technology = None
    purl = component.get('purl')
    if purl is None:
        return technology
    tokens = purl.split('/')
    if len(tokens) > 1:
        if tokens[0].startswith("pkg:"):
            technology = tokens[0][4:]
    return technology

def process_cyclonedx_sbom_json_components(products, shallow_technology_products, technology_products, components, level):
    for component in components:
        ctype = component['type']
        if ctype not in ['library','framework']:
            continue
        cname = component['name']
        cversion = component['version']
        cgroup = component.get('group')
        cscope = component.get('scope')
        if cscope == "excluded":
            continue
        ctech = get_technology(component)
        product = cname + " " + cversion
        if cgroup is not None and len(cgroup) > 0:
            if cgroup[0] == "@":
                product = cgroup + "/" + product
            else:
                product = cgroup + ":" + product
        products.add(product)

        if ctech is not None:
            if level == 1:
                # Add to shallow_technology_products
                tp_set = shallow_technology_products.get(ctech)
                if tp_set is None:
                    tp_set = set()
                    shallow_technology_products[ctech] = tp_set
                tp_set.add(product)

            # Add to technology_products
            tp_set = technology_products.get(ctech)
            if tp_set is None:
                tp_set = set()
                technology_products[ctech] = tp_set
            tp_set.add(product)

        # process sub-components
        sub_components = component.get('components')
        if sub_components is not None and len(sub_components) > 0:
            process_cyclonedx_sbom_json_components(products, shallow_technology_products, technology_products, sub_components, level + 1)

        # add logic to consume License information

def process_cyclonedx_sbom_json(sbom_abs_path, args):
    sbom_json = None
    with open(sbom_abs_path, 'rb') as sbom_fd:
        try:
            sbom_json = json.load(sbom_fd)
        except ValueError:
            logging.error("JSON parsing failed for [%s]", sbom_abs_path)
            return  []

    technology_products = { }
    shallow_technology_products = { }
    products = set()
    components = sbom_json.get('components')
    if components is None:
        logging.warning("No components found in SBOM")
        return []

    process_cyclonedx_sbom_json_components(products, shallow_technology_products, technology_products, components, 1)

    tags  = set()
    tags.add('SBOM')
    # convert shallow_technology_products set to list
    for key in shallow_technology_products:
        tp_set = shallow_technology_products[key]
        tp_list = list(tp_set)
        shallow_technology_products[key] = tp_list
        tags.add(key)

    # convert technology_products set to list
    for key in technology_products:
        tp_set = technology_products[key]
        tp_list = list(tp_set)
        technology_products[key] = tp_list
        tags.add(key)

    asset_id = get_asset_id(args)

    asset_data = { }

    asset_data['id'] = asset_id
    if args.assetname is None or len(args.assetname.strip()) == 0:
        asset_data['name'] = asset_data['id']
    else:
        asset_data['name'] = args.assetname
    asset_data['type'] = 'Source Repository'
    asset_data['owner'] = args.handle
    asset_data['products'] = list(products) # convert products set to list
    if len(technology_products) > 0:
        asset_data['compliance_metadata'] = {"source_metadata": {"technology_products": technology_products, "shallow_technology_products": shallow_technology_products}}
    asset_data['tags'] = list(tags)

    return [ asset_data ]

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

    temp = os.path.basename(sbom_abs_path)

    if sbom_standard == "cyclonedx":
        if sbom_format == "json":
            return process_cyclonedx_sbom_json(sbom_abs_path, args)

    return assets
