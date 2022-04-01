import logging

from . import sbom_utils

def process_tagvalue(sbom_abs_path, args):
    all_products = { }
    products = set()
    main_product_spdxid = None
    direct_dependencies = set()
    lines = []
    with open(sbom_abs_path, 'r') as sbom_fd:
        package_name = None
        package_spdxid = None
        package_version = None
        lines = sbom_fd.readlines()
    for line in lines:
        line = line.strip()
        if line.startswith('PackageName:'):
            if package_name is not None:
                product = package_name if package_version is None else package_name + ' ' + package_version
                products.add(product)
                package_name = None
                package_spdxid = None
                package_version = None
            package_name = line.split(':')[1].strip()
        if line.startswith('SPDXID:'):
            package_spdxid = line.split(':')[1].strip()
        if line.startswith('PackageVersion:'):
            package_version = line.split(':')[1].strip()
        if line.startswith('ExternalRef:'):
            value = line.split(':')[1].strip()
            value = value.split()
            if value[0] == "PACKAGE-MANAGER":
                if value[1] == "maven-central":
                    package_technology = "maven"
                else:
                    package_technology = value[1]
                product_dict = { }
                product_dict['name'] = package_name
                product_dict['version'] = package_version
                product_dict['technology'] = package_technology
                product_dict['spdxid'] = package_spdxid
                all_products[package_spdxid] = product_dict
        if line.startswith('Relationship:'):
            value = line.split(':')[1].strip()
            tokens = value.split()
            if tokens[1] == "DESCRIBES":
                main_product_spdxid = tokens[2]
            elif main_product_spdxid is not None and tokens[1] in ["CONTAINS", "DEPENDS_ON", "DYNAMIC_LINK", "STATIC_LINK", "HAS_PREREQUISITE"] and tokens[0] == main_product_spdxid:
                direct_dependencies.add(tokens[2])
            elif main_product_spdxid is not None and tokens[1] in ["CONTAINED_BY", "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "PREREQUISITE_FOR"] and tokens[2] == main_product_spdxid:
                direct_dependencies.add(tokens[0])
    if package_name is not None:
        product = package_name if package_version is None else package_name + ' ' + package_version
        products.add(product)

    if len(all_products) > 0 or len(direct_dependencies) > 0:
        shallow_technology_products = { }
        for dd in direct_dependencies:
            product = all_products.get(dd)
            if product is not None:
                technology = product['technology']
                pn = product['name'] if product.get('version') is None else product['name'] + ' ' + product['version']
                tp_set = shallow_technology_products.get(technology)
                if tp_set is None:
                    tp_set = set()
                    shallow_technology_products[technology] = tp_set
                tp_set.add(pn)
        technology_products = { }
        for key in all_products:
            product = all_products[key]
            pn = product['name'] if product.get('version') is None else product['name'] + ' ' + product['version']
            technology = product['technology']
            tp_set = technology_products.get(technology)
            if tp_set is None:
                tp_set = set()
                technology_products[technology] = tp_set
            tp_set.add(pn)

    tags = set()
    tags.add('SBOM')

    # convert shallow_technology_products set to list
    sbom_utils.convert_technology_products(shallow_technology_products, tags)

    # convert technology_products set to list
    sbom_utils.convert_technology_products(technology_products, tags)

    asset_id = sbom_utils.get_asset_id(args)

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

