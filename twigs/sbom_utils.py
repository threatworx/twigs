import os

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

def convert_technology_products(technology_products, tags):
    for key in technology_products:
        tp_set = technology_products[key]
        tp_list = list(tp_set)
        technology_products[key] = tp_list
        tags.add(key)

