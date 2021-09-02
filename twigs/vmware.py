import sys
import logging
import json
import traceback
import ssl
import json
from pyVim.connect import SmartConnectNoSSL
from pyVmomi import vim

# Method that populates objects of type vimtype
def get_all_objs(content, vimtype):
    obj = {}
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for managed_object_ref in container.view:
        obj.update({managed_object_ref: managed_object_ref.name}),
    return obj

def discover(args):
    si = None
    try:
        si = SmartConnectNoSSL(host=args.host, user=args.user, pwd=args.password)
    except:
         logging.error("Failed to connect to vCenter host "+args.host)
         return None
    if si == None:
         logging.error("Failed to connect to vCenter host "+args.host)
         return None

    content = si.content
    if content == None:
         logging.error("No information from vCenter host "+args.host)

    vmware_assets = []

    vcenter_asset = {}
    vcenter_asset['id'] = args.host
    vcenter_asset['name'] = args.host
    vcenter_asset['type'] = 'VMware vCenter'
    vcenter_asset['owner'] = args.handle
    plist = []
    plist.append(content.about.fullName)
    plist.append(content.about.productLineId)
    plist.append(content.about.name)
    vcenter_asset['products'] = plist
    vcenter_asset['tags'] = []
    vmware_assets.append(vcenter_asset)

    children = content.rootFolder.childEntity
    for child in children:  
        datacenter = child
        clusters = datacenter.hostFolder.childEntity
        for cluster in clusters:  
            hosts = cluster.host  
            for host in hosts:  
                esx_asset = {}
                summary = host.summary.config
                hostname = summary.name
                esx_asset['id'] = hostname
                esx_asset['name'] = hostname
                esx_asset['type'] = 'VMware ESX'
                esx_asset['owner'] = args.handle
                plist = []
                plist.append(summary.product.fullName)
                plist.append(summary.product.productLineId)
                plist.append(summary.product.name)
                esx_asset['products'] = plist
                tags = []
                tags.append('DC: '+datacenter.name)
                tags.append('Cluster: '+cluster.name)
                tags.append('vCenter: '+args.host)
                esx_asset['tags'] = tags 
                vmware_assets.append(esx_asset)

    ajson = json.dumps(vmware_assets, indent=4)
    logging.debug(ajson)
    return vmware_assets

def get_inventory(args):
    return discover(args)
