import os
import sys
import logging
import json
import traceback
import ssl
import json
from pyVim.connect import SmartConnectNoSSL
from pyVmomi import vim
from . import utils

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
        pwd = os.environ.get('VCENTER_PASSWD')
        if pwd is None:
            if args.password is None:
                logging.error("vCenter password not found")
                return None
            pwd = args.password
        si = SmartConnectNoSSL(host=args.host, user=args.user, pwd=pwd)
    except:
         logging.error("Failed to connect to vCenter host "+args.host)
         utils.tw_exit(1)
    if si == None:
         logging.error("Failed to connect to vCenter host "+args.host)
         utils.tw_exit(1)

    content = si.content
    if content == None:
         logging.error("No information from vCenter host "+args.host)
         utils.tw_exit(1)

    esx_root_found = content.about.fullName.startswith('VMware ESX')
    logging.debug("Found ESX product in root node: %s", esx_root_found)

    vmware_assets = []

    vcenter_asset = {}
    vcenter_asset['id'] = args.host
    vcenter_asset['name'] = args.host
    vcenter_asset['type'] = 'VMware ESXi' if esx_root_found else 'VMware vCenter'
    vcenter_asset['owner'] = args.handle
    plist = []
    plist.append(content.about.fullName)
    logging.debug("content.about.fullName: %s", content.about.fullName)
    logging.debug("Type of root: %s", type(content))
    #plist.append(content.about.productLineId)
    #plist.append(content.about.name)
    vcenter_asset['products'] = plist
    vcenter_asset['tags'] = []
    vmware_assets.append(vcenter_asset)

    if esx_root_found:
        # if we encounter ESX product in root node, then there is no vCenter deployment
        # Instead there is a ESX Web Client, so skip remaining content under root
        ajson = json.dumps(vmware_assets, indent=4)
        logging.debug(ajson)
        return vmware_assets

    children = content.rootFolder.childEntity
    for child in children:  
        datacenter = child
        clusters = datacenter.hostFolder.childEntity
        logging.debug("Number of clusters: %s", str(len(clusters)))
        for cluster in clusters:  
            if isinstance(cluster, vim.Folder):
                # ignore folder objects
                continue
            hosts = cluster.host  
            logging.debug("Number of hosts in cluster: %s", str(len(hosts)))
            for host in hosts:  
                esx_asset = {}
                summary = host.summary.config
                hostname = summary.name
                logging.debug("summary.name: %s", summary.name)
                esx_asset['id'] = hostname
                esx_asset['name'] = hostname
                esx_asset['type'] = 'VMware ESXi'
                esx_asset['owner'] = args.handle
                plist = []
                plist.append(summary.product.fullName)
                logging.debug("summary.product.fullName: %s", summary.product.fullName)
                #plist.append(summary.product.productLineId)
                #plist.append(summary.product.name)
                esx_asset['products'] = plist
                tags = []
                tags.append('vCenter DC: '+datacenter.name)
                tags.append('vCenter Cluster: '+cluster.name)
                tags.append('vCenter: '+args.host)
                esx_asset['tags'] = tags 
                vmware_assets.append(esx_asset)

    ajson = json.dumps(vmware_assets, indent=4)
    logging.debug(ajson)
    return vmware_assets

def get_inventory(args):
    return discover(args)
