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

def discover(host, user, password):
    si = SmartConnectNoSSL(host=host, user=user, pwd=password)
    content = si.content

    #all_esxs = get_all_objs(content, [vim.HostSystem])

    #print('All ESX info')
    #for esx in all_esxs:
    #    summary = esx.summary.config
    #    print(summary.name)
    #    print(summary.product.instanceUuid)
    #    print(summary.product.productLineId)
    #    print(summary.product.version)
    #    print(summary.product.osType)
    #    print(summary.product.vendor)
    #    print('')

    data = {}
    data['id'] = content.about.instanceUuid
    data['product_id'] = content.about.productLineId
    data['vendor'] = content.about.vendor
    data['product_name'] = content.about.name
    data['product_full_name'] = content.about.fullName
    data['version'] = content.about.version
    data['os_type'] = content.about.osType

    data['licenses'] = {}
    for l in content.licenseManager.licenses:
        data['licenses']['license_name'] = l.name

    children = content.rootFolder.childEntity
    for child in children:  # Iterate though DataCenters
        datacenter = child
        data[datacenter.name] = {}  # Add data Centers to data dict
        clusters = datacenter.hostFolder.childEntity
        for cluster in clusters:  # Iterate through the clusters in the DC
            # Add Clusters to data dict
            data[datacenter.name][cluster.name] = {}
            hosts = cluster.host  # Variable to make pep8 compliance
            for host in hosts:  # Iterate through Hosts in the Cluster
                summary = host.summary.config
                hostname = summary.name
                # Add VMs to data dict by config name
                if hostname not in data[datacenter.name][cluster.name]:
                    data[datacenter.name][cluster.name][hostname] = {}
                data[datacenter.name][cluster.name][hostname]['id'] = summary.product.instanceUuid 
                data[datacenter.name][cluster.name][hostname]['product_id'] = summary.product.productLineId
                data[datacenter.name][cluster.name][hostname]['vendor'] = summary.product.vendor
                data[datacenter.name][cluster.name][hostname]['product_name'] = summary.product.name
                data[datacenter.name][cluster.name][hostname]['product_full_name'] = summary.product.fullName
                data[datacenter.name][cluster.name][hostname]['version'] = summary.product.vendor
                data[datacenter.name][cluster.name][hostname]['os_type'] = summary.product.osType
                #vms = host.vm
                #for vm in vms:  # Iterate through each VM on the host
                #    vmname = vm.summary.config.name
                #    data[datacenter.name][cluster.name][hostname][vmname] = {}
                #    summary = vmsummary(vm.summary, vm.guest)
                #    vm2dict(datacenter.name, cluster.name, hostname, vm, summary)

    print json.dumps(data, indent=4)

if __name__ == "__main__":
    discover(sys.argv[1], sys.argv[2], sys.argv[3])
