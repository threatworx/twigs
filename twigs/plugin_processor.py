import os
import logging

from . import utils
from . import plugin_registry

supported_field_names = ["TYPE", "VULN", "PERCENTAGE", "AFFECTED_PRODUCT", "VULNERABLE_PRODUCT", "ANALYSIS", "RECOMMENDATION"]
field_name_mapping = {
    "IMPACT": {
        "TYPE": "type",
        "VULN": "id_str",
        "PERCENTAGE": "percentage",
        "AFFECTED_PRODUCT": "keyword",
        "VULNERABLE_PRODUCT": "product",
        "ANALYSIS": "analysis",
        "RECOMMENDATION": "recommendation"
    }
}
required_fields_by_type = {
    "IMPACT": ["VULN", "PERCENTAGE", "AFFECTED_PRODUCT", "VULNERABLE_PRODUCT", "ANALYSIS"]
}

def validate_record(rtype, finding_dict):
    global required_fields_by_type
    required_fields = required_fields_by_type.get(rtype)
    if required_fields is None:
        logging.error("Plugin returned malformed response - invalid record type [%s]", rtype)
        return False
    for rf in required_fields:
        if finding_dict.get(rf) is None:
            logging.error("Plugin returned malformed response - missing required field [%s]", rf)
            return False
    return True

def transform_record(rtype, finding_dict):
    global field_name_mapping
    ret_dict = { }
    for key in finding_dict.keys():
        ret_dict[field_name_mapping[rtype][key]] = finding_dict[key]
    return ret_dict

def process_record(rtype, finding_dict, asset_dict):
    if rtype != '':
        if validate_record(rtype, finding_dict):
            finding_dict = transform_record(rtype, finding_dict)
            if rtype == "IMPACT":
                if asset_dict.get('impacts') is None:
                    asset_dict['impacts'] = []
                asset_dict['impacts'].append(finding_dict)
            else:
                logging.error("Plugin returned unsupported action!")

def process_plugin_output(plugin_output, asset_dict):
    global supported_field_names

    if plugin_output is None:
        return

    lines = plugin_output.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return
    finding_dict = { }
    rtype = ''
    for cl in lines:
        if len(cl) == 0:
            process_record(rtype, finding_dict, asset_dict)
            rtype = ''
            finding_dict = { }
            continue
        if ':' not in cl:
            logging.error("Plugin returned malformed response - missing separator")
            break
        tokens = cl.split(':')
        if len(tokens) == 1:
            # there is no value specified, so skip the field
            continue
        if len(tokens) > 2:
            logging.error("Plugin returned malformed response - incorrect number of fields")
            break
        prefix = tokens[0]
        value = tokens[1]
        if prefix not in supported_field_names:
            logging.error("Plugin returned malformed response - unknown field type")
            break
        if prefix == "TYPE":
            # encountered new record, so first validate earlier record
            process_record(rtype, finding_dict, asset_dict)
            rtype = value
            finding_dict = { }
        else:
            finding_dict[prefix] = value
    if rtype != '' and len(finding_dict) > 0:
        process_record(rtype, finding_dict, asset_dict)

def execute_plugin(args, asset_dict, host, plugin_dict, root_folder):
    plugin_dir = plugin_dict['plugin_dir']
    plugin_abs_path = plugin_dir + os.sep + plugin_dict.get('file')
    logging.info("Running plugin [%s]", plugin_dict['name'])
    script_output, exit_code = utils.run_script_on_host(args, host, plugin_abs_path, [root_folder])

    if exit_code == 0:
        logging.info("Processing output from plugin [%s]", plugin_dict['name'])
        process_plugin_output(script_output, asset_dict)
    elif exit_code == 1:
        logging.error("Plugin [%s] failed to run successfully", plugin_dict['name'])

def run_plugin(args, asset_dict, host, these_checks, plugin_dir, root_folder):
    pr = plugin_registry.get_plugin_registry()
    for this_check in these_checks:
        plugin = pr.get(this_check.lower())
        if plugin is None:
            logging.error("No plugin found for [%s]", this_check)
            continue
        else:
            if plugin.get('enabled'):
                plugin['plugin_dir'] = plugin_dir
                execute_plugin(args, asset_dict, host, plugin, root_folder)
            else:
                logging.error("Specified plugin [%s] is not enabled", this_plugin)
                continue

def run_plugins(args, asset_dict, host, plugin_dir, root_folder):
    logging.info("Running all enabled plugins")
    pr = plugin_registry.get_plugin_registry()
    plugins = pr.keys()
    for p in plugins:
        if pr[p]['enabled'] == False:
            continue
        pr[p]['plugin_dir'] = plugin_dir
        execute_plugin(args, asset_dict, host, pr[p], root_folder)
    logging.info("Done running all enabled plugins")

def process_plugins(asset_dict, host, args, root_folder):
    if args.mode not in ['host', 'docker', 'gcr', 'acr', 'ecr', 'k8s']:
        return

    plugin_dir = plugin_registry.get_plugin_dir()
    if host['remote'] == True:
        # copy plugins folder on remote host
        client = utils.get_ssh_client(host)
        cmd = 'mktemp -d'
        remote_plugin_dir, exit_code = utils.run_remote_ssh_command_helper(client, cmd, args)
        remote_plugin_dir = remote_plugin_dir.strip()
        utils.scp_put_file(client, plugin_dir, remote_plugin_dir)
        cmd = 'chmod +x ' + remote_plugin_dir + '/*'
        utils.run_remote_ssh_command_helper(client, cmd, args)
        plugin_dir = remote_plugin_dir + os.sep + 'plugins'
        client.close()
        
    if args.check_vuln is not None:
        run_plugin(args, asset_dict, host, args.check_vuln, plugin_dir, root_folder)
    elif args.check_all_vulns:
        run_plugins(args, asset_dict, host, plugin_dir, root_folder)

    if host['remote'] == True:
        # remove plugin dir from remote host
        client = utils.get_ssh_client(host)
        cmd = 'rm -rf ' + remote_plugin_dir
        utils.run_remote_ssh_command_helper(client, cmd, args)
        client.close()

