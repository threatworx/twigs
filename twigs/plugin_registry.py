import os

# Please use lower case key names i.e. Vulnerability ID's
plugin_registry = {
        "cve-2021-44228": {"name": "Check for CVE-2021-44228 (log4j)", "file": "cve-2021-44228.sh", "enabled": True},
        "cve-2021-45046": {"name": "Check for CVE-2021-45046 (log4j)", "file": "cve-2021-45046.sh", "enabled": True},
        "cve-2021-45105": {"name": "Check for CVE-2021-45105 (log4j)", "file": "cve-2021-45105.sh", "enabled": True},
        "cve-2021-44832": {"name": "Check for CVE-2021-44832 (log4j)", "file": "cve-2021-44832.sh", "enabled": True},
        "cve-2022-22965": {"name": "Check for CVE-2022-22965 (Spring4Shell)", "file": "cve-2022-22965.sh", "enabled": True},
}

def get_plugin_dir():
    return os.path.dirname(os.path.abspath(__file__)) + os.sep + "plugins"

def get_plugin_registry():
    return plugin_registry
