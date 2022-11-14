import os

# Please use lower case key names based on products
plugin_registry = {
        "log4j_vulns": {"name": "Check for Log4j vulns", "file": "log4j_vulns.sh", "enabled": True},
        "spring4shell_vulns": {"name": "Check for Spring4Shell vulns", "file": "spring4shell_vulns.sh", "enabled": True},
        "poi_vulns": {"name": "Check for Apache POI vulns", "file": "poi_vulns.sh", "enabled": True},
        "tomcat_vulns": {"name": "Check for Apache Tomcat vulns", "file": "tomcat_vulns.sh", "enabled": True},
        "apache_vulns": {"name": "Check for Apache Server vulns", "file": "apache_vulns.sh", "enabled": True},
        "spring_framework_vulns": {"name": "Check for Spring Framework vulns", "file": "spring_framework_vulns.sh", "enabled": True},
}

def get_plugin_dir():
    return os.path.dirname(os.path.abspath(__file__)) + os.sep + "plugins"

def get_plugin_registry():
    return plugin_registry
