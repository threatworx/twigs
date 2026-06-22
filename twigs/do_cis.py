import logging

from . import utils
from . import digitalocean

# Common database ports checked for public exposure (Section 3.4)
_DB_PORTS = {3306, 5432, 6379, 27017, 1433, 5439, 9042}
_DB_PORT_NAMES = {
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
    27017: 'MongoDB', 1433: 'MSSQL', 5439: 'Redshift', 9042: 'Cassandra',
}
_OPEN_ADDRS = {'0.0.0.0/0', '::/0'}


def _make_issue(asset_id, check_id, title, details, rating, object_id=''):
    return {
        'twc_id': 'cis-do-bench-check-' + check_id,
        'asset_id': asset_id,
        'twc_title': check_id + ' ' + title,
        'details': details,
        'type': 'DigitalOcean CIS',
        'rating': rating,
        'object_id': object_id,
        'object_meta': '',
    }


def _is_open_source(sources):
    return bool(set(sources.get('addresses', [])) & _OPEN_ADDRS)


def _port_matches(ports_str, target_port):
    """Return True if target_port falls within the DO firewall ports expression."""
    if not ports_str or ports_str == '0':
        return True  # empty or "0" means all ports in DO's API
    if '-' in ports_str:
        parts = ports_str.split('-', 1)
        try:
            return int(parts[0]) <= target_port <= int(parts[1])
        except ValueError:
            return False
    try:
        return int(ports_str) == target_port
    except ValueError:
        return False


def _is_all_ports(ports_str):
    return not ports_str or ports_str == '0'


# ---------------------------------------------------------------------------
# Section 2: Compute (Droplets)
# ---------------------------------------------------------------------------

def _check_droplet_backups(asset_id, droplets):
    """2.1 Backups enabled — CIS / DigitalOcean Best Practices"""
    issues = []
    for d in droplets:
        if d.get('status') != 'active':
            continue
        if 'backups' not in d.get('features', []) and not d.get('backup_ids', []):
            name = d.get('name', d.get('id'))
            details = (
                'Finding: Droplet [%s] does not have automated backups enabled.\n\n'
                'Risk: Without backups, data lost through accidental deletion, ransomware, or '
                'hardware failure cannot be recovered. The Droplet would need to be rebuilt from '
                'scratch, resulting in data loss and extended downtime.\n\n'
                'Remediation:\n'
                '1. Open the DigitalOcean Control Panel and navigate to Droplets.\n'
                '2. Select the Droplet and click "Backups" in the left-hand menu.\n'
                '3. Click "Enable Weekly Backups". DigitalOcean retains four rolling weekly '
                'backup images stored in the same region as the Droplet.\n'
                '4. Alternatively, use the API: POST /v2/droplets/{droplet_id}/actions '
                'with body {"type": "enable_backups"}.\n'
                'Note: Automated backups are billed at 20%% of the Droplet\'s monthly cost. '
                'For more granular recovery, consider supplementing with Droplet Snapshots '
                'taken at critical change points.'
            ) % name
            issues.append(_make_issue(asset_id, '2.1',
                'Ensure automated backups are enabled for Droplets',
                details, '2', str(d.get('id', ''))))
    return issues


def _check_droplet_monitoring(asset_id, droplets):
    """2.2 Monitoring agent — CIS / NIST SP 800-53 AU-2"""
    issues = []
    for d in droplets:
        if d.get('status') != 'active':
            continue
        if 'monitoring' not in d.get('features', []):
            name = d.get('name', d.get('id'))
            details = (
                'Finding: Droplet [%s] does not have the DigitalOcean monitoring agent installed.\n\n'
                'Risk: Without the monitoring agent, CPU, memory, disk, and bandwidth metrics are '
                'unavailable in the Control Panel. Alert policies cannot fire on resource thresholds, '
                'making it impossible to detect performance degradation or attacks that consume system '
                'resources (such as crypto-mining malware or runaway processes).\n\n'
                'Remediation:\n'
                '1. SSH into the Droplet.\n'
                '2. Install the monitoring agent by running:\n'
                '   curl -sSL https://repos.do.io/install.sh | sudo bash\n'
                '3. Verify the agent is running:\n'
                '   sudo systemctl status do-agent\n'
                '4. For new Droplets, enable monitoring at creation time by ticking "Monitoring" '
                'under "Additional Options" in the Control Panel, or include "monitoring" in the '
                'features list when using the API (POST /v2/droplets).\n'
                '5. Once the agent is installed, configure alert policies in Control Panel > '
                'Monitoring > Alerts to notify on CPU, memory, and disk thresholds.'
            ) % name
            issues.append(_make_issue(asset_id, '2.2',
                'Ensure the DigitalOcean monitoring agent is enabled for Droplets',
                details, '2', str(d.get('id', ''))))
    return issues


def _check_droplet_vpc(asset_id, droplets):
    """2.3 VPC placement — CIS / NIST SP 800-53 SC-7"""
    issues = []
    for d in droplets:
        if d.get('status') != 'active':
            continue
        if not d.get('vpc_uuid', ''):
            name = d.get('name', d.get('id'))
            details = (
                'Finding: Droplet [%s] is not assigned to a Virtual Private Cloud (VPC).\n\n'
                'Risk: Droplets outside a VPC use DigitalOcean\'s legacy shared private network, '
                'which is accessible to all resources in the same datacenter region by default. '
                'Internal traffic between Droplets may be exposed to other tenants on the shared '
                'network. VPCs provide isolated Layer 2 broadcast domains that prevent this.\n\n'
                'Remediation:\n'
                'Note: A Droplet cannot be moved to a VPC after creation — it must be re-created.\n'
                '1. Create a VPC in the same region: Control Panel > Networking > VPCs > Create VPC.\n'
                '2. When creating the replacement Droplet, select the VPC under "VPC Network".\n'
                '3. Take a Snapshot of the old Droplet: Control Panel > Droplets > Snapshots > '
                'Take Snapshot.\n'
                '4. Create a new Droplet from the snapshot, selecting the VPC during creation.\n'
                '5. Update DNS records, load balancer targets, and any references to the old '
                'Droplet\'s IP address.\n'
                '6. Verify the new Droplet is functioning correctly, then destroy the old Droplet.'
            ) % name
            issues.append(_make_issue(asset_id, '2.3',
                'Ensure Droplets are deployed within a VPC',
                details, '3', str(d.get('id', ''))))
    return issues


def _check_droplet_firewall_assignment(asset_id, droplets, firewalls):
    """2.4 Firewall assignment — CIS / NIST SP 800-53 SC-7"""
    covered_ids = set()
    covered_tags = set()
    for fw in firewalls:
        for did in fw.get('droplet_ids', []):
            covered_ids.add(did)
        for tag in fw.get('tags', []):
            covered_tags.add(tag)

    issues = []
    for d in droplets:
        if d.get('status') != 'active':
            continue
        did = d.get('id')
        dtags = set(d.get('tags', []))
        if did not in covered_ids and not dtags.intersection(covered_tags):
            name = d.get('name', did)
            details = (
                'Finding: Droplet [%s] is not assigned to any Cloud Firewall.\n\n'
                'Risk: Without a Cloud Firewall, all inbound ports on the Droplet are reachable '
                'from the internet (subject only to any OS-level firewall that may be configured). '
                'This greatly increases the attack surface, exposing services such as SSH, web '
                'servers, and any other listening ports to automated reconnaissance, brute-force, '
                'and exploitation attempts.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Networking > Firewalls > Create Firewall.\n'
                '2. Define inbound rules that allow only the ports your workload requires:\n'
                '   - TCP 443 and TCP 80 from any source for web traffic.\n'
                '   - TCP 22 (SSH) from your specific management IP addresses only — not from all sources.\n'
                '   - No other ports should be open unless explicitly required.\n'
                '3. Under "Apply to Droplets", add this Droplet by name or by a tag it already has.\n'
                '4. Save the firewall. Cloud Firewall rules are applied at the network edge and '
                'take effect immediately, regardless of the OS-level firewall state.'
            ) % name
            issues.append(_make_issue(asset_id, '2.4',
                'Ensure Droplets are protected by Cloud Firewalls',
                details, '4', str(did)))
    return issues


def _check_droplet_tags(asset_id, droplets):
    """2.5 Resource tagging — CSA CCM GRM-02 / DigitalOcean governance best practice"""
    issues = []
    for d in droplets:
        if d.get('status') != 'active':
            continue
        if not d.get('tags'):
            name = d.get('name', d.get('id'))
            details = (
                'Finding: Droplet [%s] has no tags assigned.\n\n'
                'Risk: Without tags, Droplets cannot be grouped for bulk firewall rule application, '
                'cost allocation reporting, or automated policy enforcement. As the infrastructure '
                'scales, untagged resources become difficult to manage consistently — firewall rules '
                'must be applied individually rather than to a logical group, and cost attribution '
                'by environment, team, or application is impossible.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Droplets, select the Droplet, and add tags in the '
                '"Tags" field on the Droplet detail page.\n'
                '2. Use a consistent tagging convention, for example:\n'
                '   - env:production / env:staging / env:development\n'
                '   - role:web / role:api / role:worker\n'
                '   - team:backend / team:data\n'
                '3. Alternatively, via API: POST /v2/tags/{tag_name}/resources with body '
                '{"resources": [{"resource_id": "<droplet_id>", "resource_type": "droplet"}]}.\n'
                '4. Once tagged, Cloud Firewalls, Spaces bucket policies, and monitoring alert '
                'policies can target the tag rather than individual resource IDs.'
            ) % name
            issues.append(_make_issue(asset_id, '2.5',
                'Ensure Droplets have resource tags applied',
                details, '1', str(d.get('id', ''))))
    return issues


# ---------------------------------------------------------------------------
# Section 3: Networking
# ---------------------------------------------------------------------------

def _check_firewall_ssh_open(asset_id, firewalls):
    """3.1 Unrestricted SSH — CIS / NIST SP 800-53 AC-17"""
    issues = []
    for fw in firewalls:
        for rule in fw.get('inbound_rules', []):
            if rule.get('protocol', '').lower() != 'tcp':
                continue
            if _is_open_source(rule.get('sources', {})) and _port_matches(rule.get('ports', ''), 22):
                name = fw.get('name', fw.get('id'))
                details = (
                    'Finding: Firewall [%s] has an inbound rule that allows TCP port 22 (SSH) '
                    'from 0.0.0.0/0 (all IPv4) or ::/0 (all IPv6).\n\n'
                    'Risk: Exposing SSH to the internet allows any host to attempt authentication '
                    'against the server. This enables brute-force and credential-stuffing attacks '
                    'around the clock. SSH is one of the most heavily targeted services by automated '
                    'attack tools and botnets. A single weak or reused password is sufficient for '
                    'an attacker to gain full root access.\n\n'
                    'Remediation:\n'
                    '1. Go to Control Panel > Networking > Firewalls and select this firewall.\n'
                    '2. Locate the inbound rule allowing TCP 22 from 0.0.0.0/0 or ::/0 and '
                    'delete it.\n'
                    '3. Add a new inbound rule: Protocol TCP, Port 22, Sources = your specific '
                    'management IP addresses or CIDR ranges (e.g., your office IP, VPN exit node).\n'
                    '4. If access is needed from changing or unknown IPs, deploy a bastion host '
                    '(jump server) within a VPC and expose only the bastion\'s IP to SSH access.\n'
                    '5. Additionally harden the SSH daemon on each Droplet: set '
                    '"PasswordAuthentication no" in /etc/ssh/sshd_config to enforce key-based '
                    'authentication, and restart sshd after the change.'
                ) % name
                issues.append(_make_issue(asset_id, '3.1',
                    'Ensure Cloud Firewalls do not allow unrestricted SSH inbound access',
                    details, '5', str(fw.get('id', ''))))
                break
    return issues


def _check_firewall_rdp_open(asset_id, firewalls):
    """3.2 Unrestricted RDP — CIS / NIST SP 800-53 AC-17"""
    issues = []
    for fw in firewalls:
        for rule in fw.get('inbound_rules', []):
            if rule.get('protocol', '').lower() != 'tcp':
                continue
            if _is_open_source(rule.get('sources', {})) and _port_matches(rule.get('ports', ''), 3389):
                name = fw.get('name', fw.get('id'))
                details = (
                    'Finding: Firewall [%s] has an inbound rule that allows TCP port 3389 (RDP) '
                    'from 0.0.0.0/0 (all IPv4) or ::/0 (all IPv6).\n\n'
                    'Risk: Exposing RDP to the internet is one of the leading causes of ransomware '
                    'compromise. Automated scanners continuously probe port 3389, and critical '
                    'vulnerabilities such as BlueKeep (CVE-2019-0708) and DejaBlue have enabled '
                    'unauthenticated remote code execution against exposed RDP endpoints. Credential '
                    'brute-force against RDP is also extremely common and often successful against '
                    'accounts with weak or reused passwords.\n\n'
                    'Remediation:\n'
                    '1. Go to Control Panel > Networking > Firewalls and select this firewall.\n'
                    '2. Delete or edit the inbound rule allowing TCP 3389 from 0.0.0.0/0 or ::/0.\n'
                    '3. Replace it with a rule allowing TCP 3389 only from your specific management '
                    'IP addresses or CIDR ranges.\n'
                    '4. For stronger protection, place Windows Droplets inside a VPC and access '
                    'them via a VPN or bastion host so that the RDP port is never reachable from '
                    'the public internet directly.\n'
                    '5. Ensure the Droplet is fully patched with the latest Windows updates, uses '
                    'a strong and unique local Administrator password, and has Network Level '
                    'Authentication (NLA) enabled.'
                ) % name
                issues.append(_make_issue(asset_id, '3.2',
                    'Ensure Cloud Firewalls do not allow unrestricted RDP inbound access',
                    details, '5', str(fw.get('id', ''))))
                break
    return issues


def _check_firewall_all_open(asset_id, firewalls):
    """3.3 All-ports wildcard rule — CIS / NIST SP 800-53 SC-7"""
    issues = []
    for fw in firewalls:
        for rule in fw.get('inbound_rules', []):
            if _is_open_source(rule.get('sources', {})) and _is_all_ports(rule.get('ports', '')):
                name = fw.get('name', fw.get('id'))
                details = (
                    'Finding: Firewall [%s] has an inbound rule that allows all ports and protocols '
                    'from 0.0.0.0/0 (all IPv4) or ::/0 (all IPv6).\n\n'
                    'Risk: An all-ports, all-protocols rule from any source effectively disables the '
                    'firewall for inbound traffic. Every service running on the protected Droplets — '
                    'including databases, admin interfaces, and internal development servers — is '
                    'exposed directly to the internet. This is equivalent to having no network-level '
                    'protection at all and maximises the attack surface available to adversaries.\n\n'
                    'Remediation:\n'
                    '1. Go to Control Panel > Networking > Firewalls and select this firewall.\n'
                    '2. Remove the wildcard inbound rule immediately.\n'
                    '3. Add specific, narrow rules for each service that needs to be reachable:\n'
                    '   - TCP 80 and TCP 443 from any source (0.0.0.0/0) for public web traffic.\n'
                    '   - TCP 22 from your management IPs only.\n'
                    '   - Any other ports only from the specific sources that require them.\n'
                    '4. Apply the principle of least privilege: if a port is not actively used by '
                    'a running service, it should not be permitted in the firewall.\n'
                    '5. After tightening the rules, verify that your applications are still '
                    'reachable as expected before closing the session.'
                ) % name
                issues.append(_make_issue(asset_id, '3.3',
                    'Ensure Cloud Firewalls do not allow unrestricted inbound access on all ports',
                    details, '5', str(fw.get('id', ''))))
                break
    return issues


def _check_firewall_db_ports_open(asset_id, firewalls):
    """3.4 Database ports exposed — CIS / NIST SP 800-53 SC-7"""
    issues = []
    for fw in firewalls:
        exposed = set()
        for rule in fw.get('inbound_rules', []):
            if rule.get('protocol', '').lower() not in ('tcp', 'udp'):
                continue
            if not _is_open_source(rule.get('sources', {})):
                continue
            for port in _DB_PORTS:
                if _port_matches(rule.get('ports', ''), port):
                    exposed.add(_DB_PORT_NAMES.get(port, str(port)))
        if exposed:
            name = fw.get('name', fw.get('id'))
            port_list = ', '.join(sorted(exposed))
            details = (
                'Finding: Firewall [%s] exposes the following database port(s) to 0.0.0.0/0 '
                'or ::/0: %s.\n\n'
                'Risk: Exposing database ports to the public internet allows any host to attempt '
                'authentication against the database server. Automated tools scan the entire IPv4 '
                'address space continuously and will discover exposed database ports within minutes. '
                'Even with strong credentials, this exposure enables brute-force attacks, and any '
                'future credential leak or authentication bypass vulnerability would give an attacker '
                'direct access to all data stored in the database.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Networking > Firewalls and select this firewall.\n'
                '2. Locate the inbound rule(s) exposing the database port(s) to 0.0.0.0/0 or '
                '::/0 and delete or edit them.\n'
                '3. Replace with rules allowing database access only from specific trusted sources:\n'
                '   - The private IP addresses of your application servers within the same VPC.\n'
                '   - A dedicated bastion host IP for DBA administrative queries.\n'
                '   - Your office CIDR block for local development access, if required.\n'
                '4. If using DigitalOcean Managed Databases, prefer the "Trusted Sources" feature '
                'on the database cluster itself (Control Panel > Databases > Settings > Trusted '
                'Sources) rather than relying on Droplet firewall rules.\n'
                '5. Ensure databases do not have a public IP if they are only accessed by internal '
                'services within the same VPC.'
            ) % (name, port_list)
            issues.append(_make_issue(asset_id, '3.4',
                'Ensure Cloud Firewalls do not expose database ports to the public internet',
                details, '4', str(fw.get('id', ''))))
    return issues


def _check_lb_https(asset_id, load_balancers):
    """3.5 Load Balancer HTTPS — CIS / NIST SP 800-53 SC-8"""
    issues = []
    for lb in load_balancers:
        rules = lb.get('forwarding_rules', [])
        has_https = any(r.get('entry_protocol', '').lower() in ('https', 'http2') for r in rules)
        if rules and not has_https:
            name = lb.get('name', lb.get('id'))
            details = (
                'Finding: Load Balancer [%s] has no HTTPS or HTTP/2 forwarding rules. All '
                'configured forwarding rules use unencrypted HTTP.\n\n'
                'Risk: Without HTTPS, all data transmitted between clients and the load balancer — '
                'including authentication credentials, session tokens, form submissions, and '
                'application responses — is sent in cleartext. This data can be intercepted by '
                'passive eavesdropping on any network path between the client and the load balancer, '
                'and is vulnerable to active man-in-the-middle attacks.\n\n'
                'Remediation:\n'
                '1. Obtain a TLS certificate for your domain. The easiest option is DigitalOcean\'s '
                'free Let\'s Encrypt integration, which issues and renews certificates automatically:\n'
                '   Control Panel > Networking > Certificates > Add Certificate > Let\'s Encrypt.\n'
                '2. Go to Control Panel > Networking > Load Balancers and select this load balancer.\n'
                '3. Click "Settings", then edit "Forwarding Rules".\n'
                '4. Add a new rule: Entry Protocol = HTTPS, Entry Port = 443, Target Protocol = '
                'HTTP (or HTTPS if your backend also terminates TLS), Target Port = your backend '
                'port, and select the certificate.\n'
                '5. Save the rule. Also enable "Redirect HTTP to HTTPS" (see check 3.6) to ensure '
                'clients connecting on port 80 are automatically sent to the HTTPS endpoint.'
            ) % name
            issues.append(_make_issue(asset_id, '3.5',
                'Ensure Load Balancers use HTTPS for inbound traffic',
                details, '3', str(lb.get('id', ''))))
    return issues


def _check_lb_http_redirect(asset_id, load_balancers):
    """3.6 HTTP-to-HTTPS redirect — NIST SP 800-53 SC-8 / DigitalOcean best practice"""
    issues = []
    for lb in load_balancers:
        rules = lb.get('forwarding_rules', [])
        has_http = any(r.get('entry_protocol', '').lower() == 'http' for r in rules)
        if has_http and not lb.get('redirect_http_to_https', False):
            name = lb.get('name', lb.get('id'))
            details = (
                'Finding: Load Balancer [%s] accepts plain HTTP traffic on port 80 but does not '
                'redirect it to HTTPS.\n\n'
                'Risk: Users who access the application over plain HTTP receive unencrypted '
                'responses and are not guided to the secure version of the site. This creates an '
                'opportunity for SSL-stripping attacks, where an attacker intercepts the initial '
                'HTTP request and prevents the browser from ever upgrading to HTTPS. Any credentials '
                'or sensitive data submitted over HTTP are exposed in transit.\n\n'
                'Remediation:\n'
                '1. Ensure an HTTPS forwarding rule is already configured on the load balancer '
                '(see check 3.5). The redirect option requires HTTPS to be set up first.\n'
                '2. Go to Control Panel > Networking > Load Balancers and select this load balancer.\n'
                '3. Click "Settings" and enable the "Redirect HTTP to HTTPS" toggle.\n'
                '4. Save the change. HTTP requests on port 80 will now receive a 301 permanent '
                'redirect to the equivalent HTTPS URL.\n'
                '5. For additional protection, add an HTTP Strict Transport Security (HSTS) header '
                'in your application or web server configuration (e.g., '
                '"Strict-Transport-Security: max-age=31536000; includeSubDomains") to instruct '
                'browsers to always use HTTPS for future visits.'
            ) % name
            issues.append(_make_issue(asset_id, '3.6',
                'Ensure Load Balancers redirect HTTP traffic to HTTPS',
                details, '3', str(lb.get('id', ''))))
    return issues


# ---------------------------------------------------------------------------
# Section 4: Managed Databases
# ---------------------------------------------------------------------------

def _check_database_trusted_sources(asset_id, databases):
    """4.1 Trusted-source rules — CIS / NIST SP 800-53 AC-3"""
    issues = []
    for db in databases:
        if db.get('status') != 'online':
            continue
        if not db.get('rules', []):
            name = db.get('name', db.get('id'))
            details = (
                'Finding: Managed database cluster [%s] has no trusted-source rules configured. '
                'Any IP address can reach the database connection endpoint.\n\n'
                'Risk: Without trusted-source restrictions, the database connection endpoint is '
                'publicly reachable. Automated bots continuously scan the internet for exposed '
                'database ports. Even with strong credentials, this exposure enables brute-force '
                'attacks against the authentication layer, and any future vulnerability in the '
                'database engine or authentication mechanism would be directly exploitable without '
                'first requiring access to another system.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Databases and select the cluster.\n'
                '2. Click the "Settings" tab and scroll to the "Trusted Sources" section.\n'
                '3. Add each trusted source individually:\n'
                '   - Application server Droplets: select by Droplet name or tag.\n'
                '   - VPC subnets: enter the CIDR block of your VPC.\n'
                '   - Kubernetes clusters: select the cluster by name.\n'
                '   - DBA workstation: enter a specific IP address for administrative access.\n'
                '4. Click "Save". Only the listed sources will be able to establish connections '
                'to the database endpoint.\n'
                '5. Review and remove stale entries when servers are decommissioned to maintain '
                'the principle of least-privilege access.'
            ) % name
            issues.append(_make_issue(asset_id, '4.1',
                'Ensure managed database clusters restrict inbound access via trusted sources',
                details, '4', str(db.get('id', ''))))
    return issues


def _check_database_ssl(asset_id, databases):
    """4.2 SSL/TLS enforcement — CIS / NIST SP 800-53 SC-8"""
    issues = []
    for db in databases:
        if db.get('status') != 'online':
            continue
        connection = db.get('connection', {}) or {}
        if connection.get('ssl') is False:
            name = db.get('name', db.get('id'))
            details = (
                'Finding: Managed database cluster [%s] has SSL/TLS disabled or not required '
                'for client connections.\n\n'
                'Risk: Without SSL enforcement, application clients can connect using unencrypted '
                'connections. The database username, password, and all query data — including '
                'sensitive records — are transmitted in cleartext. An attacker with access to the '
                'network path between the application and the database (e.g., via ARP spoofing '
                'within the same data centre or a compromised intermediate host) can intercept '
                'credentials and exfiltrate all data.\n\n'
                'Remediation:\n'
                'DigitalOcean Managed Databases enforce SSL by default. If this check has fired, '
                'review your application connection configuration:\n'
                '1. Go to Control Panel > Databases > select the cluster > Connection Details.\n'
                '2. Download the CA certificate for the cluster from the "Download CA Certificate" '
                'link.\n'
                '3. Update all application connection strings to require SSL and to verify the '
                'server certificate using the CA certificate:\n'
                '   - PostgreSQL: append "?sslmode=verify-full&sslrootcert=/path/to/ca.crt" to '
                'the connection string.\n'
                '   - MySQL: add ssl-ca=/path/to/ca.crt in the client configuration or connection '
                'options.\n'
                '   - Redis: use a rediss:// URI scheme and pass the CA certificate to the client.\n'
                '4. Test the updated connection to confirm SSL is active before removing any '
                'fallback non-SSL connection paths.'
            ) % name
            issues.append(_make_issue(asset_id, '4.2',
                'Ensure SSL/TLS is required for managed database connections',
                details, '4', str(db.get('id', ''))))
    return issues


def _check_database_ha(asset_id, databases):
    """4.3 High availability / standby node — NIST SP 800-53 CP-9 / DigitalOcean best practice"""
    issues = []
    for db in databases:
        if db.get('status') != 'online':
            continue
        num_nodes = db.get('num_nodes', 1)
        if num_nodes < 2:
            name = db.get('name', db.get('id'))
            details = (
                'Finding: Managed database cluster [%s] has %d node(s) and no standby replica.\n\n'
                'Risk: A single-node database cluster has no automatic failover capability. If the '
                'primary node becomes unavailable — due to hardware failure, a DigitalOcean '
                'maintenance event, disk corruption, or any other disruption — the database is '
                'offline until the issue is resolved. This creates a single point of failure for '
                'every application that depends on the database, potentially causing an extended, '
                'unplanned outage.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Databases and select this cluster.\n'
                '2. Click "Resize" and select a plan that includes a standby node (High '
                'Availability tier). DigitalOcean supports standby nodes for PostgreSQL, MySQL, '
                'and Redis clusters.\n'
                '3. DigitalOcean will provision and synchronise a standby replica in a different '
                'physical host. In the event of a primary node failure, failover to the standby '
                'is automatic and typically completes within 60 seconds.\n'
                '4. Alternatively, via API: PUT /v2/databases/{database_id}/replicas to add a '
                'read replica, then promote it to standby.\n'
                'Note: Adding a standby node approximately doubles the database cost. For '
                'production workloads, this cost is typically justified by the reduction in '
                'recovery time objective (RTO) from hours to under a minute.'
            ) % (name, num_nodes)
            issues.append(_make_issue(asset_id, '4.3',
                'Ensure managed database clusters have a standby node for high availability',
                details, '2', str(db.get('id', ''))))
    return issues


# ---------------------------------------------------------------------------
# Section 5: Kubernetes
# ---------------------------------------------------------------------------

def _check_k8s_auto_upgrade(asset_id, clusters):
    """5.1 Auto-upgrade — CIS Kubernetes / DigitalOcean best practice"""
    issues = []
    for c in clusters:
        if c.get('status', {}).get('state') not in ('running', 'degraded'):
            continue
        if not c.get('auto_upgrade', False):
            name = c.get('name', c.get('id'))
            details = (
                'Finding: Kubernetes cluster [%s] does not have the auto-upgrade feature enabled.\n\n'
                'Risk: Without auto-upgrade, the cluster\'s Kubernetes version falls progressively '
                'further behind the supported release window. DigitalOcean supports only a limited '
                'number of Kubernetes minor versions. Running an unsupported version means no '
                'security patches are applied to the control plane, leaving known vulnerabilities '
                'unaddressed. Kubernetes vulnerabilities have enabled container escape, privilege '
                'escalation to cluster-admin level, and full cluster takeover in past CVEs '
                '(e.g., CVE-2018-1002105, CVE-2019-11246).\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Kubernetes and select the cluster.\n'
                '2. Click "Settings" and enable "Automatic Upgrade".\n'
                '3. DigitalOcean will upgrade the cluster to the latest patch release within the '
                'current minor version on a weekly maintenance window, and to the next supported '
                'minor version when the current one approaches end-of-life.\n'
                '4. Alternatively, via API: PUT /v2/kubernetes/clusters/{cluster_id} with body '
                '{"auto_upgrade": true}.\n'
                '5. To reduce upgrade risk, test your workloads against new Kubernetes versions '
                'in a non-production cluster first. Ensure PodDisruptionBudgets are defined for '
                'critical workloads so that node drains during upgrades do not cause outages.'
            ) % name
            issues.append(_make_issue(asset_id, '5.1',
                'Ensure Kubernetes clusters have auto-upgrade enabled',
                details, '3', str(c.get('id', ''))))
    return issues


def _check_k8s_surge_upgrade(asset_id, clusters):
    """5.2 Surge upgrade — DigitalOcean best practice"""
    issues = []
    for c in clusters:
        if c.get('status', {}).get('state') not in ('running', 'degraded'):
            continue
        if not c.get('surge_upgrade', False):
            name = c.get('name', c.get('id'))
            details = (
                'Finding: Kubernetes cluster [%s] does not have surge upgrade enabled.\n\n'
                'Risk: Without surge upgrade, node upgrades are performed by draining and '
                'replacing nodes one at a time. If the cluster is running at or near full '
                'capacity, workloads evicted from the node being drained may fail to reschedule '
                'because there is insufficient free capacity on the remaining nodes. This can '
                'cause pod eviction failures, scheduling backlogs, and degraded service availability '
                'for the entire duration of the upgrade window.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Kubernetes and select the cluster.\n'
                '2. Click "Settings" and enable "Surge Upgrade".\n'
                '3. With surge upgrade enabled, DigitalOcean provisions one additional (temporary) '
                'node before draining each existing node. This ensures full workload scheduling '
                'capacity is maintained throughout the upgrade process, then the temporary node '
                'is removed once each existing node has been upgraded.\n'
                '4. Alternatively, via API: PUT /v2/kubernetes/clusters/{cluster_id} with body '
                '{"surge_upgrade": true}.\n'
                'Note: Surge upgrade temporarily increases node count by one during upgrades, '
                'which incurs a small additional cost for the duration of the upgrade window. '
                'This cost is typically negligible compared to the risk of upgrade-related outages.'
            ) % name
            issues.append(_make_issue(asset_id, '5.2',
                'Ensure Kubernetes clusters have surge upgrade enabled',
                details, '2', str(c.get('id', ''))))
    return issues


def _check_k8s_autoscale(asset_id, clusters):
    """5.3 Node pool auto-scaling — NIST SP 800-53 CP-2 / DigitalOcean best practice"""
    issues = []
    for c in clusters:
        if c.get('status', {}).get('state') not in ('running', 'degraded'):
            continue
        node_pools = c.get('node_pools', [])
        if node_pools and not any(p.get('auto_scale', False) for p in node_pools):
            name = c.get('name', c.get('id'))
            details = (
                'Finding: Kubernetes cluster [%s] has no node pool with auto-scaling enabled. '
                'All node pools have a fixed node count.\n\n'
                'Risk: A fixed node count means the cluster cannot respond to changes in workload '
                'demand. During traffic spikes or batch job peaks, new pods may fail to schedule '
                'because there is insufficient node capacity, causing "Pending" pods, request '
                'timeouts, and application errors. During periods of low load, the cluster is '
                'over-provisioned and incurs unnecessary cost. Fixed capacity also slows recovery '
                'from node failures, as lost capacity cannot be automatically replaced.\n\n'
                'Remediation:\n'
                '1. Go to Control Panel > Kubernetes, select the cluster, and click on a node pool.\n'
                '2. Enable "Autoscale" and set:\n'
                '   - Minimum nodes: the baseline count needed to handle normal traffic with '
                'headroom for a node failure.\n'
                '   - Maximum nodes: the ceiling for peak load (consider cost implications).\n'
                '3. DigitalOcean\'s cluster autoscaler will add nodes when pods are pending due '
                'to insufficient resources, and remove underutilised nodes after a cooldown period.\n'
                '4. Alternatively, via API: PUT /v2/kubernetes/clusters/{cluster_id}/node_pools/'
                '{pool_id} with body {"auto_scale": true, "min_nodes": N, "max_nodes": M}.\n'
                '5. Ensure Kubernetes resource requests are set accurately on all Deployments so '
                'the autoscaler can make correct scheduling decisions.'
            ) % name
            issues.append(_make_issue(asset_id, '5.3',
                'Ensure Kubernetes cluster node pools have auto-scaling configured',
                details, '2', str(c.get('id', ''))))
    return issues


# ---------------------------------------------------------------------------
# Section 6: Monitoring and Alerting
# ---------------------------------------------------------------------------

def _check_alert_policies(asset_id, alerts):
    """6.1 Alert policies — CIS / NIST SP 800-53 AU-2, SI-2"""
    if not alerts:
        details = (
            'Finding: No monitoring alert policies are defined for this DigitalOcean account.\n\n'
            'Risk: Without alert policies, resource exhaustion, abnormal network traffic, disk '
            'space depletion, and other operational or security events go undetected until they '
            'cause an outage or are discovered during a manual review. Early detection of anomalies '
            'is critical for incident response — for example, sustained high CPU on a Droplet may '
            'indicate crypto-mining malware, and a sudden spike in outbound bandwidth may indicate '
            'active data exfiltration.\n\n'
            'Remediation:\n'
            '1. Go to Control Panel > Monitoring > Alerts > Create Alert.\n'
            '2. Create policies for the following key metrics at a minimum:\n'
            '   - CPU utilisation > 80%% for 5 minutes (overload or crypto-mining indicator).\n'
            '   - Memory utilisation > 80%% for 5 minutes.\n'
            '   - Disk utilisation > 85%% (prevents disk-full outages and log truncation).\n'
            '   - Outbound bandwidth above your established baseline (anomalous data exfiltration '
            'indicator).\n'
            '   - Droplet status: offline (immediate notification of unexpected Droplet failure).\n'
            '3. Configure notification channels (email, Slack, PagerDuty) in each alert policy '
            'so that alerts reach the on-call team in real time.\n'
            '4. Ensure the DigitalOcean monitoring agent is installed on all Droplets (see '
            'check 2.2), as agent-based metrics such as memory and disk are only available with '
            'the agent installed.\n'
            '5. Review and tune alert thresholds periodically as your workload baselines evolve '
            'to minimise false positives while maintaining meaningful signal.'
        )
        return [_make_issue(asset_id, '6.1',
            'Ensure monitoring alert policies are configured',
            details, '2', '')]
    return []


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run_checks(asset_id, headers):
    issues = []

    droplets = digitalocean.get_droplets(headers) or []
    logging.info("Fetching DigitalOcean Firewalls...")
    firewalls = digitalocean.do_get(digitalocean.DO_API_BASE + '/firewalls', headers) or []
    logging.info("Fetching DigitalOcean Load Balancers...")
    load_balancers = digitalocean.do_get(digitalocean.DO_API_BASE + '/load_balancers', headers) or []
    databases = digitalocean.get_databases(headers) or []
    clusters = digitalocean.get_kubernetes_clusters(headers) or []
    logging.info("Fetching DigitalOcean monitoring alert policies...")
    alerts = digitalocean.do_get(digitalocean.DO_API_BASE + '/monitoring/alerts', headers) or []

    # Section 2: Compute
    issues.extend(_check_droplet_backups(asset_id, droplets))
    issues.extend(_check_droplet_monitoring(asset_id, droplets))
    issues.extend(_check_droplet_vpc(asset_id, droplets))
    issues.extend(_check_droplet_firewall_assignment(asset_id, droplets, firewalls))
    issues.extend(_check_droplet_tags(asset_id, droplets))

    # Section 3: Networking
    issues.extend(_check_firewall_ssh_open(asset_id, firewalls))
    issues.extend(_check_firewall_rdp_open(asset_id, firewalls))
    issues.extend(_check_firewall_all_open(asset_id, firewalls))
    issues.extend(_check_firewall_db_ports_open(asset_id, firewalls))
    issues.extend(_check_lb_https(asset_id, load_balancers))
    issues.extend(_check_lb_http_redirect(asset_id, load_balancers))

    # Section 4: Managed Databases
    issues.extend(_check_database_trusted_sources(asset_id, databases))
    issues.extend(_check_database_ssl(asset_id, databases))
    issues.extend(_check_database_ha(asset_id, databases))

    # Section 5: Kubernetes
    issues.extend(_check_k8s_auto_upgrade(asset_id, clusters))
    issues.extend(_check_k8s_surge_upgrade(asset_id, clusters))
    issues.extend(_check_k8s_autoscale(asset_id, clusters))

    # Section 6: Monitoring
    issues.extend(_check_alert_policies(asset_id, alerts))

    logging.info("DigitalOcean CIS checks complete. Total issues found: %d", len(issues))
    return issues


def get_inventory(args):
    if not args.assetid or args.assetid.strip() == '':
        logging.error("[assetid] cannot be empty")
        utils.tw_exit(1)

    headers = {
        'Authorization': 'Bearer ' + args.do_api_key,
        'Content-Type': 'application/json',
    }

    asset_id = args.assetid
    asset = {}
    asset['id'] = asset_id
    asset['name'] = args.assetname if args.assetname and args.assetname.strip() != '' else asset_id
    asset['type'] = 'DigitalOcean'
    asset['owner'] = args.handle
    asset['products'] = []
    asset['tags'] = ['DigitalOcean', 'CIS']
    asset['config_issues'] = run_checks(asset_id, headers)
    args.no_scan = True
    return [asset]
