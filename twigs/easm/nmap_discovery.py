"""Host / service discovery via an independent nmap wrapper (deliberately not
twigs.fingerprint - see the module docstring in twigs/easm/__init__.py)."""
import os
import logging
import shutil
import subprocess
import signal
from xml.dom.minidom import parseString

from .constants import RISKY_PORTS, TLS_PORT_HINTS, RATING_INFO, ISSUE_TYPE_PORTS
from .util import _is_ipv6, _add_product, _new_issue

NMAP = shutil.which('nmap')


def nmap_exists():
    return NMAP is not None and os.access(NMAP, os.X_OK)


def _build_nmap_cmd(args, target, extra_ports=None):
    version_flag = '-sV --version-intensity 5'
    os_flag = ''
    if os.geteuid() == 0:
        os_flag = ' -O'
    else:
        logging.debug("Skipping nmap OS detection - requires root privileges")

    ipv6_flag = ' -6' if _is_ipv6(target) else ''

    scripts = ['default', 'ssl-cert', 'ssl-enum-ciphers', 'http-title', 'http-headers',
               'http-server-header', 'http-generator', 'banner', 'dns-nsid']

    if getattr(args, 'full_port_scan', False):
        port_flag = ' -p-'
    else:
        port_flag = ' --top-ports ' + str(getattr(args, 'top_ports', 1000) or 1000)

    ports = []
    if extra_ports:
        ports.append(extra_ports)
    if getattr(args, 'extra_ports', None):
        ports.append(args.extra_ports)
    if ports and not getattr(args, 'full_port_scan', False):
        # --top-ports cannot be combined with an explicit -p list (nmap
        # silently ignores --top-ports when -p is also given), so fall back
        # to an explicit port expression that also covers the extras.
        well_known = set(RISKY_PORTS.keys()) | set(TLS_PORT_HINTS)
        port_flag = ' -p1-10000,' + ','.join(str(p) for p in sorted(well_known)) + ',' + ','.join(ports)

    timing = getattr(args, 'timing', '4') or '4'
    cmd = "%s %s%s -Pn -oX - -T%s%s%s --script %s" % (
        NMAP, version_flag, os_flag, timing, ipv6_flag, port_flag, ','.join(scripts))
    return cmd


def _is_port_open(port_elem):
    state = port_elem.getElementsByTagName('state')
    return len(state) > 0 and state[0].getAttribute('state') == 'open'


def _text(elem):
    if elem.firstChild is None:
        return ''
    return elem.firstChild.nodeValue


def _script_output(host_or_port_elem, script_id):
    for s in host_or_port_elem.getElementsByTagName('script'):
        if s.getAttribute('id') == script_id:
            return s.getAttribute('output')
    return None


def _best_osfamily(host_elem):
    best = None
    best_acc = -1
    for osmatch in host_elem.getElementsByTagName('osmatch'):
        for osclass in osmatch.getElementsByTagName('osclass'):
            acc = osclass.getAttribute('accuracy')
            if acc == '':
                continue
            acc = int(acc)
            if acc > best_acc:
                best_acc = acc
                best = osclass.getAttribute('osfamily')
    return best


def parse_nmap_xml(xml_out):
    """Returns a dict keyed by IP address: {ip, hostname, ostype, products, ports}"""
    results = {}
    dom = parseString(xml_out)
    for host_elem in dom.getElementsByTagName('host'):
        status = host_elem.getElementsByTagName('status')
        if status and status[0].getAttribute('state') != 'up':
            continue
        addr_elems = host_elem.getElementsByTagName('address')
        addr = None
        for a in addr_elems:
            if a.getAttribute('addrtype') in ('ipv4', 'ipv6'):
                addr = a.getAttribute('addr')
                break
        if addr is None:
            continue

        hostname = addr
        hnames = host_elem.getElementsByTagName('hostname')
        if hnames:
            hostname = hnames[0].getAttribute('name')

        products = []
        ports_info = []
        for port_elem in host_elem.getElementsByTagName('port'):
            if not _is_port_open(port_elem):
                continue
            portid = int(port_elem.getAttribute('portid'))
            protocol = port_elem.getAttribute('protocol')
            service_elems = port_elem.getElementsByTagName('service')
            svc_name = None
            svc_product = None
            svc_version = None
            svc_extra = None
            if service_elems:
                service_elem = service_elems[0]
                svc_name = service_elem.getAttribute('name') or None
                svc_product = service_elem.getAttribute('product') or None
                svc_version = service_elem.getAttribute('version') or None
                svc_extra = service_elem.getAttribute('extrainfo') or None
                for cpe in service_elem.getElementsByTagName('cpe'):
                    cstr = _text(cpe)
                    if not cstr:
                        continue
                    carr = cstr.split(':')
                    if len(carr) >= 4:
                        prodstr = (carr[2] + ' ' + carr[3] + ' ' + (carr[4] if len(carr) >= 5 else '')).strip()
                        _add_product(products, prodstr.replace('_', ' '))
                if svc_product:
                    prodstr = svc_product + (' ' + svc_version if svc_version else '')
                    _add_product(products, prodstr.strip())

            title = _script_output(port_elem, 'http-title')
            server_hdr = _script_output(port_elem, 'http-server-header')
            generator = _script_output(port_elem, 'http-generator')
            banner = _script_output(port_elem, 'banner')
            if server_hdr:
                for tok in server_hdr.split(','):
                    tok = tok.strip().replace('/', ' ').replace('(', ' ').replace(')', ' ').strip()
                    if tok:
                        _add_product(products, tok)
            if generator:
                _add_product(products, generator.strip())

            ports_info.append({
                'port': portid, 'protocol': protocol, 'service': svc_name,
                'product': svc_product, 'version': svc_version, 'extrainfo': svc_extra,
                'title': title, 'banner': banner,
            })

        osfamily = _best_osfamily(host_elem) or 'Other'
        results[addr] = {
            'ip': addr, 'hostname': hostname, 'ostype': osfamily,
            'products': products, 'ports': ports_info,
        }
    return results


def run_nmap_scan(args, target):
    """Runs an independent, detailed nmap scan against a single host/IP.
    Returns a dict as produced by parse_nmap_xml, or None on failure."""
    if not nmap_exists():
        logging.warning("nmap CLI not found - skipping host/service discovery for [%s]", target)
        return None
    cmd = _build_nmap_cmd(args, target)
    logging.debug("EASM nmap command: %s", cmd)
    timeout = getattr(args, 'nmap_timeout', 900)
    # start_new_session=True puts nmap in its own process group so that, on
    # timeout, we can kill the actual nmap process rather than just the shell
    # wrapper spawned by shell=True (killing only the shell leaves nmap running
    # as an orphan, continuing to scan the target after we've moved on).
    proc = subprocess.Popen(cmd + ' ' + target, shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logging.warning("nmap scan against [%s] timed out after %ss - terminating", target, timeout)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.communicate()
        return None
    if proc.returncode != 0:
        logging.warning("nmap scan against [%s] failed (exit code %s)", target, proc.returncode)
        return None
    out = out.decode(getattr(args, 'encoding', 'latin-1'), errors='replace')

    try:
        parsed = parse_nmap_xml(out)
    except Exception as e:
        logging.warning("Unable to parse nmap output for [%s]: %s", target, str(e))
        return None

    if not parsed:
        return None
    # target may have been given as a hostname; nmap keys results by IP
    return list(parsed.values())[0]


def create_port_issues(host_result, asset_id):
    issues = []
    for p in sorted(host_result['ports'], key=lambda x: x['port']):
        title = "Open port [%s/%s] detected" % (p['port'], p['protocol'])
        detail = "Port [%s/%s] is open and reachable from the internet" % (p['port'], p['protocol'])
        if p['service']:
            detail += ", running service [%s]" % p['service']
        if p['product']:
            detail += " identified as [%s %s]" % (p['product'], p['version'] or '')
        if p.get('extrainfo'):
            detail += " (%s)" % p['extrainfo']
        if p.get('banner'):
            detail += ". Banner: %s" % p['banner']
        if p.get('title'):
            detail += ". Page title: %s" % p['title']
        detail += "."

        rating = RATING_INFO
        remediation = "This is informational. If the service is intentionally public, ensure it is kept patched and monitored; if not, restrict it to trusted networks/VPN via firewall rules."
        risky = RISKY_PORTS.get(p['port'])
        if risky:
            svc_label, rating = risky
            title = "Externally exposed %s service on port [%s]" % (svc_label, p['port'])
            detail = ("Service commonly associated with [%s] was found exposed on port [%s/%s]. "
                       "Services of this type are frequently targeted by automated scanners and botnets, and internet exposure is a significant risk unless explicitly intended and hardened (e.g. behind additional authentication or IP allow-listing).") % (svc_label, p['port'], p['protocol'])
            if p['product']:
                detail += " Detected as [%s %s]." % (p['product'], p['version'] or '')
            remediation = ("Restrict access to this port to trusted/allow-listed source IP ranges via firewall or security-group rules, or place the service behind a VPN/bastion host instead of exposing it directly. "
                            "If the service must remain internet-facing, ensure it is fully patched, enforces strong authentication (no default credentials), and is actively monitored for abuse.")

        issues.append(_new_issue(
            'open-port-%s-%s' % (p['protocol'], p['port']), title, detail, rating,
            asset_id, ISSUE_TYPE_PORTS, object_id=str(p['port']), remediation=remediation))
    return issues
