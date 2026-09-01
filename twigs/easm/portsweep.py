"""Full-range port sweeps across a discovered netblock (CIDR/ASN seed, or a
target-owned prefix derived by netblock_sweep) - not just the single resolved
IP of each hostname.

Uses masscan or naabu when present on PATH (fast, async); otherwise a bounded
Python TCP-connect scanner. Results feed both a summary finding and (in
__init__) the creation of host assets for IPs that answered.
"""
import json
import shutil
import socket
import logging
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import RATING_INFO, ISSUE_TYPE_PORTS, RISKY_PORTS
from .util import _new_issue, _is_ipv6

MASSCAN = shutil.which('masscan')
NAABU = shutil.which('naabu')

# ~ top TCP ports worth a range sweep (web, mgmt, db, mail, rpc, misc).
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    993, 995, 1080, 1433, 1521, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128,
    3306, 3389, 4443, 4444, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 7001,
    8000, 8005, 8008, 8009, 8080, 8081, 8083, 8088, 8161, 8443, 8500, 8834,
    8888, 9000, 9042, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 15672,
    27017, 27018, 50000,
]

PY_SCAN_MAX_TARGETS = 4096      # cap (ips * ports) for the pure-python path
PY_SCAN_WORKERS = 200
PY_SCAN_TIMEOUT = 1.5


def _parse_ports(spec):
    if not spec:
        return list(DEFAULT_PORTS)
    out = set()
    for part in str(spec).split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return sorted(out) or list(DEFAULT_PORTS)


def _addrs(cidr, cap):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    out = []
    for a in (net.hosts() if net.num_addresses > 2 else net):
        out.append(str(a))
        if len(out) >= cap:
            break
    return out


def _masscan(cidr, ports, rate):
    cmd = [MASSCAN, cidr, '-p', ','.join(str(p) for p in ports),
           '--rate', str(rate), '-oJ', '-', '--wait', '2']
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except Exception as e:
        raise RuntimeError('masscan failed: %s' % e)
    res = {}
    for line in p.stdout.splitlines():
        line = line.strip().rstrip(',')
        if not line.startswith('{'):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        ip = rec.get('ip')
        for po in rec.get('ports', []):
            if po.get('status') == 'open':
                res.setdefault(ip, set()).add(po.get('port'))
    return res


def _naabu(cidr, ports):
    cmd = [NAABU, '-host', cidr, '-p', ','.join(str(p) for p in ports),
           '-json', '-silent', '-rate', '2000']
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except Exception as e:
        raise RuntimeError('naabu failed: %s' % e)
    res = {}
    for line in p.stdout.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get('ip') and rec.get('port'):
            res.setdefault(rec['ip'], set()).add(rec['port'])
    return res


def _py_scan(cidr, ports):
    addrs = _addrs(cidr, max(1, PY_SCAN_MAX_TARGETS // max(1, len(ports))))
    if not addrs:
        return {}
    res = {}

    def _probe(ip, port):
        fam = socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(PY_SCAN_TIMEOUT)
        try:
            return (ip, port) if s.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=PY_SCAN_WORKERS) as pool:
        futs = [pool.submit(_probe, ip, po) for ip in addrs for po in ports]
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                res.setdefault(r[0], set()).add(r[1])
    return res


def sweep_netblock(cidr, args):
    """{ip: sorted[open_ports]} for one prefix. Prefers masscan > naabu >
    pure-python."""
    ports = _parse_ports(getattr(args, 'portsweep_ports', None))
    rate = getattr(args, 'portsweep_rate', 2000) or 2000
    engine = 'python'
    try:
        if MASSCAN:
            engine, raw = 'masscan', _masscan(cidr, ports, rate)
        elif NAABU:
            engine, raw = 'naabu', _naabu(cidr, ports)
        else:
            raw = _py_scan(cidr, ports)
    except Exception as e:
        logging.warning("[EASM] portsweep: %s sweep of %s failed: %s", engine, cidr, e)
        return {}, engine
    return {ip: sorted(pset) for ip, pset in raw.items() if pset}, engine


def summary_issue(prefix, results, engine, asset_id):
    if not results:
        return None
    lines = []
    for ip in sorted(results):
        labelled = []
        for p in results[ip]:
            svc = RISKY_PORTS.get(p)
            labelled.append('%d%s' % (p, ('/' + svc[0]) if svc else ''))
        lines.append('%s: %s' % (ip, ', '.join(labelled)))
    return _new_issue(
        'netblock-portsweep-%s' % prefix.replace('/', '_').replace(':', '_'),
        "Open ports across netblock %s (%s sweep)" % (prefix, engine),
        "A port sweep of %s found %d host(s) with at least one open TCP port - hosts and services in target-attributed space beyond the single resolved IP of each seeded name:\n%s"
        % (prefix, len(results), '\n'.join(lines[:400])),
        RATING_INFO, asset_id, ISSUE_TYPE_PORTS, object_id=prefix,
        object_meta=','.join(sorted(results)),
        remediation="Review each exposed service. Anything not intentionally internet-facing (databases, admin/RPC/mgmt ports, dev servers) should be firewalled to trusted sources or moved behind a VPN/bastion.")
