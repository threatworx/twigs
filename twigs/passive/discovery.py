"""twigs passive discovery: medical, OT, building automation and IoT devices
identified from network traffic (pcap files, a live SPAN / TAP interface, or
existing Zeek logs) without sending any packets."""

import argparse
import glob
import logging
import logging.handlers
import os
import re
import shutil
import signal
import time

from .classifier import Classifier, Registry, Signatures, CATEGORIES, identified_via
from .inventory import Inventory
from .oui import OUILookup
from .zeek_runner import Zeek, ZeekError, new_work_dir

CONFIDENCE_ORDER = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
DEFAULT_DURATION = '1h'
DEFAULT_REPORT_INTERVAL = '1h'
POLL_SECONDS = 15                 # how often continuous mode checks for rotated logs
MAX_ROTATION_SECONDS = 600        # Zeek rotates at least this often in continuous mode
MAX_RESTARTS_PER_HOUR = 5
ROTATED_LOG = re.compile(r'^[A-Za-z0-9_]+\.\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.log$')


def parse_duration(value):
    """'90' (seconds), '30m', '2h', '1d' -> seconds."""
    m = re.match(r'^\s*(\d+)\s*([smhd]?)\s*$', str(value).lower())
    if not m:
        raise ValueError("Invalid duration %r (use e.g. 300, 30m, 2h, 1d)" % value)
    return int(m.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400}[m.group(2)]


def add_arguments(parser):
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('--pcap', nargs='+', help='One or more pcap files to analyze')
    src.add_argument('--interface', help='Network interface connected to a SPAN / mirror port or TAP to listen on (requires root or CAP_NET_RAW)')
    src.add_argument('--zeek_logs', nargs='+', help='Directories with existing Zeek logs (JSON or TSV) to analyze instead of running Zeek')
    live = parser.add_mutually_exclusive_group()
    live.add_argument('--duration', help='With --interface: listen for this long, report once and exit, e.g. 30m, 4h, 1d (default: %s)' % DEFAULT_DURATION)
    live.add_argument('--continuous', action='store_true', help='With --interface: keep listening and report every --report_interval until stopped (Ctrl-C / SIGTERM)')
    parser.add_argument('--report_interval', help='With --continuous: how often to report discovered devices, e.g. 15m, 1h (default: 1h)')
    parser.add_argument('--bpf', help='Optional BPF capture filter, e.g. "not port 22"')
    parser.add_argument('--categories', nargs='+', choices=sorted(CATEGORIES), default=sorted(CATEGORIES),
                        help='Device categories to report (default: all)')
    parser.add_argument('--min_confidence', choices=['low', 'medium', 'high'], default='low',
                        help='Only report devices identified with at least this confidence (default: low)')
    parser.add_argument('--signatures', action='append', help='Additional signature YAML file or directory. Can be repeated')
    parser.add_argument('--asset_registry', help='CSV of known assets (serial numbers, hostnames, MACs) to label matching devices. See README')
    # Hidden: path of the zeek binary / bin directory (default: PATH, /opt/zeek/bin) and extra Zeek scripts.
    parser.add_argument('--zeek_path', help=argparse.SUPPRESS)
    parser.add_argument('--zeek_script', action='append', help=argparse.SUPPRESS)
    parser.add_argument('--oui_file', help='MAC vendor (OUI) database in nmap or Wireshark format')
    parser.add_argument('--keep_logs', help='Keep the Zeek logs in this directory (default: discarded after the run)')
    parser.add_argument('--router_mac_threshold', type=int, default=3, help=argparse.SUPPRESS)


def _fail(message):
    logging.error("%s", message)
    from .. import utils
    utils.tw_exit(1)


def _validate(args):
    if (args.duration or args.continuous) and not args.interface:
        raise ValueError("--duration and --continuous can only be used with --interface")
    if args.continuous and getattr(args, 'schedule', None):
        raise ValueError("--continuous runs until stopped and cannot be combined with --schedule")
    if args.report_interval and not args.continuous:
        raise ValueError("--report_interval can only be used with --continuous")
    if args.continuous and parse_duration(args.report_interval or DEFAULT_REPORT_INTERVAL) < 60:
        raise ValueError("--report_interval must be at least 60 seconds")
    parse_duration(args.duration or DEFAULT_DURATION)


def _zeek(args):
    zeek = Zeek(args.zeek_path)
    logging.info("Using Zeek %s (%s)", zeek.version, zeek.zeek)
    if zeek.packages:
        logging.info("Zeek packages: %s", ', '.join(sorted(zeek.packages)))
    else:
        logging.warning("No Zeek protocol packages (ICSNPP) found; BACnet / Modbus / EtherNet/IP identity parsing is limited")
    return zeek


def get_inventory(args, report=None):
    """Return the discovered devices as twigs assets.

    In --continuous mode, report(assets) is called every --report_interval and
    the assets of the final report (after the capture is stopped) are returned.
    """
    try:
        _validate(args)
    except ValueError as e:
        _fail(e)
    work_dir = new_work_dir(args.keep_logs if args.keep_logs else None)
    try:
        if args.continuous:
            return _continuous(args, work_dir, report)
        try:
            if args.zeek_logs:
                for d in args.zeek_logs:
                    if not os.path.isdir(d):
                        raise ZeekError("Zeek log directory not found: %s" % d)
                log_dirs = args.zeek_logs
            elif args.pcap:
                log_dirs = _zeek(args).run_pcaps(args.pcap, work_dir, args.zeek_script, args.bpf)
            else:
                log_dirs = [_zeek(args).run_live(args.interface, parse_duration(args.duration or DEFAULT_DURATION),
                                                 work_dir, args.zeek_script, args.bpf)]
        except (ZeekError, ValueError) as e:
            _fail(e)
        inv = Inventory(router_mac_threshold=args.router_mac_threshold)
        inv.load(log_dirs)
        assets, records, total = build_assets(inv, _classifier(args), args)
        log_report(records, total, logging.INFO)
        return assets
    finally:
        if args.keep_logs:
            logging.info("Zeek logs kept in %s", work_dir)
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


def _classifier(args):
    return Classifier(Signatures(args.signatures), OUILookup(args.oui_file), Registry(args.asset_registry))


def build_assets(inv, classifier, args):
    """Classify the devices in the inventory.

    Returns (assets, records, devices seen); records describe each reported
    device for logging.
    """
    devices = inv.devices()
    min_level = CONFIDENCE_ORDER[args.min_confidence.upper()]
    assets = []
    records = []
    for h in devices:
        c = classifier.classify(h)
        if c is None or c['category'] not in args.categories or CONFIDENCE_ORDER[c['confidence']] < min_level:
            continue
        asset = classifier.to_asset(h, c, args)
        assets.append(asset)
        records.append({
            'id': asset['id'], 'ips': ', '.join(sorted(h.ips)) or '-', 'mac': h.mac or '-',
            'category': c['category'], 'confidence': c['confidence'], 'vendor': c['vendor'],
            'model': c['model'], 'device_class': c['device_class'], 'firmware': c['firmware'],
            'via': identified_via(c['findings'], c['category']),
        })
        logging.debug("Device %s: %s", asset['id'], '; '.join('%s(%d) %s' % (f.source, f.score, f.detail)
                                                          for f in c['findings']))
    return assets, records, len(devices)


def _describe(r):
    name = ' '.join(p for p in (r['vendor'], r['model']) if p) or 'Unknown vendor'
    text = '[%s] %s (%s) %s / %s' % (r['category'], name, r['device_class'], r['ips'], r['mac'])
    if r['firmware']:
        text += ', firmware %s' % r['firmware']
    return text + ', confidence %s, via %s' % (r['confidence'], ', '.join(r['via']) or '-')


def log_changes(known, records):
    """Log devices that are new or changed since the last report (continuous mode)."""
    for r in records:
        old = known.get(r['id'])
        if old is None:
            logging.info("New device: %s", _describe(r))
            continue
        changes = []
        for key, label in (('category', 'category'), ('device_class', 'class'), ('vendor', 'vendor'),
                           ('model', 'model'), ('firmware', 'firmware'), ('confidence', 'confidence')):
            if old[key] != r[key]:
                changes.append('%s %s -> %s' % (label, old[key] or '-', r[key] or '-'))
        if changes:
            logging.info("Device updated: %s / %s: %s", r['ips'], r['mac'], '; '.join(changes))
    known.clear()
    known.update((r['id'], r) for r in records)


def log_report(records, total, table_level):
    counts = {}
    for r in records:
        counts[r['category']] = counts.get(r['category'], 0) + 1
    order = {'medical': 0, 'ot': 1, 'building': 2, 'iot': 3}
    logging.info("Passive discovery: %d devices seen, %d identified (%s)", total, len(records),
                 ', '.join('%s %d' % (c, counts[c]) for c in sorted(counts, key=lambda c: order.get(c, 9))) or 'none')
    for r in sorted(records, key=lambda r: (order.get(r['category'], 9), -CONFIDENCE_ORDER[r['confidence']], r['ips'])):
        logging.log(table_level, "  %-8s %-6s %-30s %-17s %-22s %-26s %-24s %-10s via %s",
                    *([str(x)[:30] or '-' for x in (r['category'], r['confidence'], r['ips'], r['mac'], r['vendor'],
                                                   r['model'], r['device_class'], r['firmware'])] + [', '.join(r['via'])]))


def _rotate_log_files(backups=7):
    """Rotate the twigs run log daily during long continuous captures."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if type(handler) is logging.FileHandler:
            rotating = logging.handlers.TimedRotatingFileHandler(handler.baseFilename, when='midnight',
                                                                 backupCount=backups, encoding=handler.encoding)
            rotating.setLevel(handler.level)
            rotating.setFormatter(handler.formatter)
            root.removeHandler(handler)
            handler.close()
            root.addHandler(rotating)


class _Stop(object):
    """Set by SIGTERM / SIGINT so the capture loop can shut down cleanly."""

    def __init__(self):
        self.requested = False
        self._previous = {}
        for sig in (signal.SIGTERM, signal.SIGINT):
            self._previous[sig] = signal.signal(sig, self._handler)

    def _handler(self, signum, frame):
        if not self.requested:
            logging.info("Stopping passive discovery (signal %d), sending the final report", signum)
        self.requested = True

    def restore(self):
        for sig, handler in self._previous.items():
            signal.signal(sig, handler)

    def sleep(self, seconds):
        end = time.time() + seconds
        while not self.requested and time.time() < end:
            time.sleep(min(1.0, end - time.time()))


def _continuous(args, work_dir, report):
    report_interval = args.report_interval or DEFAULT_REPORT_INTERVAL
    interval = parse_duration(report_interval)
    rotation = max(60, min(interval, MAX_ROTATION_SECONDS))
    try:
        zeek = _zeek(args)
    except ZeekError as e:
        _fail(e)
    classifier = _classifier(args)
    inv = Inventory(router_mac_threshold=args.router_mac_threshold)
    live_dir = os.path.join(work_dir, 'live')
    stop = _Stop()
    restarts = []
    known = {}
    _rotate_log_files()

    processed_dir = os.path.join(live_dir, 'processed')

    def ingest(rotated_only=True):
        # Each file is read once, then deleted (or moved aside with --keep_logs).
        files = inv.load([live_dir], rotated_only=rotated_only)
        # Rotated (closed) logs twigs does not use, e.g. dns or files, go too,
        # so a long running capture does not fill the disk.
        files += [f for f in glob.glob(os.path.join(live_dir, '*.log'))
                  if ROTATED_LOG.match(os.path.basename(f)) and f not in files]
        for f in files:
            try:
                if args.keep_logs:
                    os.makedirs(processed_dir, exist_ok=True)
                    os.replace(f, os.path.join(processed_dir, '%d-%s' % (time.time() * 1000, os.path.basename(f))))
                else:
                    os.remove(f)
            except OSError as e:
                logging.debug("Unable to remove processed log %s: %s", f, e)

    logging.info("Listening on %s continuously, reporting every %s (Ctrl-C or SIGTERM to stop)",
                 args.interface, report_interval)
    proc = zeek.start_live(args.interface, live_dir, args.zeek_script, args.bpf, rotation)
    next_report = time.time() + interval
    try:
        while not stop.requested:
            stop.sleep(POLL_SECONDS)
            if proc.poll() is not None and not stop.requested:
                logging.error("Zeek stopped unexpectedly (exit code %s): %s", proc.returncode, zeek.output(live_dir))
                now = time.time()
                restarts = [t for t in restarts if now - t < 3600] + [now]
                if len(restarts) > MAX_RESTARTS_PER_HOUR:
                    _fail("Zeek failed %d times within an hour, giving up" % len(restarts))
                ingest(rotated_only=False)
                logging.info("Restarting Zeek on %s", args.interface)
                proc = zeek.start_live(args.interface, live_dir, args.zeek_script, args.bpf, rotation)
            ingest()
            if time.time() >= next_report and not stop.requested:
                next_report += interval
                assets, records, total = build_assets(inv, classifier, args)
                log_changes(known, records)
                log_report(records, total, logging.DEBUG)
                if assets and report is not None:
                    report(assets)
    finally:
        zeek.stop(proc)
        stop.restore()
    # Zeek closes (and rotates) its logs on shutdown; read everything that is left.
    ingest(rotated_only=False)
    assets, records, total = build_assets(inv, classifier, args)
    log_changes(known, records)
    log_report(records, total, logging.INFO)
    return assets
