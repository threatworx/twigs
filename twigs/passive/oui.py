"""MAC address to vendor (IEEE OUI) lookup.

Lookup order: a file given with --oui_file, the IEEE registry bundled at
BUNDLED_OUI_FILE (built from the current IEEE MA-L, MA-M and MA-S registries,
e.g. in the twigs Docker image), then the copies shipped with nmap (a twigs
dependency) or Wireshark. Locally administered (randomised) MACs are never
looked up.

Build the bundled file from the IEEE CSV registries with:

    python3 -m twigs.passive.oui build /usr/local/share/twigs/oui.txt oui.csv mam.csv oui36.csv

(https://standards-oui.ieee.org/oui/oui.csv, /oui28/mam.csv, /oui36/oui36.csv)
"""

import csv
import gzip
import logging
import os
import re
import sys

BUNDLED_OUI_FILE = '/usr/local/share/twigs/oui.txt'
OUI_FILES = [
    BUNDLED_OUI_FILE,
    '/usr/share/nmap/nmap-mac-prefixes',
    '/usr/local/share/nmap/nmap-mac-prefixes',
    '/usr/share/wireshark/manuf',
    '/usr/share/wireshark/manuf.gz',
    '/usr/local/share/wireshark/manuf',
]

_HEX = re.compile(r'[^0-9A-Fa-f]')


def normalize_mac(mac):
    if not mac:
        return None
    h = _HEX.sub('', mac).lower()
    if len(h) != 12 or h in ('000000000000', 'ffffffffffff'):
        return None
    return ':'.join(h[i:i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac):
    return bool(int(mac[0:2], 16) & 0x02)


def is_multicast(mac):
    return bool(int(mac[0:2], 16) & 0x01)


class OUILookup(object):
    def __init__(self, extra_file=None):
        self.prefixes = {}          # prefix length (hex chars) -> {prefix: vendor}
        self.source = None
        if extra_file and not os.path.isfile(extra_file):
            logging.warning("OUI file %s not found", extra_file)
        for f in ([extra_file] if extra_file else []) + OUI_FILES:
            if f and os.path.isfile(f):
                count = self._load(f)
                if count:
                    self.source = f
                    logging.info("MAC vendor database: %s (%d entries)", f, count)
                    break
        if not self.source:
            logging.warning("No MAC vendor (OUI) database found; install nmap or use --oui_file")

    def _load(self, path):
        opener = gzip.open if path.endswith('.gz') else open
        count = 0
        with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # nmap: "0000AA Xerox"   wireshark: "00:00:AA\tXerox\tXerox Corporation" or "00:1B:C5:00:00/36 ..."
                parts = re.split(r'\s+', line, 1) if '\t' not in line else line.split('\t')
                if len(parts) < 2:
                    continue
                prefix, bits = parts[0], None
                if '/' in prefix:
                    prefix, bits = prefix.split('/', 1)
                prefix = _HEX.sub('', prefix).lower()
                if bits:
                    try:
                        prefix = prefix[:int(bits) // 4]
                    except ValueError:
                        continue
                vendor = parts[-1].strip()
                if len(prefix) < 6 or not vendor:
                    continue
                self.prefixes.setdefault(len(prefix), {})[prefix] = vendor
                count += 1
        return count

    def lookup(self, mac):
        mac = normalize_mac(mac)
        if not mac or is_locally_administered(mac) or is_multicast(mac):
            return None
        h = mac.replace(':', '')
        for length in sorted(self.prefixes, reverse=True):
            v = self.prefixes[length].get(h[:length])
            if v:
                return v
        return None


def build_from_ieee(out_path, csv_paths):
    """Write a compact "<hex prefix><TAB><organization>" file from IEEE registry CSVs."""
    entries = {}
    for path in csv_paths:
        with open(path, newline='', encoding='utf-8', errors='replace') as fh:
            for row in csv.DictReader(fh):
                prefix = _HEX.sub('', row.get('Assignment') or '').upper()
                name = re.sub(r'\s+', ' ', row.get('Organization Name') or '').strip()
                if len(prefix) in (6, 7, 9) and name:
                    entries[prefix] = name
    if len(entries) < 10000:
        raise ValueError("only %d entries found in %s, not an IEEE registry?" % (len(entries), ', '.join(csv_paths)))
    tmp = out_path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write('# IEEE MA-L / MA-M / MA-S registry (prefix<TAB>organization), built by twigs\n')
        for prefix in sorted(entries):
            fh.write('%s\t%s\n' % (prefix, entries[prefix]))
    os.replace(tmp, out_path)
    return len(entries)


if __name__ == '__main__':
    if len(sys.argv) < 4 or sys.argv[1] != 'build':
        sys.exit("usage: python3 -m twigs.passive.oui build <output file> <ieee csv> [<ieee csv> ...]")
    print("wrote %d entries to %s" % (build_from_ieee(sys.argv[2], sys.argv[3:]), sys.argv[2]))
