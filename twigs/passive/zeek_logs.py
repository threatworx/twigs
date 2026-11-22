"""Read Zeek logs in JSON or TSV format (optionally gzip compressed)."""

import glob
import gzip
import json
import logging
import os


def _open(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')


def _tsv_value(value, unset, empty, set_sep):
    if value == unset:
        return None
    if value == empty:
        return ''
    return value


def read_log(path):
    """Yield one dict per record. TSV vectors/sets are returned as strings."""
    try:
        with _open(path) as fh:
            first = fh.readline()
            if not first:
                return
            if first.lstrip().startswith('{'):
                fh.seek(0)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        logging.debug("Skipping malformed JSON line in %s", path)
                return
            sep, unset, empty, set_sep, fields = '\t', '-', '(empty)', ',', None
            fh.seek(0)
            for line in fh:
                line = line.rstrip('\n')
                if line.startswith('#'):
                    key, _, rest = line.partition(sep if line.startswith('#fields') or line.startswith('#types') else ' ')
                    if key == '#separator':
                        sep = bytes(rest.strip(), 'utf-8').decode('unicode_escape')
                    elif key == '#set_separator':
                        set_sep = rest.split(sep)[-1]
                    elif key == '#unset_field':
                        unset = rest.split(sep)[-1]
                    elif key == '#empty_field':
                        empty = rest.split(sep)[-1]
                    elif line.startswith('#fields'):
                        fields = line.split(sep)[1:]
                    continue
                if not fields or not line:
                    continue
                parts = line.split(sep)
                yield {f: _tsv_value(parts[i] if i < len(parts) else unset, unset, empty, set_sep)
                       for i, f in enumerate(fields)}
    except (OSError, EOFError) as e:
        logging.warning("Unable to read Zeek log %s: %s", path, e)


def find_logs(log_dirs, name, rotated_only=False):
    """Files for log 'name' (e.g. conn) in the directories.

    rotated_only returns only closed, rotated files (conn.<timestamp>.log),
    never the file Zeek is still writing (conn.log).
    """
    patterns = ['%s.*.log' % name, '%s.*.log.gz' % name]
    if not rotated_only:
        patterns += ['%s.log' % name, '%s.log.gz' % name]
    files = []
    for d in log_dirs:
        for pattern in patterns:
            files.extend(glob.glob(os.path.join(d, pattern)))
    return sorted(set(files))
