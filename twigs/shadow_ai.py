import os
import re
import json
import logging
import hashlib
import datetime

from . import utils

_SIGNATURES = None

RATING_INFO = '2'
RATING_MEDIUM = '3'
RATING_HIGH = '4'

VERSION_RE = re.compile(r'\d+\.\d+(?:\.\d+)*')


def _load_signatures():
    global _SIGNATURES
    if _SIGNATURES is None:
        sig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shadow_ai_signatures.json')
        with open(sig_path, 'r') as f:
            _SIGNATURES = json.load(f)
    return _SIGNATURES


def os_family(atype):
    if atype == 'Mac OS':
        return 'macos'
    return 'linux'


def _slug(*parts):
    s = '-'.join([str(p) for p in parts if p])
    s = re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
    return s[:80] if len(s) > 80 else s


def _issue(asset_id, twc_id, title, details, rating, object_id=''):
    return {
        'twc_id': 'shadow-ai-' + twc_id,
        'asset_id': asset_id,
        'twc_title': title,
        'details': details,
        'rating': rating,
        'object_id': object_id,
        'object_meta': '',
        'type': 'Shadow AI',
    }


def classify_model(name, families):
    lname = name.lower()
    for fam in families:
        for m in fam.get('match', []):
            if m.lower() in lname:
                return 'public', fam['vendor']
    return 'custom', None


def _shell_path(p):
    if p.startswith('~/'):
        return '$HOME/' + p[2:]
    if p == '~':
        return '$HOME'
    return p


# ---------------------------------------------------------------------------
# Probe script builders. Each returns a single POSIX-shell script that is
# run once on the host (locally or over SSH via utils.run_cmd_on_host), to
# minimize round trips against remote hosts. Output lines are tab-delimited
# and prefixed with a tag so the corresponding _parse_* function can pull
# them back out.
# ---------------------------------------------------------------------------

def _build_fs_probe_script(sig):
    lines = ['export LC_ALL=C 2>/dev/null']

    for app in sig.get('desktop_apps', []):
        product = app['product']
        category = app['category']
        for path in app.get('paths', []):
            if '*' in path:
                pattern = _shell_path(path)
                lines.append(
                    'for __f in %s; do [ -e "$__f" ] && printf "APP\\t%s\\t%s\\t%%s\\n" "$__f"; done 2>/dev/null'
                    % (pattern, product, category)
                )
            else:
                p = _shell_path(path)
                lines.append(
                    '[ -e "%s" ] && printf "APP\\t%s\\t%s\\t%s\\n"' % (p, product, category, path)
                )

    for cli in sig.get('cli_tools', []):
        b = cli['bin']
        lines.append(
            'if command -v ' + b + ' >/dev/null 2>&1; then '
            'printf "CLI\\t' + cli['product'] + '\\t' + cli['category'] + '\\t' + b + '\\n"; '
            # Redirect stdin from /dev/null and cap with timeout (when available) so a
            # tool that doesn't recognize --version and drops into an interactive
            # prompt can't hang the whole scan.
            'if command -v timeout >/dev/null 2>&1; then __sa_vc="timeout 3 ' + b + '"; else __sa_vc="' + b + '"; fi; '
            '__sa_ver=$($__sa_vc --version </dev/null 2>&1 | head -1); '
            '[ -n "$__sa_ver" ] && printf "CLIVER\\t' + cli['product'] + '\\t%s\\n" "$__sa_ver"; '
            'fi'
        )

    lines.append(
        'for __d in "$HOME"/.vscode/extensions "$HOME"/.vscode-server/extensions; do '
        '[ -d "$__d" ] && ls "$__d" 2>/dev/null; done | while read -r __ext; do '
        'printf "IDEEXT\\t%s\\n" "$__ext"; done'
    )

    chrome_profiles = (
        '"$HOME"/.config/google-chrome/*/Extensions '
        '"$HOME"/.config/chromium/*/Extensions '
        '"$HOME"/Library/Application\\ Support/Google/Chrome/*/Extensions'
    )
    lines.append(
        'for __d in %s; do [ -d "$__d" ] && ls "$__d" 2>/dev/null; done | while read -r __id; do '
        'printf "BROWSEREXT\\t%%s\\n" "$__id"; done' % chrome_profiles
    )

    for envvar in sig.get('credential_markers', {}).get('env_vars', []):
        lines.append(
            'eval "__v=\\${%s:-}"; [ -n "$__v" ] && printf "CREDENV\\t%s\\n"' % (envvar, envvar)
        )
    for path in sig.get('credential_markers', {}).get('paths', []):
        p = _shell_path(path)
        lines.append('[ -e "%s" ] && printf "CREDPATH\\t%s\\n"' % (p, path))

    for ms in sig.get('model_stores', []):
        runtime = ms['runtime']
        mtype = ms['type']
        path = _shell_path(ms['path'])
        if mtype == 'ollama_manifest':
            lines.append(
                '[ -d "%s" ] && find "%s" -type f 2>/dev/null | while read -r __m; do '
                'printf "MODELOLLAMA\\t%s\\t%%s\\n" "$__m"; done' % (path, path, runtime)
            )
        elif mtype == 'hf_cache':
            lines.append(
                '[ -d "%s" ] && ls "%s" 2>/dev/null | while read -r __hf; do '
                'printf "MODELHF\\t%s\\t%%s\\n" "$__hf"; done' % (path, path, runtime)
            )
        elif mtype == 'glob':
            exts = ms.get('ext', [])
            for ext in exts:
                lines.append(
                    '[ -d "%s" ] && find "%s" -type f -iname "*%s" 2>/dev/null | while read -r __mf; do '
                    'printf "MODELGLOB\\t%s\\t%%s\\t%%s\\n" "$__mf" "$(wc -c < "$__mf" 2>/dev/null || echo 0)"; done'
                    % (path, path, ext, runtime)
                )

    # The last check above routinely fails (nothing found) with no set -e in
    # play, but that failing exit code becomes the *script's* exit code,
    # which run_cmd_on_host()/subprocess.check_output() treats as a failed
    # command and discards all captured stdout. Force success regardless.
    lines.append('true')
    return '\n'.join(lines)


def _build_process_port_probe_script():
    return (
        'ps -eo args= 2>/dev/null | while read -r __p; do printf "PROC\\t%s\\n" "$__p"; done\n'
        'printf "%s\\n" "---PORTS---"\n'
        '(ss -ltnp 2>/dev/null || netstat -tlnp 2>/dev/null || netstat -an -p tcp 2>/dev/null) '
        '| while read -r __l; do printf "PORT\\t%s\\n" "$__l"; done\n'
        'true'
    )


def _build_service_probe_script(sig):
    lines = []
    for svc in sig.get('services', []):
        unit = svc['unit']
        lines.append(
            'command -v systemctl >/dev/null 2>&1 && '
            'systemctl is-active %s >/dev/null 2>&1 && printf "SVC\\t%s\\t%s\\t%s\\n"'
            % (unit, svc['product'], svc['category'], unit)
        )
    if not lines:
        return ''
    lines.append('true')
    return '\n'.join(lines)


def _build_package_probe_script(sig):
    lines = [
        'for __pipcmd in pip3 pip; do command -v "$__pipcmd" >/dev/null 2>&1 && '
        '"$__pipcmd" list --disable-pip-version-check --format=freeze 2>/dev/null && break; done '
        '| while read -r __pl; do printf "PIPPKG\\t%s\\n" "$__pl"; done',
        'command -v npm >/dev/null 2>&1 && npm ls -g --depth=0 2>/dev/null '
        '| while read -r __nl; do printf "NPMPKG\\t%s\\n" "$__nl"; done',
        'command -v gem >/dev/null 2>&1 && gem list --local 2>/dev/null '
        '| while read -r __gl; do printf "GEMPKG\\t%s\\n" "$__gl"; done',
        'true',
    ]
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_fs_probe(output):
    result = {
        'apps': [], 'cli': [], 'ide_ext': [], 'browser_ext': [],
        'cred_env': [], 'cred_path': [], 'model_ollama': [], 'model_hf': [], 'model_glob': [],
        'cli_ver': {},
    }
    if not output:
        return result
    for line in output.splitlines():
        if '\t' not in line:
            continue
        if line.startswith('CLIVER\t'):
            # Handled separately (not via the generic split below) since the
            # captured `--version` output could itself contain a tab.
            cliver_parts = line.split('\t', 2)
            if len(cliver_parts) >= 3:
                result['cli_ver'][cliver_parts[1]] = cliver_parts[2]
            continue
        parts = line.split('\t')
        tag = parts[0]
        if tag == 'APP' and len(parts) >= 4:
            result['apps'].append({'product': parts[1], 'category': parts[2], 'path': parts[3]})
        elif tag == 'CLI' and len(parts) >= 4:
            result['cli'].append({'product': parts[1], 'category': parts[2], 'bin': parts[3]})
        elif tag == 'IDEEXT' and len(parts) >= 2:
            result['ide_ext'].append(parts[1])
        elif tag == 'BROWSEREXT' and len(parts) >= 2:
            result['browser_ext'].append(parts[1])
        elif tag == 'CREDENV' and len(parts) >= 2:
            result['cred_env'].append(parts[1])
        elif tag == 'CREDPATH' and len(parts) >= 2:
            result['cred_path'].append(parts[1])
        elif tag == 'MODELOLLAMA' and len(parts) >= 3:
            result['model_ollama'].append({'runtime': parts[1], 'path': parts[2]})
        elif tag == 'MODELHF' and len(parts) >= 3:
            result['model_hf'].append({'runtime': parts[1], 'dirname': parts[2]})
        elif tag == 'MODELGLOB' and len(parts) >= 4:
            result['model_glob'].append({'runtime': parts[1], 'path': parts[2], 'size': parts[3]})
    return result


def _parse_processes_and_ports(output, sig_processes, sig_ports):
    matched_procs = []
    matched_ports = []
    if not output:
        return matched_procs, matched_ports

    in_ports = False
    proc_lines = []
    port_lines = []
    for line in output.splitlines():
        if line.strip() == '---PORTS---':
            in_ports = True
            continue
        if not line.startswith('PROC\t') and not line.startswith('PORT\t'):
            continue
        value = line.split('\t', 1)[1] if '\t' in line else ''
        if in_ports or line.startswith('PORT\t'):
            port_lines.append(value)
        else:
            proc_lines.append(value)

    for sig_p in sig_processes:
        pattern = sig_p['match']
        for pl in proc_lines:
            if re.search(pattern, pl, re.IGNORECASE):
                matched_procs.append({'product': sig_p['product'], 'category': sig_p['category'], 'evidence': pl.strip()[:200]})
                break

    for sig_port in sig_ports:
        port_str = ':' + str(sig_port['port'])
        for pl in port_lines:
            if port_str not in pl or 'LISTEN' not in pl.upper():
                continue
            proc_match = sig_port.get('process_match', '')
            if proc_match and not re.search(proc_match, pl, re.IGNORECASE):
                continue
            exposed = bool(re.search(r'(^|[^0-9])0\.0\.0\.0:%d\b' % sig_port['port'], pl) or re.search(r'(^|[^0-9])\*:%d\b' % sig_port['port'], pl))
            matched_ports.append({
                'product': sig_port['product'], 'category': sig_port['category'],
                'port': sig_port['port'], 'exposed': exposed, 'evidence': pl.strip()[:200],
            })
            break

    return matched_procs, matched_ports


def _parse_services(output):
    matched = []
    if not output:
        return matched
    for line in output.splitlines():
        if not line.startswith('SVC\t'):
            continue
        parts = line.split('\t')
        if len(parts) >= 4:
            matched.append({'product': parts[1], 'category': parts[2], 'unit': parts[3]})
    return matched


def _parse_packages(output, sig_packages):
    found = []
    if not output:
        return found
    pip_names = set(n.lower() for n in sig_packages.get('pip', []))
    npm_names = set(n.lower() for n in sig_packages.get('npm', []))
    gem_names = set(n.lower() for n in sig_packages.get('gem', []))
    for line in output.splitlines():
        if line.startswith('PIPPKG\t'):
            entry = line.split('\t', 1)[1].strip()
            if '==' in entry:
                name, version = entry.split('==', 1)
            else:
                name, version = entry, ''
            name = name.strip()
            if name.lower() in pip_names:
                found.append({'ecosystem': 'pip', 'name': name, 'version': version.strip()})
        elif line.startswith('NPMPKG\t'):
            entry = line.split('\t', 1)[1]
            m = re.search(r'([\w@/.\-]+)@([\w.\-]+)', entry)
            if m and m.group(1).lower() in npm_names:
                found.append({'ecosystem': 'npm', 'name': m.group(1), 'version': m.group(2)})
        elif line.startswith('GEMPKG\t'):
            entry = line.split('\t', 1)[1].strip()
            name = entry.split(' ')[0].strip()
            version = ''
            vm = re.search(r'\(([^)]+)\)', entry)
            if vm:
                version = vm.group(1)
            if name.lower() in gem_names:
                found.append({'ecosystem': 'gem', 'name': name, 'version': version})
    return found


# ---------------------------------------------------------------------------
# Model manifest interpretation
# ---------------------------------------------------------------------------

def _model_name_from_ollama_manifest_path(path):
    # Manifests live at .../manifests/<registry>/<namespace>/<model>/<tag>
    tokens = [t for t in path.split('/') if t]
    if len(tokens) >= 2:
        return tokens[-2] + ':' + tokens[-1]
    return path


def _model_name_from_hf_dirname(dirname):
    # Hugging Face cache directories look like: models--<org>--<model>
    if dirname.startswith('models--'):
        rest = dirname[len('models--'):]
        segs = rest.split('--')
        if len(segs) >= 2:
            org = segs[0]
            model = '--'.join(segs[1:])
            return org + '/' + model, org
        return rest, None
    return dirname, None


# ---------------------------------------------------------------------------
# Browser history (opt-in, --shadow_ai_check_browsing). Domain + visit count
# + last-visit date only - never full URLs, search queries, or page titles.
# ---------------------------------------------------------------------------

CHROMIUM_EPOCH = datetime.datetime(1601, 1, 1)
SAFARI_EPOCH = datetime.datetime(2001, 1, 1)


def _chromium_case_sql(ai_chat_domains):
    parts = []
    for entry in ai_chat_domains:
        name = entry['name'].replace("'", "''")
        conds = ' OR '.join(
            "url LIKE '%%" + d.replace("'", "''") + "%%'" for d in entry['domains']
        )
        parts.append("WHEN " + conds + " THEN '" + name + "'")
    return "CASE " + " ".join(parts) + " ELSE '' END"


def _browsing_sql(family, case_expr):
    # Per-row (per-URL) tag/cnt/ts in the inner query, regardless of family's
    # native schema; a single aggregation (SUM/MAX grouped by tag) in the
    # outer query. This uniform shape is what lets Safari slot in: unlike
    # Chromium/Firefox (one flat table with both a running visit_count and
    # a last-visit timestamp column), Safari splits a URL's aggregate visit
    # count (history_items.visit_count) from its individual visit timestamps
    # (history_visits.visit_time, one row per visit) across two tables. A
    # plain JOIN between them would multiply visit_count once per matching
    # visit row and wildly overcount, so the per-visit max is instead pulled
    # via an uncorrelated-looking but per-row-correlated subquery, keeping
    # history_items.visit_count (already correct per URL) as the only count
    # source.
    if family == 'chromium':
        inner = "SELECT " + case_expr + " AS tag, visit_count AS cnt, last_visit_time AS ts FROM urls"
    elif family == 'firefox':
        inner = "SELECT " + case_expr + " AS tag, visit_count AS cnt, last_visit_date AS ts FROM moz_places"
    else:  # safari
        inner = (
            "SELECT " + case_expr + " AS tag, hi.visit_count AS cnt, "
            "(SELECT MAX(hv.visit_time) FROM history_visits hv WHERE hv.history_item = hi.id) AS ts "
            "FROM history_items hi"
        )
    # Dropping the no-match ('') bucket in SQL itself (rather than relying
    # solely on the shell/Python side to skip it) means a genuinely empty
    # leading field is never on the wire in the first place.
    return "SELECT tag, SUM(cnt), MAX(ts) FROM (" + inner + ") WHERE tag <> '' GROUP BY tag;"


def _build_browsing_probe_script(sig_all, sig):
    domains = sig_all.get('ai_chat_domains', [])
    profiles = sig.get('browser_profiles', [])
    if not domains or not profiles:
        return 'true'

    case_expr = _chromium_case_sql(domains)
    sql_by_family = {
        'chromium': _browsing_sql('chromium', case_expr).replace('"', '\\"'),
        'firefox': _browsing_sql('firefox', case_expr).replace('"', '\\"'),
        'safari': _browsing_sql('safari', case_expr).replace('"', '\\"'),
    }

    lines = [
        'export LC_ALL=C 2>/dev/null',
        # A non-whitespace separator for the sqlite3 output specifically:
        # POSIX `read` treats tab/space/newline as "IFS whitespace" even
        # when explicitly assigned, which collapses/strips leading empty
        # fields - breaking field alignment whenever a column is empty.
        '__sa_sep="|"',
        '__sa_has_sqlite3=0',
        'command -v sqlite3 >/dev/null 2>&1 && __sa_has_sqlite3=1',
        '__sa_has_timeout=0',
        'command -v timeout >/dev/null 2>&1 && __sa_has_timeout=1',
        '__sa_tmpdir=$(mktemp -d 2>/dev/null)',
        '[ -d "$__sa_tmpdir" ] || __sa_tmpdir="/tmp/.sa_browse_$$"',
        'mkdir -p "$__sa_tmpdir" 2>/dev/null',
    ]

    # If sqlite3 isn't available at all, skip the whole check - no
    # presence-only fallback is generated. A bare "this domain's text
    # appears somewhere in the file" signal with no count or date was
    # assessed as noise rather than a useful finding (same decision already
    # made for the Windows/ShadowAI.psm1 implementation).
    lines.append('if [ "$__sa_has_sqlite3" = "1" ]; then')

    for bp in profiles:
        base = _shell_path(bp['base'])
        pattern = bp['profile_pattern']
        fname = bp['file']
        browser = bp['browser']
        family = bp['family']
        sql = sql_by_family[family]

        lines.append('  if [ -d "' + base + '" ]; then')
        lines.append(
            '    find "' + base + '" -mindepth 1 -maxdepth 1 -type d -iname "' + pattern + '" 2>/dev/null'
            ' | while IFS= read -r __pd; do'
        )
        lines.append('      __bf="$__pd/' + fname + '"')
        lines.append('      [ -e "$__bf" ] || continue')
        lines.append('      __bc="$__sa_tmpdir/sa_$$_$(basename "$__pd" | tr -c "A-Za-z0-9" "_")"')
        lines.append('      cp "$__bf" "$__bc" 2>/dev/null || continue')
        lines.append('      [ -e "$__bf-wal" ] && cp "$__bf-wal" "$__bc-wal" 2>/dev/null')
        lines.append('      __sa_out="$__sa_tmpdir/out_$$_$(basename "$__pd" | tr -c "A-Za-z0-9" "_")"')
        # Query failure for ANY reason (missing/corrupted copy, schema
        # mismatch, still locked despite the copy, or a hang bounded by
        # `timeout` when available) must result in nothing being read back -
        # output is written to a file and only consumed if the exit code is
        # exactly 0, rather than trusting whatever happens to be on stdout.
        lines.append('      if [ "$__sa_has_timeout" = "1" ]; then __sa_sqlite_cmd="timeout 8 sqlite3"; else __sa_sqlite_cmd="sqlite3"; fi')
        lines.append('      $__sa_sqlite_cmd -separator "$__sa_sep" "$__bc" "' + sql + '" >"$__sa_out" 2>/dev/null')
        lines.append('      __sa_rc=$?')
        lines.append('      if [ "$__sa_rc" = "0" ]; then')
        lines.append('        while IFS="$__sa_sep" read -r __tag __cnt __ts; do')
        lines.append(
            '          [ -n "$__tag" ] && printf "BROWSE\\t' + browser + '\\t%s\\t%s\\t%s\\t' + family + '\\n"'
            ' "$__tag" "$__cnt" "$__ts"'
        )
        lines.append('        done <"$__sa_out"')
        lines.append('      fi')
        lines.append('      rm -f "$__bc" "$__bc-wal" "$__sa_out" 2>/dev/null')
        lines.append('    done')
        lines.append('  fi')

    lines.append('fi')
    lines.append('rm -rf "$__sa_tmpdir" 2>/dev/null')
    lines.append('true')
    return '\n'.join(lines)


def _parse_browsing_probe(output):
    precise = {}
    if not output:
        return precise
    for line in output.splitlines():
        if line.startswith('BROWSE\t'):
            parts = line.split('\t')
            if len(parts) >= 6:
                browser, name, cnt, ts, family = parts[1], parts[2], parts[3], parts[4], parts[5]
                try:
                    cnt_i = int(float(cnt))
                except ValueError:
                    cnt_i = 0
                try:
                    # float() first: Safari's visit_time is a REAL column
                    # (fractional seconds), unlike Chromium/Firefox's integer
                    # microsecond columns. Sub-second precision doesn't
                    # matter for the day-level date string this feeds into.
                    ts_i = int(float(ts))
                except ValueError:
                    ts_i = 0
                key = (browser, name)
                if key not in precise:
                    precise[key] = [0, 0, family]
                precise[key][0] += cnt_i
                if ts_i > precise[key][1]:
                    precise[key][1] = ts_i
    return precise


def _timestamp_to_date_str(ts_micro, family):
    try:
        if family == 'chromium':
            dt = CHROMIUM_EPOCH + datetime.timedelta(microseconds=ts_micro)
        elif family == 'safari':
            # Mac absolute time: seconds (not microseconds) since 2001-01-01 UTC.
            dt = SAFARI_EPOCH + datetime.timedelta(seconds=ts_micro)
        else:
            dt = datetime.datetime.utcfromtimestamp(ts_micro / 1000000.0)
        return dt.strftime('%Y-%m-%d')
    except (OverflowError, ValueError, OSError):
        return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_scan(args, host, asset_id, atype):
    logging.info("Running shadow AI discovery for [%s]. This may take some time...", host['hostname'])

    sig_all = _load_signatures()
    family = os_family(atype)
    sig = sig_all.get(family, {})
    families = sig_all.get('public_model_families', [])

    config_issues = []
    products = []
    tags = []
    found_any = False

    logging.info("Scanning for AI desktop apps, CLI tools, IDE/browser extensions and locally stored AI models on [%s]", host['hostname'])
    fs_script = _build_fs_probe_script(sig)
    fs_out = utils.run_cmd_on_host(args, host, [fs_script], False)
    fs = _parse_fs_probe(fs_out)

    for a in fs['apps']:
        found_any = True
        products.append('%s (detected)' % a['product'])
        tags.append('SHADOW_AI:' + a['product'])
        config_issues.append(_issue(
            asset_id, _slug('app', a['product'], a['path']),
            'Shadow AI: %s (%s) detected' % (a['product'], a['category']),
            'Found at [%s].' % a['path'],
            RATING_INFO, object_id=a['path'],
        ))
    for c in fs['cli']:
        found_any = True
        ver_line = fs['cli_ver'].get(c['product'], '')
        ver_match = VERSION_RE.search(ver_line) if ver_line else None
        if ver_match:
            products.append('%s %s' % (c['product'], ver_match.group(0)))
        else:
            products.append('%s (detected)' % c['product'])
        tags.append('SHADOW_AI:' + c['product'])
        details = 'Binary [%s] found on PATH.' % c['bin']
        if ver_line:
            details += ' Version output: %s' % ver_line[:200]
        config_issues.append(_issue(
            asset_id, _slug('cli', c['product']),
            'Shadow AI: %s (%s) CLI available' % (c['product'], c['category']),
            details,
            RATING_INFO, object_id=c['bin'],
        ))

    ide_sig_by_id = {}
    for e in sig.get('ide_extensions', []):
        ide_sig_by_id[e['vscode_id'].lower()] = e
    seen_ext = set()
    for ext_dir in fs['ide_ext']:
        # VS Code extension dirs are named "<publisher>.<extension>-<version>";
        # capture the version so "github.copilot-chat-1.2.3" both identifies
        # as "github.copilot-chat" and reports version "1.2.3".
        ext_match = re.match(r'^(.*?)-(\d+(?:\.\d+)*)(?:-[a-zA-Z0-9]+)?$', ext_dir)
        if ext_match:
            ext_id = ext_match.group(1).lower()
            ext_version = ext_match.group(2)
        else:
            ext_id = ext_dir.lower()
            ext_version = None
        meta = ide_sig_by_id.get(ext_id)
        if meta is not None and ext_id not in seen_ext:
            seen_ext.add(ext_id)
            found_any = True
            if ext_version:
                products.append('%s %s' % (meta['product'], ext_version))
            else:
                products.append('%s (detected)' % meta['product'])
            tags.append('SHADOW_AI:' + meta['product'])
            config_issues.append(_issue(
                asset_id, _slug('ideext', meta['product']),
                'Shadow AI: %s (%s) installed' % (meta['product'], meta['category']),
                'VS Code extension directory [%s] found.' % ext_dir,
                RATING_INFO, object_id=ext_dir,
            ))

    browser_sig = {}
    for browser_map in sig.get('browser_extensions', {}).values():
        browser_sig.update(browser_map)
    seen_bext = set()
    for ext_id in fs['browser_ext']:
        name = browser_sig.get(ext_id)
        if name and ext_id not in seen_bext:
            seen_bext.add(ext_id)
            found_any = True
            tags.append('SHADOW_AI:' + name)
            config_issues.append(_issue(
                asset_id, _slug('browserext', name, ext_id),
                'Shadow AI: browser extension %s detected' % name,
                'Extension ID [%s] found in a browser profile.' % ext_id,
                RATING_INFO, object_id=ext_id,
            ))

    if getattr(args, 'shadow_ai_check_credentials', False):
        logging.info("Checking for presence of AI provider credentials on [%s] (values are not read)", host['hostname'])
        for v in fs['cred_env']:
            found_any = True
            config_issues.append(_issue(
                asset_id, _slug('credenv', v),
                'Shadow AI: AI provider credential env var set [%s]' % v,
                'Environment variable [%s] is set for this host/user. Value was not read.' % v,
                RATING_HIGH, object_id=v,
            ))
        for p in fs['cred_path']:
            found_any = True
            config_issues.append(_issue(
                asset_id, _slug('credpath', p),
                'Shadow AI: AI tool credential/config file present',
                'Path [%s] exists. Contents were not read.' % p,
                RATING_MEDIUM, object_id=p,
            ))

    # Models
    for m in fs['model_ollama']:
        model_name = _model_name_from_ollama_manifest_path(m['path'])
        cls, vendor = classify_model(model_name, families)
        found_any = True
        rating = RATING_MEDIUM if cls == 'custom' else RATING_INFO
        products.append('%s Model: %s' % (m['runtime'], model_name))
        tags.append('AI_MODEL:' + model_name)
        tags.append('AI_MODEL_CLASS:' + cls)
        details = 'Found via %s manifest at [%s].' % (m['runtime'], m['path'])
        if vendor:
            details += ' Matches known public model family (%s).' % vendor
        else:
            details += ' Does not match a known public model family - treat as custom/unreviewed.'
        config_issues.append(_issue(
            asset_id, _slug('model', m['runtime'], model_name),
            'Shadow AI: %s model [%s] present (%s)' % (m['runtime'], model_name, cls),
            details, rating, object_id=m['path'],
        ))

    for m in fs['model_hf']:
        model_name, org = _model_name_from_hf_dirname(m['dirname'])
        cls, vendor = classify_model(model_name, families)
        found_any = True
        rating = RATING_MEDIUM if cls == 'custom' else RATING_INFO
        products.append('%s Model: %s' % (m['runtime'], model_name))
        tags.append('AI_MODEL:' + model_name)
        tags.append('AI_MODEL_CLASS:' + cls)
        if cls == 'custom' and org:
            details = 'Found in Hugging Face cache. Publisher/org [%s] does not match a known public model family - treat as custom/unreviewed.' % org
        elif vendor:
            details = 'Found in Hugging Face cache. Matches known public model family (%s).' % vendor
        else:
            details = 'Found in Hugging Face cache.'
        config_issues.append(_issue(
            asset_id, _slug('model', m['runtime'], model_name),
            'Shadow AI: %s model [%s] present (%s)' % (m['runtime'], model_name, cls),
            details, rating, object_id=m['dirname'],
        ))

    for m in fs['model_glob']:
        fname = os.path.basename(m['path'])
        cls, vendor = classify_model(fname, families)
        found_any = True
        rating = RATING_MEDIUM if cls == 'custom' else RATING_INFO
        try:
            size_mb = int(m['size']) / (1024 * 1024)
            size_str = '%.1f MB' % size_mb
        except (ValueError, TypeError):
            size_str = 'unknown size'
        products.append('%s Model: %s' % (m['runtime'], fname))
        tags.append('AI_MODEL:' + fname)
        tags.append('AI_MODEL_CLASS:' + cls)
        details = 'Weight file at [%s] (%s).' % (m['path'], size_str)
        if vendor:
            details += ' Matches known public model family (%s).' % vendor
        else:
            details += ' Does not match a known public model family - treat as custom/unreviewed.'
        config_issues.append(_issue(
            asset_id, _slug('model', m['runtime'], fname),
            'Shadow AI: %s model file [%s] present (%s)' % (m['runtime'], fname, cls),
            details, rating, object_id=m['path'],
        ))

    # Processes and listening ports
    logging.info("Scanning running processes and listening ports on [%s] for local AI runtimes", host['hostname'])
    proc_port_out = utils.run_cmd_on_host(args, host, [_build_process_port_probe_script()], False)
    matched_procs, matched_ports = _parse_processes_and_ports(
        proc_port_out, sig.get('processes', []), sig.get('ports', [])
    )
    for p in matched_procs:
        found_any = True
        tags.append('SHADOW_AI:' + p['product'])
        config_issues.append(_issue(
            asset_id, _slug('proc', p['product']),
            'Shadow AI: %s (%s) running' % (p['product'], p['category']),
            'Matching process found: [%s]' % p['evidence'],
            RATING_MEDIUM, object_id=p['product'],
        ))
    for p in matched_ports:
        found_any = True
        tags.append('SHADOW_AI:' + p['product'])
        rating = RATING_HIGH if p['exposed'] else RATING_MEDIUM
        exposure_note = ' This port is bound to all interfaces (0.0.0.0), not just localhost - it may be reachable from the network.' if p['exposed'] else ' Bound to localhost.'
        config_issues.append(_issue(
            asset_id, _slug('port', p['product'], p['port']),
            'Shadow AI: %s listening on port %d' % (p['product'], p['port']),
            'Evidence: [%s].%s' % (p['evidence'], exposure_note),
            rating, object_id=str(p['port']),
        ))

    # Services
    svc_script = _build_service_probe_script(sig)
    if svc_script:
        logging.info("Checking for AI-related services on [%s]", host['hostname'])
        svc_out = utils.run_cmd_on_host(args, host, [svc_script], False)
        for s in _parse_services(svc_out):
            found_any = True
            tags.append('SHADOW_AI:' + s['product'])
            config_issues.append(_issue(
                asset_id, _slug('svc', s['product']),
                'Shadow AI: %s (%s) running as a service' % (s['product'], s['category']),
                'Active systemd unit [%s].' % s['unit'],
                RATING_MEDIUM, object_id=s['unit'],
            ))

    # Package manager SDK usage (opt-in, slower)
    if getattr(args, 'shadow_ai_check_packages', False):
        logging.info("Scanning pip/npm/gem package listings on [%s] for AI SDK dependencies. This may take some time...", host['hostname'])
        pkg_out = utils.run_cmd_on_host(args, host, [_build_package_probe_script(sig)], False)
        for pkg in _parse_packages(pkg_out, sig.get('packages', {})):
            found_any = True
            display = ('%s %s' % (pkg['name'], pkg['version'])).strip()
            products.append(display)
            config_issues.append(_issue(
                asset_id, _slug('pkg', pkg['ecosystem'], pkg['name']),
                'Shadow AI: AI SDK dependency installed [%s]' % display,
                'Found via %s package listing.' % pkg['ecosystem'],
                RATING_INFO, object_id=display,
            ))

    # Browser history (opt-in, separate from credentials/packages given its
    # sensitivity). Domain + visit count + last-visit date only.
    if getattr(args, 'shadow_ai_check_browsing', False):
        logging.info(
            "Scanning browser history on [%s] for visits to known AI chat sites "
            "(domain-level only - no URLs or page content are read)", host['hostname']
        )
        sig_all = _load_signatures()
        browse_out = utils.run_cmd_on_host(args, host, [_build_browsing_probe_script(sig_all, sig)], False)
        precise = _parse_browsing_probe(browse_out)
        for (browser, name), (total_cnt, max_ts, family) in precise.items():
            found_any = True
            tags.append('SHADOW_AI:' + name)
            date_str = _timestamp_to_date_str(max_ts, family)
            details = 'Detected via %s browsing history: %d visit(s)' % (browser, total_cnt)
            if date_str:
                details += ', last visit %s' % date_str
            details += '. Only the domain and visit metadata were read - no URLs, search queries, or page content.'
            config_issues.append(_issue(
                asset_id, _slug('browse', browser, name),
                'Shadow AI: browsing activity to %s detected (%s)' % (name, browser),
                details, RATING_MEDIUM, object_id=name,
            ))

    if found_any:
        tags.append('Shadow AI')

    # de-duplicate tags while preserving order
    seen = set()
    unique_tags = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            unique_tags.append(t)

    logging.info("Completed shadow AI discovery for [%s]. Found %d finding(s)", host['hostname'], len(config_issues))

    return config_issues, products, unique_tags
