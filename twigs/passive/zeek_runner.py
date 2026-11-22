"""Locate Zeek, build the twigs analyzers and run Zeek over pcaps or an interface."""

import glob
import hashlib
import logging
import os
import shutil
import signal
import subprocess
import tempfile

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
ZEEK_SCRIPT_DIR = os.path.join(PKG_DIR, 'zeek')
MAIN_SCRIPT = os.path.join(ZEEK_SCRIPT_DIR, 'twigs_passive.zeek')
MEDICAL_DIR = os.path.join(ZEEK_SCRIPT_DIR, 'medical')
MEDICAL_SOURCES = ['dicom.spicy', 'hl7.spicy', 'medical.evt']

DEFAULT_ZEEK_LOCATIONS = ['/opt/zeek/bin/zeek', '/usr/local/zeek/bin/zeek', '/usr/bin/zeek']
# Analyzers precompiled at install time (e.g. in the twigs Docker image).
SYSTEM_CACHE_DIR = '/var/cache/twigs/passive'


class ZeekError(Exception):
    pass


class Zeek(object):
    def __init__(self, zeek_path=None, cache_dir=None):
        self.zeek = self._find_zeek(zeek_path)
        self.bin_dir = os.path.dirname(self.zeek)
        self.version = self._run_quiet([self.zeek, '--version']).split()[-1]
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser('~'), '.cache', 'twigs', 'passive')
        self.plugin_dirs = []
        self.packages = self._find_packages()

    # ------------------------------------------------------------ discovery
    @staticmethod
    def _find_zeek(zeek_path):
        candidates = []
        if zeek_path:
            candidates.append(os.path.join(zeek_path, 'zeek') if os.path.isdir(zeek_path) else zeek_path)
        else:
            found = shutil.which('zeek')
            if found:
                candidates.append(found)
            candidates.extend(DEFAULT_ZEEK_LOCATIONS)
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return os.path.realpath(c)
        raise ZeekError("Zeek not found. Install Zeek (see twigs/passive/README.md) or use --zeek_path")

    @staticmethod
    def _run_quiet(cmd):
        try:
            return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', 'replace').strip()
        except (OSError, subprocess.CalledProcessError) as e:
            raise ZeekError("Unable to run %s: %s" % (cmd[0], e))

    def _zeek_config(self, option):
        zc = os.path.join(self.bin_dir, 'zeek-config')
        if not os.path.isfile(zc):
            return None
        try:
            return self._run_quiet([zc, option])
        except ZeekError:
            return None

    def _find_packages(self):
        """Zeek packages installed with zkg, system-wide or per user.

        Each package is loaded by absolute path so that a broken site
        local.zeek (or packages that are referenced but not installed) never
        stops twigs from running.
        """
        script_dirs = []
        site_dir = self._zeek_config('--site_dir')
        if site_dir:
            script_dirs.append(os.path.join(site_dir, 'packages'))
        # ZEEK_PLUGIN_PATH replaces Zeek's default plugin path, so the system
        # plugin directory has to be listed explicitly next to the user one.
        plugin_dir = self._zeek_config('--plugin_dir')
        if plugin_dir:
            self.plugin_dirs.append(plugin_dir)
        user_zkg = os.path.join(os.path.expanduser('~'), '.zkg')
        script_dirs.append(os.path.join(user_zkg, 'script_dir', 'packages'))
        self.plugin_dirs.append(os.path.join(user_zkg, 'plugin_dir', 'packages'))
        packages = {}
        for d in script_dirs:
            for p in sorted(glob.glob(os.path.join(d, '*', '__load__.zeek'))):
                name = os.path.basename(os.path.dirname(p))
                packages.setdefault(name, os.path.dirname(p))
        return packages

    def spicyz(self):
        p = os.path.join(self.bin_dir, 'spicyz')
        return p if os.path.isfile(p) else shutil.which('spicyz')

    # ---------------------------------------------------- medical analyzers
    def medical_analyzers(self):
        """Compile (once) and return the path of the DICOM / HL7 Spicy analyzers.

        Returns None if Spicy is not available; discovery then falls back to
        port-based detection for DICOM and HL7.
        """
        h = hashlib.sha256(self.version.encode())
        for f in MEDICAL_SOURCES:
            with open(os.path.join(MEDICAL_DIR, f), 'rb') as fh:
                h.update(fh.read())
        name = 'twigs-medical-%s.hlto' % h.hexdigest()[:16]
        for d in (self.cache_dir, SYSTEM_CACHE_DIR):
            if os.path.isfile(os.path.join(d, name)):
                return os.path.join(d, name)
        hlto = os.path.join(self.cache_dir, name)
        spicyz = self.spicyz()
        if not spicyz:
            logging.warning("spicyz not found: DICOM and HL7 identity parsing is disabled (port based detection only)")
            return None
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except OSError as e:
            logging.warning("Cannot create %s (%s): DICOM and HL7 identity parsing is disabled", self.cache_dir, e)
            return None
        logging.info("Compiling DICOM / HL7 analyzers (one time, takes about a minute)")
        # spicyz picks the output type from the extension, so keep '.hlto'.
        tmp = hlto[:-len('.hlto')] + '.tmp-%d.hlto' % os.getpid()
        cmd = [spicyz, '-o', tmp] + [os.path.join(MEDICAL_DIR, f) for f in MEDICAL_SOURCES]
        try:
            # spicyz writes scratch files into its working directory.
            out = subprocess.run(cmd, cwd=self.cache_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError as e:
            logging.warning("Unable to run spicyz: %s", e)
            return None
        if out.returncode != 0 or not os.path.isfile(tmp):
            logging.warning("Failed to compile DICOM / HL7 analyzers, continuing without them: %s",
                            out.stdout.decode('utf-8', 'replace').strip()[-1000:])
            return None
        os.replace(tmp, hlto)
        return hlto

    # ------------------------------------------------------------- running
    def _write_loader(self, work_dir, medical, extra_scripts, rotation=0):
        lines = ['@load %s' % MAIN_SCRIPT]
        for name in sorted(self.packages):
            lines.append('@load %s' % self.packages[name])
        if medical:
            lines.append('@load %s' % os.path.join(MEDICAL_DIR, 'medical.zeek'))
        for s in extra_scripts or []:
            lines.append('@load %s' % os.path.abspath(s))
        lines += [
            'redef LogAscii::use_json = T;',
            'redef Log::default_rotation_interval = %d secs;' % rotation,
            'redef ignore_checksums = T;',
        ]
        path = os.path.join(work_dir, 'twigs_loader.zeek')
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        return path

    def _env(self):
        env = dict(os.environ)
        dirs = [d for d in self.plugin_dirs if os.path.isdir(d)]
        if env.get('ZEEK_PLUGIN_PATH'):
            dirs.append(env['ZEEK_PLUGIN_PATH'])
        if dirs:
            env['ZEEK_PLUGIN_PATH'] = ':'.join(dirs)
        return env

    def _command(self, work_dir, extra_scripts, rotation=0):
        medical = self.medical_analyzers()
        loader = self._write_loader(work_dir, medical is not None, extra_scripts, rotation)
        cmd = [self.zeek, '-C']
        return cmd, ([medical] if medical else []) + [loader]

    def run_pcaps(self, pcaps, work_root, extra_scripts=None, bpf=None):
        """Run Zeek over each pcap. Returns the list of log directories."""
        log_dirs = []
        for i, pcap in enumerate(pcaps):
            pcap = os.path.abspath(pcap)
            if not os.path.isfile(pcap):
                raise ZeekError("pcap not found: %s" % pcap)
            wd = os.path.join(work_root, 'pcap-%03d' % i)
            os.makedirs(wd, exist_ok=True)
            cmd, scripts = self._command(wd, extra_scripts)
            cmd += ['-r', pcap]
            if bpf:
                cmd += ['-f', bpf]
            cmd += scripts
            logging.info("Running Zeek over %s", pcap)
            logging.debug("Zeek command: %s", ' '.join(cmd))
            res = subprocess.run(cmd, cwd=wd, env=self._env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = res.stdout.decode('utf-8', 'replace')
            if res.returncode != 0:
                # A truncated capture still yields logs for the packets that were read.
                if 'truncated dump file' in output or 'failed to read a packet' in output:
                    logging.warning("pcap %s is truncated, using the packets read before the error", pcap)
                else:
                    raise ZeekError("Zeek failed on %s: %s" % (pcap, output.strip()[-2000:]))
            elif output.strip():
                logging.debug("Zeek output for %s: %s", pcap, output.strip()[-2000:])
            log_dirs.append(wd)
        return log_dirs

    def start_live(self, interface, work_dir, extra_scripts=None, bpf=None, rotation=0):
        """Start Zeek on an interface. rotation > 0 rotates the logs every that many seconds.

        Returns the running process; its output goes to zeek_stdout.log in work_dir.
        """
        os.makedirs(work_dir, exist_ok=True)
        cmd, scripts = self._command(work_dir, extra_scripts, rotation)
        cmd += ['-i', interface]
        if bpf:
            cmd += ['-f', bpf]
        cmd += scripts
        logging.debug("Zeek command: %s", ' '.join(cmd))
        out = open(os.path.join(work_dir, 'zeek_stdout.log'), 'a')
        try:
            return subprocess.Popen(cmd, cwd=work_dir, env=self._env(), stdout=out, stderr=subprocess.STDOUT)
        finally:
            out.close()

    @staticmethod
    def stop(proc):
        """Stop Zeek; SIGTERM makes it flush and close its logs."""
        if proc.poll() is not None:
            return
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    @staticmethod
    def output(work_dir):
        try:
            with open(os.path.join(work_dir, 'zeek_stdout.log')) as fh:
                return fh.read().strip()[-2000:]
        except OSError:
            return ''

    def run_live(self, interface, duration, work_root, extra_scripts=None, bpf=None):
        """Capture on an interface for duration seconds. Returns the log directory."""
        wd = os.path.join(work_root, 'live')
        logging.info("Listening on %s for %d seconds", interface, duration)
        proc = self.start_live(interface, wd, extra_scripts, bpf)
        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            self.stop(proc)
        else:
            raise ZeekError("Zeek exited early on %s: %s" % (interface, self.output(wd)))
        return wd

def new_work_dir(base=None):
    if base:
        os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix='twigs_passive_', dir=base)
