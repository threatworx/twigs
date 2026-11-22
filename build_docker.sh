#!/bin/bash

# Build script for twigs docker image
# Targets Ubuntu 24.04 LTS (Python 3.12). Also runs on Ubuntu 20.04 LTS (Python 3.8).
#
# Set TWIGS_PIP_SPEC to install twigs from somewhere other than PyPI, e.g. a
# locally built wheel (TWIGS_PIP_SPEC=/tmp/twigs-1.3.25-py3-none-any.whl).
# Install all components required by twigs including dependencies and most plugins except
# ones for DAST support

set -euo pipefail

# Fail loudly with the line number of whatever broke instead of silently
# producing a half-built image.
trap 'echo "ERROR: build_docker.sh failed at line ${LINENO}" >&2' ERR

export DEBIAN_FRONTEND=noninteractive

# Retry a command a few times - most transient failures here are network blips
# (apt mirrors, GitHub releases, pip index).
retry() {
    local n=1 max=3 delay=5
    while true; do
        "$@" && return 0
        if [ "$n" -ge "$max" ]; then
            echo "ERROR: command failed after ${n} attempts: $*" >&2
            return 1
        fi
        echo "WARN: attempt ${n} failed: $* -- retrying in ${delay}s" >&2
        n=$((n + 1))
        sleep "$delay"
    done
}

apt_get() { retry apt-get -y "$@"; }
apt_install() { retry apt-get -y install "$@"; }

# Verify that an expected binary landed on PATH; abort the build otherwise.
require_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: expected '$1' to be installed but it is not on PATH" >&2
        exit 1
    fi
    echo "OK: found $1 -> $(command -v "$1")"
}

echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
apt_get update
apt_get upgrade
apt_install dialog apt-utils wget

#install nmap
apt_install nmap
#install snmpwalk
apt_install snmp

# Setup gcloud sdk
apt_install curl
apt_install apt-transport-https ca-certificates gnupg
# NOTE: Google dropped the legacy transitional 'google-cloud-sdk' package name
# from the apt repo; the package is now 'google-cloud-cli' (still ships the
# gcloud/gsutil/bq binaries). Installing the old name here fails with
# "Unable to locate package" and, without set -e, used to leave the image with
# no gcloud at all.
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list
retry curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor --yes -o /usr/share/keyrings/cloud.google.gpg
apt_get update
apt_install google-cloud-cli

# Install AZ Cli
retry curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash
retry /usr/bin/az extension add --name account
retry /usr/bin/az extension add --name log-analytics
retry /usr/bin/az extension add --name connectedmachine


# Link python3 as default python
ln -fs /usr/bin/python3 /usr/bin/python

# Get pip for python3
apt_install python3-pip

# This image is dedicated to twigs, so install Python packages system-wide
# instead of in a virtualenv. Ubuntu 23.04+ blocks system-wide pip installs
# (PEP 668); removing the marker lifts that for pip run from anywhere,
# including twigs-update.sh under cron.
rm -f /usr/lib/python3*/EXTERNALLY-MANAGED

# pip 20.0 shipped with Ubuntu 20.04 has the legacy resolver, which leaves
# conflicting dependency versions behind. Newer Ubuntu releases ship a recent pip.
if python3 -c 'import sys; sys.exit(0 if sys.version_info < (3, 10) else 1)'; then
    retry python3 -m pip install --upgrade pip
fi

# Link pip to whichever pip python3 now uses
cat > /usr/bin/pip <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -m pip "$@"
EOF
chmod 755 /usr/bin/pip

# Install git
apt_install git

# Install grep
retry wget -O /usr/local/bin/opengrep https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_manylinux_x86
chmod +x /usr/local/bin/opengrep

# Install docker
apt_install docker.io

# Clone prowler repo
rm -rf /usr/share/prowler
apt_install jq
retry git clone --depth 1 --branch 2.12.1 https://github.com/prowler-cloud/prowler.git /usr/share/prowler

# Clone docker bench repo
rm -rf /usr/share/docker-bench-security
retry git clone https://github.com/docker/docker-bench-security.git /usr/share/docker-bench-security

# Setup PROWLER_HOME in bashrc
if ! grep -q "PROWLER_HOME" "$HOME/.bashrc"; then
    printf "\nexport PROWLER_HOME=/usr/share/prowler\n" >> "$HOME/.bashrc"
fi

# install trufflehog
retry curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Replace motd
cp -f /tmp/motd /etc/motd
# glob can be empty on a minimal image - do not let that abort the build
if compgen -G "/etc/update-motd.d/*" > /dev/null; then
    chmod 600 /etc/update-motd.d/*
fi

# install dnsutils for dig etc. required by ssl audit
apt_install dnsutils

# install bsdutils for hexdump required by ssl audit
apt_install bsdmainutils

# install sqlite3 CLI for shadow AI browser-history detection (host mode,
# --shadow_ai_check_browsing). Without it that check is skipped entirely
# (no lower-fidelity fallback is reported) rather than failing the scan.
apt_install sqlite3

# install jdk
apt_install openjdk-17-jdk

# install zaproxy
retry wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.0/ZAP_2.16.0_Linux.tar.gz -P /tmp
tar -xzf /tmp/ZAP_2.16.0_Linux.tar.gz -C /usr/share
ln -fs /usr/share/ZAP_2.16.0/zap.sh /usr/bin/zaproxy

# install Zeek (LTS) and the CISA ICSNPP protocol packages for passive
# discovery of medical / OT / building / IoT devices (twigs passive). The
# compiler tools are needed to build the ICSNPP plugins and the twigs DICOM /
# HL7 Spicy parsers. The Zeek project publishes packages for Ubuntu 22.04+.
. /etc/os-release
ZEEK_REPO="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}"
if curl -fsI "${ZEEK_REPO}/Release.key" > /dev/null 2>&1; then
    echo "deb ${ZEEK_REPO}/ /" > /etc/apt/sources.list.d/security:zeek.list
    retry curl -fsSL "${ZEEK_REPO}/Release.key" | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/security_zeek.gpg
    apt_get update
    apt_install zeek-lts g++ cmake make libpcap-dev
    ln -fs /opt/zeek/bin/zeek /usr/local/bin/zeek
    ln -fs /opt/zeek/bin/zkg /usr/local/bin/zkg
    /opt/zeek/bin/zkg autoconfig --force
    retry /opt/zeek/bin/zkg install --force --skiptests icsnpp-bacnet icsnpp-modbus icsnpp-enip icsnpp-s7comm
    ZEEK_INSTALLED=1
else
    echo "WARN: no Zeek packages for Ubuntu ${VERSION_ID}; twigs passive will not be available in this image" >&2
    ZEEK_INSTALLED=0
fi

# install unzip (needed to unpack the nuclei release archive)
apt_install unzip

# install Go (latest stable release, official linux-amd64 tarball)
# sed (not head) so the upstream curl is not killed by SIGPIPE under pipefail
GO_VERSION=$(retry curl -fsSL 'https://go.dev/VERSION?m=text' | sed -n '1p')
if [ -z "$GO_VERSION" ]; then
    echo "ERROR: could not determine latest Go version" >&2
    exit 1
fi
retry wget -q "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm -f /tmp/go.tar.gz
ln -fs /usr/local/go/bin/go /usr/local/bin/go
ln -fs /usr/local/go/bin/gofmt /usr/local/bin/gofmt
if ! grep -q "/usr/local/go/bin" "$HOME/.bashrc"; then
    printf "\nexport PATH=\$PATH:/usr/local/go/bin\n" >> "$HOME/.bashrc"
fi

# install nuclei (latest release, official linux-amd64 zip) - used by twigs EASM web application testing
NUCLEI_TAG=$(retry curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name')
NUCLEI_VERSION=${NUCLEI_TAG#v}
if [ -z "$NUCLEI_VERSION" ] || [ "$NUCLEI_VERSION" = "null" ]; then
    echo "ERROR: could not determine latest nuclei version" >&2
    exit 1
fi
retry wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_TAG}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip
unzip -o /tmp/nuclei.zip -d /tmp/nuclei
install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei
rm -rf /tmp/nuclei /tmp/nuclei.zip
# pre-fetch nuclei templates so the first EASM run does not have to
# (non-fatal - templates are also fetched on first real run)
/usr/local/bin/nuclei -update-templates || true

# Install twigs together with the Python tools it drives (checkov for IaC,
# awscli and detect-secrets for prowler) in a single pip run, so that pip
# resolves one consistent set of dependency versions. Installing them in
# separate runs lets a later install silently break an earlier one.
TWIGS_PIP_SPEC=${TWIGS_PIP_SPEC:-twigs}
retry python3 -m pip install "$TWIGS_PIP_SPEC" checkov awscli detect-secrets
python3 -m pip check
# Prowler launches AWS CLI and this could be from cron
ln -fs /usr/local/bin/aws /usr/bin/aws

# Record the resolved Python package versions shipped in this image
mkdir -p /usr/local/share/twigs
python3 -m pip freeze > /usr/local/share/twigs/pip-freeze.txt

# Setup twigs update script
cat > /usr/local/bin/twigs-update.sh <<'EOF'
#!/bin/bash
/usr/bin/python3 -m pip install --upgrade twigs
EOF

chmod 755 /usr/local/bin/twigs-update.sh

# Verify the critical tooling actually made it into the image before we ship it.
echo "--- verifying installed tooling ---"
require_bin gcloud
require_bin az
require_bin nmap
require_bin snmpwalk
require_bin opengrep
require_bin checkov
require_bin docker
require_bin aws
require_bin jq
require_bin trufflehog
require_bin dig
require_bin hexdump
require_bin sqlite3
require_bin java
require_bin zaproxy
require_bin go
require_bin nuclei
if [ "$ZEEK_INSTALLED" = 1 ]; then
    require_bin zeek
    require_bin zkg
    for p in icsnpp-bacnet icsnpp-modbus icsnpp-enip icsnpp-s7comm; do
        if ! /opt/zeek/bin/zkg list installed | grep -q "/$p "; then
            echo "ERROR: Zeek package $p is not installed" >&2
            exit 1
        fi
    done
fi
require_bin twigs
if [ ! -x /usr/share/prowler/prowler ]; then
    echo "ERROR: prowler not found at /usr/share/prowler/prowler" >&2
    exit 1
fi
echo "--- all required tooling present ---"

# Smoke test: every twigs module must import and the CLI must start
echo "--- twigs smoke test ---"
python3 - <<'EOF'
import importlib, pkgutil, sys
import twigs
failed = []
for m in pkgutil.walk_packages(twigs.__path__, 'twigs.'):
    try:
        importlib.import_module(m.name)
    except Exception as e:
        failed.append("%s: %r" % (m.name, e))
for f in failed:
    print("FAILED to import " + f)
sys.exit(1 if failed else 0)
EOF
twigs --version
twigs --help > /dev/null
echo "--- twigs smoke test passed ---"

# Bundle the current IEEE MAC address registry (MA-L, MA-M and MA-S) for
# passive discovery's MAC vendor lookups; nmap's copy can be years old.
# twigs uses /usr/local/share/twigs/oui.txt before any other OUI database.
echo "--- building IEEE OUI database ---"
OUI_TMP=$(mktemp -d)
for reg in oui/oui.csv oui28/mam.csv oui36/oui36.csv; do
    retry curl -fsSL -A "twigs-build" -o "$OUI_TMP/$(basename $reg)" "https://standards-oui.ieee.org/$reg"
done
mkdir -p /usr/local/share/twigs
python3 -m twigs.passive.oui build /usr/local/share/twigs/oui.txt "$OUI_TMP/oui.csv" "$OUI_TMP/mam.csv" "$OUI_TMP/oui36.csv"
rm -rf "$OUI_TMP"
python3 - <<'EOF'
import sys
from twigs.passive.oui import OUILookup, BUNDLED_OUI_FILE
lookup = OUILookup()
if lookup.source != BUNDLED_OUI_FILE:
    sys.exit("ERROR: twigs is not using the bundled IEEE OUI database (using %s)" % lookup.source)
print("OK: twigs uses %s (%d prefixes)" % (BUNDLED_OUI_FILE, sum(len(t) for t in lookup.prefixes.values())))
EOF

# Precompile the twigs DICOM / HL7 Zeek parsers so containers do not have to
# (twigs looks in /var/cache/twigs/passive before compiling its own copy).
if [ "$ZEEK_INSTALLED" = 1 ]; then
    echo "--- compiling twigs passive DICOM / HL7 parsers ---"
    python3 -c 'import sys; from twigs.passive.zeek_runner import Zeek, SYSTEM_CACHE_DIR; sys.exit(0 if Zeek(cache_dir=SYSTEM_CACHE_DIR).medical_analyzers() else 1)'
fi

# Cleanup /tmp
rm -rf /tmp/*
