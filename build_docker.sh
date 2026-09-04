#!/bin/bash

# Build script for twigs docker image
# Tested only on Ubuntu 20.04 LTS
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

# Link pip
ln -fs /usr/bin/pip3 /usr/bin/pip

rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL

# Install git
apt_install git

# Install grep
retry wget -O /usr/local/bin/opengrep https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_manylinux_x86
chmod +x /usr/local/bin/opengrep

# Install checkov
retry pip install checkov

# Install docker
apt_install docker.io

# Install prereqs for prowler
retry pip install awscli detect-secrets
# Prowler launches AWS CLI and this could be from cron
ln -fs /usr/local/bin/aws /usr/bin/aws

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

# install jdk
apt_install openjdk-17-jdk

# install zaproxy
retry wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.0/ZAP_2.16.0_Linux.tar.gz -P /tmp
tar -xzf /tmp/ZAP_2.16.0_Linux.tar.gz -C /usr/share
ln -fs /usr/share/ZAP_2.16.0/zap.sh /usr/bin/zaproxy

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

# Install twigs and related packages
retry pip install twigs
rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL
retry pip install twigs_host_benchmark
retry pip install twigs_ssl_audit
rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL

# Setup twigs update script
printf "#!/bin/bash\n/usr/bin/pip install --upgrade twigs\n/usr/bin/pip install --upgrade twigs_host_benchmark\n/usr/bin/pip install twigs_ssl_audit --upgrade\n" > /usr/local/bin/twigs-update.sh

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
require_bin java
require_bin zaproxy
require_bin go
require_bin nuclei
require_bin twigs
echo "--- all required tooling present ---"

# Cleanup /tmp
rm -rf /tmp/*
