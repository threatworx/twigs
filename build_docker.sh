#!/bin/bash

# Build script for twigs docker image
# Tested only on Ubuntu 20.04 LTS
# Install all components required by twigs including dependencies and most plugins except
# ones for DAST support

echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
apt-get -y update
apt-get -y upgrade
apt-get -y install dialog apt-utils wget

#install nmap
apt-get -y install nmap

# Setup gcloud sdk
apt-get -y install curl
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get install -y apt-transport-https ca-certificates gnupg
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
apt-get -y update && apt-get install -y google-cloud-sdk

# Install AZ Cli
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
/usr/bin/az extension add --name account
/usr/bin/az extension add --name log-analytics


# Link python3 as default python
ln -fs /usr/bin/python3 /usr/bin/python

# Get pip for python3
apt-get install -y python3-pip

# Link pip
ln -fs /usr/bin/pip3 /usr/bin/pip

rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL

# Install twigs and related packages
pip install twigs
rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL
pip install twigs_host_benchmark
pip install twigs_ssl_audit
rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL

# Setup twigs update script
printf "#!/bin/bash\n/usr/bin/pip install --upgrade twigs\n/usr/bin/pip install --upgrade twigs_host_benchmark\n/usr/bin/pip install twigs_ssl_audit --upgrade\n" > /usr/local/bin/twigs-update.sh

chmod 755 /usr/local/bin/twigs-update.sh

# Install git
apt-get install -y git

# Install grep
wget -O /usr/local/bin/opengrep https://github.com/opengrep/opengrep/releases/download/v1.1.2/opengrep_manylinux_x86 
chmod +x /usr/local/bin/opengrep

# Install checkov 
pip install checkov 

# Install docker
apt-get install -y docker.io

# Install prereqs for prowler
pip install awscli detect-secrets
# Prowler launches AWS CLI and this could be from cron
ln -s /usr/local/bin/aws /usr/bin/aws

# Clone prowler repo
rm -rf /usr/share/prowler
apt-get install -y jq
git clone --depth 1 --branch 2.12.1 https://github.com/prowler-cloud/prowler.git /usr/share/prowler

# Clone docker bench repo
rm -rf /usr/share/docker-bench-security
git clone https://github.com/docker/docker-bench-security.git /usr/share/docker-bench-security

# Setup PROWLER_HOME in bashrc
if ! grep -q "PROWLER_HOME" $HOME/.bashrc
then
    printf "\nexport PROWLER_HOME=/usr/share/prowler\n" >> $HOME/.bashrc
fi

# Replace motd
cp -f /tmp/motd /etc/motd
chmod 600 /etc/update-motd.d/*

# install dnsutils for dig etc. required by ssl audit
apt-get install dnsutils -y

# install bsdutils for hexdump required by ssl audit
apt-get install bsdmainutils -y

# install jdk
apt-get install openjdk-17-jdk -y

# install zaproxy
wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.0/ZAP_2.16.0_Linux.tar.gz -P /tmp
tar -xvzf /tmp/ZAP_2.16.0_Linux.tar.gz -C /usr/share
ln -s /usr/share/ZAP_2.16.0/zap.sh /usr/bin/zaproxy

# Cleanup /tmp
rm -rf /tmp/*
