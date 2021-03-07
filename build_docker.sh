#!/bin/bash

# Build script for twigs docker image
# Tested only on Ubuntu 20.04 LTS
# Install all components required by twigs including dependencies and most plugins except
# ones for DAST support

echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
apt-get -y update
apt-get -y upgrade
apt-get -y install dialog apt-utils

# Setup gcloud sdk
apt-get -y install curl
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get install -y apt-transport-https ca-certificates gnupg
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
apt-get -y update && apt-get install -y google-cloud-sdk

# Link python3 as default python
ln -fs /usr/bin/python3 /usr/bin/python

# Get pip for python3
apt-get install -y python3-pip

# Link pip
ln -fs /usr/bin/pip3 /usr/bin/pip

# Install twigs and related packages
pip install twigs
pip install twigs_host_benchmark
pip install twigs_ssl_audit

# Setup twigs update script
printf "#!/bin/bash\n/usr/bin/pip install --upgrade twigs\n/usr/bin/pip install --upgrade twigs_host_benchmark\n/usr/bin/pip install twigs_ssl_audit --upgrade\n" > /usr/local/bin/twigs-update.sh

chmod 755 /usr/local/bin/twigs-update.sh

# Install semgrep
pip install semgrep

# Install docker
apt-get install -y docker.io

# Install prereqs for prowler
pip install awscli detect-secrets

# Clone prowler repo
rm -rf /usr/share/prowler
git clone https://github.com/toniblyx/prowler /usr/share/prowler

# Setup PROWLER_HOME in bashrc
if ! grep -q "PROWLER_HOME" $HOME/.bashrc
then
    printf "\nexport PROWLER_HOME=/usr/share/prowler\n" >> $HOME/.bashrc
fi

# Setup one-time login script
rm -rf /opt/threatwatch
mkdir -p /opt/threatwatch
printf "#!/bin/bash\n\nif [ ! -f '$HOME/.tw/auth.json' ];then\n    /usr/local/bin/twigs login\nfi\n" > /opt/threatwatch/twigs-login.sh
chmod 755 /opt/threatwatch/twigs-login.sh

# Setup login script in bashrc
if ! grep -q "twigs-login.sh" $HOME/.bashrc
then
    printf "\n/opt/threatwatch/twigs-login.sh\n" >> $HOME/.bashrc
fi

# Replace motd
cp -f /tmp/motd /etc/motd
chmod 600 /etc/update-motd.d/*

# Cleanup /tmp
rm -f /tmp/*

