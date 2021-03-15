#!/bin/bash

# Build script for twigs droplet for DigitalOcean
# Tested only on Ubuntu 20.04 LTS
# Install all components required by twigs including dependencies and most plugins except
# ones for DAST support

apt-get -y update
apt-get -y upgrade

# Setup gcloud sdk
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get install -y apt-transport-https ca-certificates gnupg
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
apt-get -y update && sudo apt-get install -y google-cloud-sdk

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

# Setup crontab for automatic upgrades of twigs components
printf "0 1 * * 0 /usr/local/bin/twigs-update.sh\n" | crontab -

# Setup twigs update systemd service
printf "[Unit]\nAfter=network.service\n[Service]\nExecStart=/usr/local/bin/twigs-update.sh\n[Install]\nWantedBy=default.target\n" > /etc/systemd/system/twigs-update.service
chmod 664 /etc/systemd/system/twigs-update.service
systemctl enable twigs-update

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

# Setup ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# Replace motd
cp -f motd /etc/motd
chmod 600 /etc/update-motd.d/*

# Clear logs
> /var/log/alternatives.log
> /var/log/auth.log
> /var/log/cloud-init-output.log
> /var/log/cloud-init.log
> /var/log/dpkg.log
> /var/log/kern.log
> /var/log/ufw.log
> /var/log/cloud-init.log
> /var/log/unattended-upgrades/unattended-upgrades-shutdown.log
