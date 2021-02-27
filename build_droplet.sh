#!/bin/bash

# Build script for twigs droplet for DigitalOcean
# Tested only on Ubuntu 20.04 LTS
# Install all components required by twigs including dependencies and most plugins except
# ones for DAST support

apt-get -y update
apt-get -y upgrade

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
