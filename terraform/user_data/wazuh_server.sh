#!/bin/bash
set -e

# Update system
echo "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install prerequisites
apt-get install -y curl tar

# Download Wazuh installation script
echo "Downloading Wazuh installation script..."
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Run Wazuh all-in-one installation
echo "Installing Wazuh (this takes ~10 minutes)..."
bash wazuh-install.sh --all-in-one -i

# Save credentials
echo "Saving installation files..."
tar -xvf wazuh-install-files.tar

# Enable and start services
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Install CloudWatch agent (optional for monitoring)
echo "Installing CloudWatch agent..."
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

# Create completion marker
echo "Wazuh installation complete!" > /tmp/wazuh-install-complete.txt

# Log system info
echo "==================================" >> /var/log/wazuh-install.log
echo "Wazuh Installation Complete" >> /var/log/wazuh-install.log
echo "Timestamp: $(date)" >> /var/log/wazuh-install.log
echo "Public IP: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)" >> /var/log/wazuh-install.log
echo "Dashboard URL: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)" >> /var/log/wazuh-install.log
echo "Credentials file: /home/ubuntu/wazuh-install-files.tar" >> /var/log/wazuh-install.log
echo "==================================" >> /var/log/wazuh-install.log

echo "Wazuh installation complete!"
echo "Access dashboard at: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "Retrieve credentials with: sudo tar -xvf wazuh-install-files.tar && sudo cat wazuh-install-files/wazuh-passwords.txt"
