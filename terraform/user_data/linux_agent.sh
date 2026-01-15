#!/bin/bash
set -e

# Variables from Terraform
WAZUH_MANAGER_IP="${wazuh_server_ip}"

# Update system
echo "Updating system packages..."
apt-get update && apt-get upgrade -y

# Wait for Wazuh server to be ready (installation takes ~10 minutes)
echo "Waiting for Wazuh server to be ready..."
sleep 120

# Install Wazuh agent
echo "Installing Wazuh agent..."
curl -so wazuh-agent-4.7.2.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.2-1_amd64.deb
WAZUH_MANAGER="$WAZUH_MANAGER_IP" dpkg -i wazuh-agent-4.7.2.deb

# Enable and start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Install auditd for advanced monitoring
echo "Installing auditd..."
apt-get install -y auditd audispd-plugins

# Basic auditd rules
cat > /etc/audit/rules.d/wazuh.rules <<EOF
# Monitor identity changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation

# Monitor SSH activity
-w /var/log/auth.log -p wa -k ssh_activity
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor suspicious commands
-w /usr/bin/curl -p x -k suspicious_network
-w /usr/bin/wget -p x -k suspicious_network
-w /usr/bin/nc -p x -k suspicious_network

# Monitor privilege escalation
-w /usr/bin/sudo -p x -k privilege_command
-w /bin/su -p x -k privilege_command
EOF

# Apply auditd rules
augenrules --load
systemctl restart auditd

echo "Wazuh agent installed and connected to $WAZUH_MANAGER_IP"
echo "Agent installation complete!" > /tmp/wazuh-agent-install-complete.txt
