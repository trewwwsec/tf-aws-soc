# Cloud SOC Configuration
aws_region = "us-east-1"

# Your public IP for SSH access (IMPORTANT!)
allowed_ssh_cidr = ["YOUR.PUBLIC.IP/32"]

# SSH Key Configuration
ssh_key_name         = "cloud-soc-key"
ssh_private_key_path = "~/.ssh/cloud-soc-key.pem"

# Instance Types
wazuh_instance_type    = "t3.medium"
endpoint_instance_type = "t3.micro"

# macOS endpoint (disabled by default - expensive!)
enable_macos_endpoint = false

# Environment
environment  = "demo"
project_name = "cloud-soc-platform"
