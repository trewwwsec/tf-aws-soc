# Data source for latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Data source for latest Windows Server AMI
data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"] # Amazon-owned Windows AMIs

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Wazuh Server
resource "aws_instance" "wazuh_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.wazuh_instance_type
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.wazuh_server_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.wazuh_server_profile.name
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = file("${path.module}/user_data/wazuh_server.sh")

  tags = {
    Name = "${var.project_name}-wazuh-server"
    Role = "SIEM"
  }
}

# Deploy custom detection rules after Wazuh is ready
resource "null_resource" "deploy_detection_rules" {
  depends_on = [aws_instance.wazuh_server]

  # Trigger redeployment when rules change
  triggers = {
    local_rules_hash = filemd5("${path.module}/../wazuh/custom_rules/local_rules.xml")
    macos_rules_hash = filemd5("${path.module}/../wazuh/custom_rules/macos_rules.xml")
  }

  # Wait for Wazuh to be ready
  provisioner "local-exec" {
    command = "echo 'Waiting for Wazuh server to initialize...' && sleep 120"
  }

  # Copy local_rules.xml
  provisioner "file" {
    source      = "${path.module}/../wazuh/custom_rules/local_rules.xml"
    destination = "/tmp/local_rules.xml"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh_private_key_path)
      host        = aws_instance.wazuh_server.public_ip
    }
  }

  # Copy macos_rules.xml
  provisioner "file" {
    source      = "${path.module}/../wazuh/custom_rules/macos_rules.xml"
    destination = "/tmp/macos_rules.xml"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh_private_key_path)
      host        = aws_instance.wazuh_server.public_ip
    }
  }

  # Deploy rules and restart Wazuh
  provisioner "remote-exec" {
    inline = [
      "echo 'Deploying custom detection rules...'",
      "sudo mv /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml",
      "sudo mv /tmp/macos_rules.xml /var/ossec/etc/rules/macos_rules.xml",
      "sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml",
      "sudo chown wazuh:wazuh /var/ossec/etc/rules/macos_rules.xml",
      "sudo chmod 660 /var/ossec/etc/rules/local_rules.xml",
      "sudo chmod 660 /var/ossec/etc/rules/macos_rules.xml",
      "echo 'Restarting Wazuh manager to load rules...'",
      "sudo systemctl restart wazuh-manager",
      "echo 'Custom detection rules deployed successfully!'",
      "echo '  - local_rules.xml: 45 Windows/Linux rules'",
      "echo '  - macos_rules.xml: 28 macOS rules'",
      "echo '  - Total: 73 MITRE ATT&CK mapped rules'"
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh_private_key_path)
      host        = aws_instance.wazuh_server.public_ip
    }
  }
}

# Linux Endpoint
resource "aws_instance" "linux_endpoint" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.endpoint_instance_type
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.linux_endpoint_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.endpoint_profile.name
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = 10
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/user_data/linux_agent.sh", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
  })

  tags = {
    Name = "${var.project_name}-linux-endpoint"
    Role = "Endpoint"
  }

  depends_on = [aws_instance.wazuh_server]
}

# Windows Endpoint
resource "aws_instance" "windows_endpoint" {
  ami                    = data.aws_ami.windows.id
  instance_type          = var.endpoint_instance_type
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.windows_endpoint_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.endpoint_profile.name
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/user_data/windows_agent.ps1", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
  })

  tags = {
    Name = "${var.project_name}-windows-endpoint"
    Role = "Endpoint"
  }

  depends_on = [aws_instance.wazuh_server]
}
