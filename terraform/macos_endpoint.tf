# =============================================================================
# macOS EC2 Instance Configuration
# Cloud SOC Platform
# =============================================================================
#
# IMPORTANT: macOS on AWS requires Dedicated Hosts and is NOT free tier eligible
#
# Costs:
#   - Dedicated Host: ~$1.083/hour ($26/day, $780/month)
#   - Minimum lease: 24 hours (Apple licensing requirement)
#   - Instance types: mac1.metal (Intel) or mac2.metal (Apple Silicon)
#
# Deployment:
#   - Dedicated Host allocation takes 10-15 minutes
#   - macOS boot takes 5-10 minutes
#   - Total: ~20-25 minutes
#
# To enable macOS endpoint:
#   1. Uncomment all resources below
#   2. Run: terraform init && terraform apply
#   3. Remember to destroy when done to avoid costs!
#
# =============================================================================

# -----------------------------------------------------------------------------
# UNCOMMENT EVERYTHING BELOW TO ENABLE MACOS ENDPOINT
# -----------------------------------------------------------------------------

# # Dedicated Host for macOS (required by Apple licensing)
# resource "aws_ec2_host" "macos_host" {
#   instance_type     = "mac1.metal"  # Intel Mac, or "mac2.metal" for Apple Silicon
#   availability_zone = "${var.aws_region}a"
#   
#   # Auto-placement allows instances to target this host automatically
#   auto_placement = "on"
#   
#   # Host recovery - automatically restart on underlying hardware failure
#   host_recovery = "on"
#   
#   tags = {
#     Name        = "soc-macos-dedicated-host"
#     Environment = "soc-lab"
#     Project     = "cloud-soc-platform"
#     ManagedBy   = "terraform"
#     CostCenter  = "security-lab"
#   }
# }

# # macOS EC2 Instance
# resource "aws_instance" "macos_endpoint" {
#   ami           = data.aws_ami.macos.id
#   instance_type = "mac1.metal"
#   
#   # Must run on dedicated host
#   host_id = aws_ec2_host.macos_host.id
#   
#   subnet_id                   = aws_subnet.private.id
#   vpc_security_group_ids      = [aws_security_group.endpoints.id]
#   associate_public_ip_address = false
#   
#   key_name = var.key_name
#   
#   # Root volume - macOS requires at least 60GB
#   root_block_device {
#     volume_size           = 100
#     volume_type           = "gp3"
#     encrypted             = true
#     delete_on_termination = true
#   }
#   
#   # User data for macOS (runs as launchd script)
#   user_data = base64encode(templatefile("${path.module}/user_data/macos_endpoint.sh", {
#     wazuh_server_ip = aws_instance.wazuh_server.private_ip
#     agent_name      = "macos-endpoint-01"
#   }))
#   
#   tags = {
#     Name        = "macos-endpoint-01"
#     Environment = "soc-lab"
#     OS          = "macOS"
#     Role        = "monitored-endpoint"
#     Project     = "cloud-soc-platform"
#     ManagedBy   = "terraform"
#   }
#   
#   # macOS instances take longer to boot
#   timeouts {
#     create = "30m"
#   }
#   
#   depends_on = [aws_ec2_host.macos_host]
# }

# # Get latest macOS AMI
# data "aws_ami" "macos" {
#   most_recent = true
#   owners      = ["amazon"]
#   
#   filter {
#     name   = "name"
#     values = ["amzn-ec2-macos-13.*"]  # macOS Ventura 13.x
#   }
#   
#   filter {
#     name   = "architecture"
#     values = ["x86_64_mac"]  # Intel Mac, use "arm64_mac" for Apple Silicon
#   }
#   
#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }
#   
#   filter {
#     name   = "state"
#     values = ["available"]
#   }
# }

# # Security group rule for macOS SSH (add to existing endpoints SG)
# resource "aws_security_group_rule" "macos_ssh" {
#   type              = "ingress"
#   from_port         = 22
#   to_port           = 22
#   protocol          = "tcp"
#   cidr_blocks       = [var.allowed_ssh_cidr]
#   security_group_id = aws_security_group.endpoints.id
#   description       = "SSH access to macOS endpoint"
# }

# # Security group rule for macOS VNC/Screen Sharing (optional)
# resource "aws_security_group_rule" "macos_vnc" {
#   type              = "ingress"
#   from_port         = 5900
#   to_port           = 5900
#   protocol          = "tcp"
#   cidr_blocks       = [var.allowed_ssh_cidr]
#   security_group_id = aws_security_group.endpoints.id
#   description       = "VNC/Screen Sharing access to macOS endpoint"
# }

# -----------------------------------------------------------------------------
# OUTPUTS (uncomment when enabling macOS)
# -----------------------------------------------------------------------------

# output "macos_endpoint_private_ip" {
#   description = "Private IP of macOS endpoint"
#   value       = aws_instance.macos_endpoint.private_ip
# }

# output "macos_dedicated_host_id" {
#   description = "Dedicated Host ID for macOS"
#   value       = aws_ec2_host.macos_host.id
# }

# output "macos_instance_id" {
#   description = "Instance ID of macOS endpoint"
#   value       = aws_instance.macos_endpoint.id
# }

# output "macos_hourly_cost" {
#   description = "Estimated hourly cost for macOS Dedicated Host"
#   value       = "$1.083/hour (~$26/day, ~$780/month) - DESTROY WHEN NOT IN USE!"
# }
