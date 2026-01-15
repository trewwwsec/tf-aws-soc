# IAM role for Wazuh server
resource "aws_iam_role" "wazuh_server_role" {
  name = "${var.project_name}-wazuh-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-wazuh-server-role"
  }
}

# Attach CloudWatch Logs policy for monitoring
resource "aws_iam_role_policy_attachment" "wazuh_cloudwatch" {
  role       = aws_iam_role.wazuh_server_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance profile for Wazuh server
resource "aws_iam_instance_profile" "wazuh_server_profile" {
  name = "${var.project_name}-wazuh-server-profile"
  role = aws_iam_role.wazuh_server_role.name
}

# IAM role for endpoints (minimal permissions)
resource "aws_iam_role" "endpoint_role" {
  name = "${var.project_name}-endpoint-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-endpoint-role"
  }
}

# Instance profile for endpoints
resource "aws_iam_instance_profile" "endpoint_profile" {
  name = "${var.project_name}-endpoint-profile"
  role = aws_iam_role.endpoint_role.name
}
