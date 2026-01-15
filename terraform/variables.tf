variable "aws_region" {
  description = "AWS region for SOC infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloud-soc"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "allowed_ssh_cidr" {
  description = "CIDR blocks allowed to SSH (YOUR IP ONLY)"
  type        = list(string)
  default     = ["73.162.120.46/32"] # Your public IP
}

variable "wazuh_instance_type" {
  description = "EC2 instance type for Wazuh server"
  type        = string
  default     = "t3.medium" # Required for Wazuh (2 vCPU, 4GB RAM) - Not Free Tier but necessary
}

variable "endpoint_instance_type" {
  description = "EC2 instance type for endpoints"
  type        = string
  default     = "t3.micro" # Free Tier eligible
}

variable "ssh_key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "cloud-soc-key"
}
