terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -----------------------
# Inputs
# -----------------------
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "ami_id" {
  type    = string
  default = "ami-0cb183c3095c323ed" # your current AMI
}

variable "instance_type" {
  type    = string
  default = "t3.nano"
}

variable "ss_password" {
  type      = string
  sensitive = true
}

variable "ssh_cidr" {
  type    = string
  default = "0.0.0.0/0" # strongly recommend setting to your IP/CIDR
}

# If you want to place this in the default VPC:
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# -----------------------
# SSM Parameter
# -----------------------
resource "aws_ssm_parameter" "ss_password" {
  name        = "ss_password"
  description = "Password for Shadowsocks server"
  type        = "SecureString"
  value       = var.ss_password
  overwrite   = true
}

# -----------------------
# Security Group
# -----------------------
resource "aws_security_group" "ss" {
  name        = "shadowsocks-sg"
  description = "Allow TCP, UDP on port 8488 and SSH on port 22"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Shadowsocks TCP"
    from_port   = 8488
    to_port     = 8488
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Shadowsocks UDP"
    from_port   = 8488
    to_port     = 8488
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------
# IAM Role + Instance Profile
# -----------------------
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm_access" {
  name               = "SSMAccessRole"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

data "aws_iam_policy_document" "ssm_get_parameter" {
  statement {
    effect  = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters"
    ]
    resources = [aws_ssm_parameter.ss_password.arn]
  }

  # If your SecureString uses the default AWS-managed key for SSM in the account/region,
  # this often works without explicit kms:Decrypt. If you use a customer-managed CMK,
  # you MUST add kms:Decrypt for that key ARN.
  # statement {
  #   effect = "Allow"
  #   actions = ["kms:Decrypt"]
  #   resources = ["arn:aws:kms:REGION:ACCOUNT:key/YOUR_KEY_ID"]
  # }
}

resource "aws_iam_role_policy" "inline" {
  name   = "SSMAccessPolicy"
  role   = aws_iam_role.ssm_access.id
  policy = data.aws_iam_policy_document.ssm_get_parameter.json
}

resource "aws_iam_instance_profile" "ss_profile" {
  name = "SSMAccessRole-InstanceProfile"
  role = aws_iam_role.ssm_access.name
}

# -----------------------
# User data
# -----------------------
locals {
  user_data = <<-EOF
  #!/bin/bash
  set -euo pipefail

  # Ensure AWS CLI exists (most AL2/AL2023 AMIs have it; this is defensive)
  if ! command -v aws >/dev/null 2>&1; then
    yum install -y awscli || dnf install -y awscli
  fi

  # Fetch the password from Parameter Store
  SS_PASSWORD=$(aws ssm get-parameter --name "ss_password" --with-decryption --query "Parameter.Value" --output text)
  echo "export SS_PASSWORD=$SS_PASSWORD" > /etc/profile.d/ss.sh
  chmod +x /etc/profile.d/ss.sh

  # Install Go (your script used yum; support both yum/dnf)
  yum install -y golang || dnf install -y golang

  export GOPATH=/root/go
  export GOCACHE=/root/.cache/go-build
  export PATH=$GOPATH/bin:/usr/local/bin:/usr/bin:/bin:$PATH

  cat > /etc/profile.d/go.sh <<'SH'
  export GOPATH=/root/go
  export GOCACHE=/root/.cache/go-build
  export PATH=$GOPATH/bin:/usr/local/bin:/usr/bin:/bin:$PATH
  SH
  chmod +x /etc/profile.d/go.sh
  source /etc/profile.d/go.sh

  mkdir -p "$GOPATH" "$GOCACHE"

  # Install Shadowsocks
  go install github.com/shadowsocks/go-shadowsocks2@latest

  # Run shadowsocks and log
  nohup $GOPATH/bin/go-shadowsocks2 -s "ss://AEAD_CHACHA20_POLY1305:$SS_PASSWORD@:8488" -verbose > /tmp/shadowsocks.log 2>&1 &
  EOF
}

# -----------------------
# EC2 instance
# -----------------------
resource "aws_instance" "ss" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.ss.id]
  iam_instance_profile   = aws_iam_instance_profile.ss_profile.name

  user_data = local.user_data

  tags = {
    Name = "shadowsocks-server"
  }
}

output "public_ip" {
  value = aws_instance.ss.public_ip
}

output "ss_port" {
  value = 8488
}
