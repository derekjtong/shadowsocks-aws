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
  default = "ap-east-1"
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"

  validation {
    condition = contains(
      ["t3.nano", "t4g.nano"],
      var.instance_type
    )
    error_message = "instance_type must be t3.nano or t4g.nano."
  }
}

variable "amazon_linux_generation" {
  type    = string
  default = "al2023"

  validation {
    condition     = contains(["al2023", "al2"], var.amazon_linux_generation)
    error_message = "Use al2023 or al2."
  }
}

variable "ss_password" {
  type      = string
  sensitive = true
}

variable "ss_cipher" {
  type    = string
  default = "AEAD_CHACHA20_POLY1305"

  validation {
    condition     = contains(["AEAD_CHACHA20_POLY1305", "AEAD_AES_256_GCM"], var.ss_cipher)
    error_message = "ss_cipher must be AEAD_CHACHA20_POLY1305 or AEAD_AES_256_GCM."
  }
}

variable "ssh_cidr" {
  type    = string
  default = "0.0.0.0/0" # strongly recommend setting to your IP/CIDR
}

variable "ipv6_only" {
  type        = bool
  default     = false
  description = "Use IPv6 only instead of IPv4. Automatically creates IPv6-enabled subnet. Currently unsupported due many sites not supporting IPv6, notably GitHub"
}

# -----------------------
# Architecture Detection
# -----------------------
locals {
  architecture = startswith(var.instance_type, "t4g") ? "arm64" : "x86_64"
}

# -----------------------
# AMI Selection
# -----------------------
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = var.amazon_linux_generation == "al2023" ? ["al2023-ami-*-kernel-*-${local.architecture}"] : ["amzn2-ami-hvm-*-${local.architecture}-gp2"]
  }

  filter {
    name   = "architecture"
    values = [local.architecture]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
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

# Enable IPv6 on the default VPC if ipv6_only is true
resource "aws_vpc_ipv6_cidr_block_association" "default" {
  count = var.ipv6_only ? 1 : 0

  vpc_id                           = data.aws_vpc.default.id
  assign_generated_ipv6_cidr_block = true
}

# Get availability zones to create IPv6 subnet
data "aws_availability_zones" "available" {
  count = var.ipv6_only ? 1 : 0

  state = "available"
}

# Create a new subnet with IPv6 enabled
resource "aws_subnet" "ipv6" {
  count = var.ipv6_only ? 1 : 0

  vpc_id                          = data.aws_vpc.default.id
  cidr_block                      = "172.31.128.0/20" # Non-overlapping CIDR in default VPC range
  ipv6_cidr_block                 = cidrsubnet(aws_vpc_ipv6_cidr_block_association.default[0].ipv6_cidr_block, 8, 1)
  assign_ipv6_address_on_creation = true
  availability_zone               = data.aws_availability_zones.available[0].names[0]

  tags = {
    Name = "shadowsocks-ipv6-subnet"
  }
}

# Get the default internet gateway for IPv6 routing
data "aws_internet_gateway" "default" {
  count = var.ipv6_only ? 1 : 0

  filter {
    name   = "attachment.vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Add IPv6 route to the main route table
resource "aws_route" "ipv6_default" {
  count = var.ipv6_only ? 1 : 0

  route_table_id              = data.aws_vpc.default.main_route_table_id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = data.aws_internet_gateway.default[0].id
}

# -----------------------
# Security Group
# -----------------------
resource "aws_security_group" "ss" {
  name        = "shadowsocks-sg"
  description = "Allow TCP, UDP on port 8488 and SSH on port 22"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description      = "Shadowsocks TCP"
    from_port        = 8488
    to_port          = 8488
    protocol         = "tcp"
    cidr_blocks      = var.ipv6_only ? [] : ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.ipv6_only ? ["::/0"] : []
  }

  ingress {
    description      = "Shadowsocks UDP"
    from_port        = 8488
    to_port          = 8488
    protocol         = "udp"
    cidr_blocks      = var.ipv6_only ? [] : ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.ipv6_only ? ["::/0"] : []
  }

  ingress {
    description      = "SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = var.ipv6_only ? [] : [var.ssh_cidr]
    ipv6_cidr_blocks = var.ipv6_only ? ["::/0"] : []
  }

  egress {
    description      = "All egress"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = var.ipv6_only ? [] : ["0.0.0.0/0"]
    ipv6_cidr_blocks = var.ipv6_only ? ["::/0"] : []
  }
}

# -----------------------
# User data
# -----------------------
locals {
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    ss_password      = var.ss_password
    ss_cipher        = var.ss_cipher
    service_script   = file("${path.module}/shadowsocks-service.sh")
  })
}

# -----------------------
# EC2 instance
# -----------------------
resource "aws_instance" "ss" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  subnet_id              = var.ipv6_only ? aws_subnet.ipv6[0].id : data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.ss.id]
  ipv6_address_count     = var.ipv6_only ? 1 : 0

  user_data = local.user_data

  tags = {
    Name = "shadowsocks-server"
  }
}

output "public_ip" {
  value       = var.ipv6_only ? null : aws_instance.ss.public_ip
  description = "Public IPv4 address (null if IPv6 only)"
}

output "ipv6_address" {
  value       = var.ipv6_only ? try(aws_instance.ss.ipv6_addresses[0], null) : null
  description = "IPv6 address (null if IPv4 only)"
}

output "ss_port" {
  value = 8488
}
