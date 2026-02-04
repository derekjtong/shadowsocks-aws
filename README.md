# Shadowsocks Server Deployment with AWS EC2

This repository provides two ways to deploy a Shadowsocks server on AWS EC2:
1. **Terraform** (recommended): Infrastructure-as-code approach with declarative configuration
2. **Python Script**: Automated deployment using the AWS SDK for Python (boto3)

Both methods leverage AWS services such as EC2, IAM, VPC, and security groups for streamlined setup.

### Features
* **Automated Shadowsocks Deployment**: Sets up a Shadowsocks server on an EC2 instance
* **Infrastructure as Code** (Terraform): Declarative configuration with version control
* **Flexible Architecture**: Support for both x86 (t3.nano) and ARM (t4g.nano) instances
* **Secure Configuration**: Configurable password and SSH access restrictions
* **Predefined Security Rules**: Automatically configures security groups for Shadowsocks and SSH traffic
* **Systemd Service**: Shadowsocks runs as a managed systemd service with auto-restart
* **IPv6 Support**: Optional IPv6-only mode (experimental)

#### Python Script Features
* Secure Password Storage: Uses AWS SSM Parameter Store to securely store credentials
* IAM Role Management: Creates and assigns IAM roles for secure SSM access

## Deployment Options

### Option 1: Terraform Deployment (Recommended)

#### Prerequisites
* Terraform >= 1.6.0 ([install instructions](https://developer.hashicorp.com/terraform/downloads))
* AWS CLI configured with credentials (`aws configure`)
* AWS account with permissions to manage EC2, VPC, and security groups

#### Quick Start

1. Clone this repository:
```bash
git clone https://github.com/yourusername/shadowsocks-aws.git
cd shadowsocks-aws
```

2. Initialize Terraform:
```bash
terraform init
```

3. (Optional) Customize variables by creating a `terraform.tfvars` file:
```hcl
aws_region     = "ap-east-1"      # AWS region
instance_type  = "t4g.nano"       # t3.nano (x86) or t4g.nano (ARM)
ss_password    = "your-password"  # Shadowsocks password
ssh_cidr       = "1.2.3.4/32"    # Restrict SSH to your IP
```

4. Deploy the infrastructure:
```bash
terraform apply
```

5. Get the connection details:
```bash
terraform output
```

#### Terraform Configuration Options

The Terraform configuration supports the following variables (see [shadowsocks.tf](shadowsocks.tf)):

* `aws_region` - AWS region (default: "ap-east-1")
* `instance_type` - EC2 instance type: "t3.nano" or "t4g.nano" (default: "t4g.nano")
* `amazon_linux_generation` - AMI generation: "al2023" or "al2" (default: "al2023")
* `ss_password` - Shadowsocks password (default: "123", change in production)
* `ssh_cidr` - CIDR block for SSH access (default: "0.0.0.0/0", restrict to your IP)
* `ipv6_only` - Use IPv6 only instead of IPv4 (default: false, currently unsupported)

#### Cleanup

To destroy the infrastructure:
```bash
terraform destroy
```

### Option 2: Python Script Deployment

#### Prerequisites

1. AWS CLI: Ensure that the AWS CLI is installed and configured with appropriate credentials. To set up, use

```
aws configure
```

2. Ensure that your AWS account has permission to
   * Manage EC2 instances
   * Create IAM roles and policies
   * Access SSM Parameter Store

3. Python 3.6 or higher
4. Install required dependencies using

```
pip install boto3
```
#### How It Works (Python Script)
1. Password Storage
2. Security Group Setup
3. IAM Role Creation
4. EC2 Instance Launch
5. Retrieve Public IP

#### Usage
1. Clone this repository
```
git clone https://github.com/yourusername/shadowsocks-aws.git
cd shadowsocks-deployment
```
2. Open the script and configure the following variables as needed, can be left as is
   * `SHADOWSOCKS_PASSWORD`: Set the password your clients will use to authenticate themselves to the server
   * `INSTANCE_TYPE`: Choose the EC@ instance type
   * `AMI_ID`: Specify the Amazon Machine Image (AMI) ID
3. Execute the sscript:
```
python shadowsocks_deployment.py
```
4. Upon successful deployment, the script will output the information needed to connect to the Shadowsocks server
   * Public IP
   * Port (default 8488)
   * Shadowsocks password
5. (Optional) Add `start.sh` to `ec2-user` home for easy control

#### Example Output
```
--- Shadowsocks ---
IP Address: 3.92.183.45
Port: 8488
Shadowsocks Password: insert_your_password_here
```

### Uptime Server

Optional uptime server

https://github.com/derekjtong/shadowsocks_status

## AWS Services Used

### Terraform Deployment
* EC2 (Elastic Compute Cloud)
* VPC (Virtual Private Cloud)
* Security Groups
* AMI (Amazon Machine Images)

### Python Script Deployment
* EC2 (Elastic Compute Cloud)
* SSM Parameter Store (Secure password storage)
* IAM (Identity and Access Management)
* VPC Security Groups
