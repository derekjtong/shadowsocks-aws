# Shadowsocks Server Deployment with AWS EC2

This repository contains a Python script to automate the deployment of a Shadowsocks server on AWS EC2 using the AWS SDK for Python (boto3). It leverages AWS services such as EC2, IAM, and SSM Parameter Store for secure password management and streamlined setup.

### Features
* Automated Shadowsocks Deployment: Sets up a Shadowsocks server on an EC2 instance.
* Secure Configuration: Uses AWS SSM Parameter Store to securely store the Shadowsocks password as a SecureString.
* Predefined Security Rules: Automatically configures a security group to allow necessary traffic.
* IAM Role Management: Creates and assigns an IAM role for the EC2 instance to access the SSM Parameter Store securely.
* Dynamic Instance Setup: Automatically provisions an EC2 instance and installs necessary dependencies using a user data script.

## Prerequisites

### AWS Configuration

1. AWS CLI: Ensure that the AWS CLI is installed and configured with appropriate credentials. To set up, use

```
aws configure
```

2. Ensure that your AWS account has permission to
   * Manage EC2 instances
   * Create IAM roles and policies
   * Access SSM Parameter Store
  
### AWS Configuration

* Python 3.6 or higher
* Install required dependencies using

```
pip install boto3
```
## How It Works
1. Password Storage
2. Security Group Setup
3. IAM Role Creation
4. EC2 Instance Launch
5. Retrieve Public IP

## Usage
### Run the Script
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
### Example Output
```
--- Shadowsocks ---
IP Address: 3.92.183.45
Port: 8488
Shadowsocks Password: insert_your_password_here
```
## AWS Services Used
* EC2
* SSM Parameter Store
* IAM
* VPC Security Groups
