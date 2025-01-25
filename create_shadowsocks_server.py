import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import json


# Shadowsocks Configuration
# Will be stored on SSM Parameter Store
SHADOWSOCKS_PASSWORD = "insert_your_password_here"


# AWS Configuration
# EC2
INSTANCE_TYPE = "t3.nano"
AMI_ID = "ami-0df8c184d5f6ae949"
TAG_NAME = "Name"
TAG_VALUE = "shadowsocks-server"
# EC2 Security Group
SECURITY_GROUP_NAME = "shadowsocks-sg"
SECURITY_GROUP_DESCRIPTION = "Allow TCP, UDP on port 8488 and SSH on port 22"
# SSM Parameter Store field to store password
PARAMETER_NAME = "ss_password"
PARAMETER_DESCRIPTION = "Password for Shadowsocks server"


# SSM Parameter Store access role
# Allow EC2 instance profile access to Shadowsocks password stored in SSM Parameter Store
ROLE_NAME = "SSMAccessRole"
POLICY_NAME = "SSMAccessPolicy"
TRUST_RELATIONSHIP = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": "arn:aws:ssm:*:*:parameter/ss_password",
        }
    ],
}


# User Data script that runs on first instance start
USER_DATA_SCRIPT = """#!/bin/bash
# Fetch the password from Parameter Store
SS_PASSWORD=$(aws ssm get-parameter --name "ss_password" --with-decryption --query "Parameter.Value" --output text)
echo "export SS_PASSWORD=$SS_PASSWORD" >> /etc/profile.d/ss.sh
chmod +x /etc/profile.d/ss.sh
echo "the SS_PASSWORD is"
echo $SS_PASSWORD

# Install Go
sudo yum install go -y
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export PATH=$GOPATH/bin:/usr/local/bin:/usr/bin:/bin:$PATH
echo "export GOPATH=/root/go" >> /etc/profile.d/go.sh
echo "export GOCACHE=/root/.cache/go-build" >> /etc/profile.d/go.sh
echo "export PATH=$GOPATH/bin:/usr/local/bin:/usr/bin:/bin:\$PATH" >> /etc/profile.d/go.sh
chmod +x /etc/profile.d/go.sh
source /etc/profile.d/go.sh
mkdir -p $GOPATH
mkdir -p $GOCACHE

# Install Shadowsocks
go install github.com/shadowsocks/go-shadowsocks2@latest

# Run shadowsocks and log
$GOPATH/bin/go-shadowsocks2 -s "ss://AEAD_CHACHA20_POLY1305:$SS_PASSWORD@:8488" -verbose > /tmp/shadowsocks.log 2>&1 &
"""


def add_password_to_parameter_store():
    try:
        ssm = boto3.client("ssm")

        ssm.put_parameter(
            Name=PARAMETER_NAME,
            Description=PARAMETER_DESCRIPTION,
            Value=SHADOWSOCKS_PASSWORD,
            Type="SecureString",
            Overwrite=True,
        )
        print(f"Password added to Parameter Store under the name '{PARAMETER_NAME}'")
        return SHADOWSOCKS_PASSWORD

    except Exception as e:
        print(f"An error occurred while adding the password to Parameter Store: {e}")


def create_security_group(ec2):
    try:
        # Check if the security group already exists
        response = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [SECURITY_GROUP_NAME]}]
        )
        if response["SecurityGroups"]:
            # Security group exists, retrieve its ID
            security_group_id = response["SecurityGroups"][0]["GroupId"]
            print(
                f"Security group '{SECURITY_GROUP_NAME}' already exists with ID: {security_group_id}"
            )
        else:
            # Create the security group
            response = ec2.create_security_group(
                GroupName=SECURITY_GROUP_NAME, Description=SECURITY_GROUP_DESCRIPTION
            )
            security_group_id = response["GroupId"]
            print(f"Security group created with ID: {security_group_id}")

            # Authorize inbound traffic
            ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        # All TCP
                        "IpProtocol": "tcp",
                        "FromPort": 8488,
                        "ToPort": 8488,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    },
                    {
                        # All UDP
                        "IpProtocol": "udp",
                        "FromPort": 8488,
                        "ToPort": 8488,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    },
                    {
                        # SSH
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    },
                ],
            )
            print(
                f"Inbound rules added to allow TCP and UDP traffic on port 8488 and SSH on port 22."
            )

        return security_group_id

    except Exception as e:
        print(f"An error occurred while creating the security group: {e}")


def create_iam_role():
    try:
        iam = boto3.client("iam")

        # Create the IAM role
        role_response = iam.create_role(
            RoleName=ROLE_NAME, AssumeRolePolicyDocument=json.dumps(TRUST_RELATIONSHIP)
        )
        print(f"IAM Role {ROLE_NAME} created.")

        # Attach the policy to the role
        iam.put_role_policy(
            RoleName=ROLE_NAME,
            PolicyName=POLICY_NAME,
            PolicyDocument=json.dumps(POLICY_DOCUMENT),
        )
        print(f"Policy {POLICY_NAME} attached to role {ROLE_NAME}.")

        return role_response["Role"]["Arn"]

    except iam.exceptions.EntityAlreadyExistsException:
        print(f"Role {ROLE_NAME} already exists.")
        role = iam.get_role(RoleName=ROLE_NAME)
        return role["Role"]["Arn"]
    except Exception as e:
        print(f"An error occurred while creating the IAM role: {e}")


def attach_role_to_instance_profile(iam, instance_profile_name, role_name):
    try:
        # List existing roles in the instance profile
        response = iam.get_instance_profile(InstanceProfileName=instance_profile_name)
        roles = response.get("InstanceProfile", {}).get("Roles", [])

        # If a role is already attached, detach it
        if roles:
            existing_role_name = roles[0]["RoleName"]
            print(
                f"Detaching existing role '{existing_role_name}' from instance profile '{instance_profile_name}'."
            )
            iam.remove_role_from_instance_profile(
                InstanceProfileName=instance_profile_name, RoleName=existing_role_name
            )

        # Attach the new role
        print(
            f"Attaching role '{role_name}' to instance profile '{instance_profile_name}'."
        )
        iam.add_role_to_instance_profile(
            InstanceProfileName=instance_profile_name, RoleName=role_name
        )
    except Exception as e:
        print(f"An error occurred while attaching role to instance profile: {e}")


def create_instance():
    try:
        ec2 = boto3.client("ec2")

        # Get the security group
        security_group_id = create_security_group(ec2)

        # Create IAM role and get its ARN
        iam_role_arn = create_iam_role()

        # Create an instance profile for the role
        iam = boto3.client("iam")
        instance_profile_name = f"{ROLE_NAME}-InstanceProfile"
        try:
            iam.create_instance_profile(InstanceProfileName=instance_profile_name)
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"Instance profile {instance_profile_name} already exists.")

        attach_role_to_instance_profile(iam, instance_profile_name, ROLE_NAME)

        # Create the EC2 instance
        response = ec2.run_instances(
            InstanceType=INSTANCE_TYPE,
            ImageId=AMI_ID,
            SecurityGroupIds=[security_group_id],
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={"Name": instance_profile_name},
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": TAG_NAME, "Value": TAG_VALUE}],
                }
            ],
            UserData=USER_DATA_SCRIPT,
        )

        instance_id = response["Instances"][0]["InstanceId"]
        print(f"EC2 Instance created with ID: {instance_id}")
        return instance_id

    except NoCredentialsError:
        print("Error: AWS credentials not found.")
    except PartialCredentialsError:
        print("Error: Incomplete AWS credentials.")
    except Exception as e:
        print(f"An error occurred: {e}")


def get_instance_public_ip(instance_id):
    try:
        ec2 = boto3.client("ec2")

        # Wait for the instance to transition to running state
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])

        # Fetch instance details
        response = ec2.describe_instances(InstanceIds=[instance_id])
        public_ip = response["Reservations"][0]["Instances"][0]["PublicIpAddress"]
        return public_ip

    except Exception as e:
        print(f"An error occurred while fetching the public IP: {e}")
        return None


def main():
    # Add password to Parameter Store
    password = add_password_to_parameter_store()

    # Create EC2 instance
    instance_id = create_instance()

    if instance_id:
        # Get public IP
        public_ip = get_instance_public_ip(instance_id)

        if public_ip:
            print("\n--- Shadowsocks ---")
            print(f"IP Address: {public_ip}")
            print(f"Port: 8488")
            print(f"Shadowsocks Password: {password}")
        else:
            print("Failed to retrieve the public IP address.")


if __name__ == "__main__":
    main()
