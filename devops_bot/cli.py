import os
import json
import click
from cryptography.fernet import Fernet
from getpass import getpass
from botocore.exceptions import ClientError
from tabulate import tabulate
import boto3


BASE_DIR = os.path.expanduser("~/.etc/devops-bot")
AWS_CREDENTIALS_FILE = os.path.join(BASE_DIR, "aws_credentials.json")
KEY_FILE = os.path.join(BASE_DIR, "key.key")

@click.group()
def cli():
    """DevOps Bot CLI."""
    pass

def ensure_user_folder():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("Encryption key generated and saved.")

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    return open(KEY_FILE, 'rb').read()

def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted



def load_aws_credentials():
    credentials = None
    try:
        if os.path.exists(AWS_CREDENTIALS_FILE):
            key = load_key()
            with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
                encrypted_credentials = cred_file.read()
            decrypted_credentials = decrypt_data(encrypted_credentials, key)
            credentials = json.loads(decrypted_credentials)
    except FileNotFoundError:
        pass
    return credentials


def save_aws_credentials(access_key, secret_key, region):
    ensure_user_folder()
    key = load_key()
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }
    encrypted_credentials = encrypt_data(json.dumps(credentials), key)
    with open(AWS_CREDENTIALS_FILE, 'wb') as cred_file:
        cred_file.write(encrypted_credentials)
    os.chmod(AWS_CREDENTIALS_FILE, 0o600)
    click.echo("AWS credentials encrypted and saved locally.")

@cli.command(name="configure-aws", help="Configure AWS credentials.")
@click.option('--aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--region', required=True, help="AWS Region")
def configure_aws(aws_access_key_id, aws_secret_access_key, region):
    save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
    click.echo("AWS credentials configured successfully.") 


#ec2 instance list

def list_ec2_instances():
    credentials = load_aws_credentials()
    if not credentials:
        return "No AWS credentials found. Please configure them first."

    ec2 = boto3.client('ec2', **credentials)
    try:
        response = ec2.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                key_name = instance.get('KeyName', '-')
                security_groups = ', '.join([sg['GroupId'] for sg in instance.get('SecurityGroups', [])])
                state = instance['State']['Name']
                public_ip = instance.get('PublicIpAddress', 'N/A')
                state_symbol = {
                    'running': '+',
                    'stopped': '-',
                    'terminated': 'x'
                }.get(state, state)
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', [])])
                instances.append([
                    state_symbol, instance_id, instance_type, key_name, security_groups,
                    launch_time, tags, public_ip
                ])
        return instances
    except ClientError as e:
        return f"Failed to list instances: {e}"


@cli.command(name="list-ec2", help="List EC2 instances.")
def list_ec2_command():
    instances = list_ec2_instances()
    if isinstance(instances, str):
        click.echo(instances)
    else:
        headers = ["State", "Instance ID", "Instance Type", "Key Name", "Security Groups", "Launch Time", "Tags", "Public IP"]
        click.echo(tabulate(instances, headers, tablefmt="grid"))



if __name__ == "__main__":
    cli()

