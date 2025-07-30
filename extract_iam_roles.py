#!/usr/bin/env python3

import subprocess
import csv
import argparse
import json
from datetime import datetime

def run_aws_command(command, profile=None):
    """Run AWS CLI command and return JSON output"""
    cmd = ['aws'] + command
    if profile:
        cmd.extend(['--profile', profile])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.stdout.strip():
            return json.loads(result.stdout)
        return {}
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {' '.join(cmd)}")
        print(f"[ERROR] Error: {e.stderr}")
        return {}
    except json.JSONDecodeError as e:
        print(f"[ERROR] Could not parse JSON output from: {' '.join(cmd)}")
        return {}

def get_iam_roles(profile=None):
    """Get all IAM roles in the account using AWS CLI"""
    print(f"[INFO] Getting IAM roles using AWS CLI...")
    
    # Get list of roles
    roles_data = run_aws_command(['iam', 'list-roles'], profile)
    
    if not roles_data or 'Roles' not in roles_data:
        print("[ERROR] No roles data returned")
        return []
    
    roles = []
    for role in roles_data['Roles']:
        # Convert datetime to string if it's not already
        create_date = role.get('CreateDate', '')
        if isinstance(create_date, str):
            # Already a string, keep as is
            create_date_str = create_date
        else:
            # Convert to ISO format
            create_date_str = str(create_date)
        
        roles.append({
            'RoleName': role.get('RoleName', ''),
            'Path': role.get('Path', '/'),
            'RoleId': role.get('RoleId', ''),
            'Arn': role.get('Arn', ''),
            'CreateDate': create_date_str,
            'AssumeRolePolicyDocument': json.dumps(role.get('AssumeRolePolicyDocument', {}), separators=(',', ':')),
            'Description': role.get('Description', ''),
            'MaxSessionDuration': role.get('MaxSessionDuration', 3600),
            'Tags': json.dumps(role.get('Tags', []), separators=(',', ':'))
        })
    
    return roles

def main():
    parser = argparse.ArgumentParser(description="Extract IAM roles to CSV using AWS CLI")
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--output", default="iam_roles.csv", help="Output CSV file")
    args = parser.parse_args()
    
    print(f"[INFO] Extracting IAM roles using AWS CLI with profile: {args.profile or 'default'}")
    
    # Test AWS CLI access
    test_result = run_aws_command(['sts', 'get-caller-identity'], args.profile)
    if not test_result:
        print("[ERROR] Could not access AWS CLI or invalid credentials")
        return
    
    print(f"[INFO] Connected as: {test_result.get('Arn', 'Unknown')}")
    
    # Get roles
    roles = get_iam_roles(args.profile)
    
    if not roles:
        print("[WARNING] No IAM roles found")
        return
    
    # Write to CSV
    fieldnames = ['RoleName', 'Path', 'RoleId', 'Arn', 'CreateDate', 
                 'AssumeRolePolicyDocument', 'Description', 'MaxSessionDuration', 'Tags']
    
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(roles)
    
    print(f"[SUCCESS] Extracted {len(roles)} IAM roles to {args.output}")

if __name__ == "__main__":
    main()