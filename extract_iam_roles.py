#!/usr/bin/env python3

import boto3
import csv
import argparse
import json
from datetime import datetime
from botocore.exceptions import ClientError

def get_iam_roles(profile=None):
    """Get all IAM roles in the account"""
    try:
        if profile:
            session = boto3.Session(profile_name=profile)
        else:
            session = boto3.Session()
        
        iam = session.client('iam')
        roles = []
        
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                # Get trust policy
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                
                roles.append({
                    'RoleName': role['RoleName'],
                    'Path': role['Path'],
                    'RoleId': role['RoleId'],
                    'Arn': role['Arn'],
                    'CreateDate': role['CreateDate'].isoformat(),
                    'AssumeRolePolicyDocument': json.dumps(trust_policy, separators=(',', ':')),
                    'Description': role.get('Description', ''),
                    'MaxSessionDuration': role.get('MaxSessionDuration', 3600),
                    'Tags': json.dumps(role.get('Tags', []), separators=(',', ':'))
                })
        
        return roles
    
    except ClientError as e:
        print(f"[ERROR] Failed to get IAM roles: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Extract IAM roles to CSV")
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--output", default="iam_roles.csv", help="Output CSV file")
    args = parser.parse_args()
    
    print(f"[INFO] Extracting IAM roles using profile: {args.profile or 'default'}")
    
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