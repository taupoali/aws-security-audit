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
        print(f"[WARNING] Command failed: {' '.join(cmd)}")
        return {}
    except json.JSONDecodeError:
        print(f"[WARNING] Could not parse JSON output")
        return {}

def get_identity_store_id(profile=None):
    """Get Identity Store ID"""
    instances = run_aws_command(['sso-admin', 'list-instances'], profile)
    if instances and 'Instances' in instances:
        return instances['Instances'][0].get('IdentityStoreId')
    return None

def get_user_details(identity_store_id, user_id, profile=None):
    """Get user details from Identity Store"""
    user_data = run_aws_command(['identitystore', 'describe-user', '--identity-store-id', identity_store_id, '--user-id', user_id], profile)
    
    if user_data:
        username = user_data.get('UserName', '')
        display_name = user_data.get('DisplayName', '')
        
        # Try to get email from user attributes
        emails = user_data.get('Emails', [])
        email = emails[0].get('Value', '') if emails else ''
        
        return {
            'username': username,
            'display_name': display_name,
            'email': email
        }
    return None

def create_user_mapping_file(identity_center_file, output_file, profile=None):
    """Create user mapping CSV from Identity Center assignments"""
    print(f"[INFO] Loading Identity Center assignments from: {identity_center_file}")
    
    # Load Identity Center assignments
    try:
        with open(identity_center_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            assignments = list(reader)
    except Exception as e:
        print(f"[ERROR] Failed to load Identity Center file: {e}")
        return
    
    print(f"[INFO] Found {len(assignments)} assignments")
    
    # Get Identity Store ID
    identity_store_id = get_identity_store_id(profile)
    if not identity_store_id:
        print("[ERROR] Could not get Identity Store ID")
        return
    
    print(f"[INFO] Using Identity Store ID: {identity_store_id}")
    
    # Extract unique user IDs
    user_ids = set()
    for assignment in assignments:
        principal_id = assignment.get('PrincipalId', '')
        principal_type = assignment.get('PrincipalType', '')
        
        if principal_id and principal_type == 'USER':
            user_ids.add(principal_id)
    
    print(f"[INFO] Found {len(user_ids)} unique users")
    
    # Create user mapping
    user_mappings = []
    for i, user_id in enumerate(user_ids, 1):
        print(f"[PROGRESS] Processing user {i}/{len(user_ids)}: {user_id}")
        
        user_details = get_user_details(identity_store_id, user_id, profile)
        
        if user_details:
            user_mappings.append({
                'PrincipalId': user_id,
                'Username': user_details['username'],
                'DisplayName': user_details['display_name'],
                'Email': user_details['email'],
                'FriendlyName': user_details['username'] or user_details['display_name'] or user_details['email'] or f"User-{user_id[:8]}"
            })
        else:
            # Fallback if API call fails
            user_mappings.append({
                'PrincipalId': user_id,
                'Username': '',
                'DisplayName': '',
                'Email': '',
                'FriendlyName': f"User-{user_id[:8]}"
            })
    
    # Write user mapping CSV
    fieldnames = ['PrincipalId', 'Username', 'DisplayName', 'Email', 'FriendlyName']
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(user_mappings)
    
    print(f"[SUCCESS] Created user mapping file: {output_file}")
    print(f"[INFO] Mapped {len(user_mappings)} users")

def main():
    parser = argparse.ArgumentParser(description="Create user mapping from Identity Center UUIDs to usernames")
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--input", default="identity_center_assignments.csv", help="Input Identity Center assignments CSV")
    parser.add_argument("--output", default="user_mapping.csv", help="Output user mapping CSV")
    args = parser.parse_args()
    
    print(f"[INFO] Creating user mapping using profile: {args.profile or 'default'}")
    
    create_user_mapping_file(args.input, args.output, args.profile)

if __name__ == "__main__":
    main()