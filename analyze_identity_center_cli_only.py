#!/usr/bin/env python3

import subprocess
import json
import csv
import argparse
import os
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
        print(f"[WARNING] Error: {e.stderr}")
        return {}
    except json.JSONDecodeError as e:
        print(f"[WARNING] Could not parse JSON output from: {' '.join(cmd)}")
        return {}

def get_organization_accounts(profile=None):
    """Get list of accounts using organizations CLI"""
    print("[INFO] Getting organization accounts...")
    
    accounts_data = run_aws_command(['organizations', 'list-accounts'], profile)
    
    accounts = []
    for account in accounts_data.get('Accounts', []):
        if account.get('Status') == 'ACTIVE':
            accounts.append({
                'Id': account['Id'],
                'Name': account['Name']
            })
    
    return accounts

def get_iam_roles_for_account(account_id, profile=None):
    """Get IAM roles for an account (requires cross-account access)"""
    print(f"[INFO] Getting IAM roles for account: {account_id}")
    
    # Note: This assumes you have cross-account access or are running from each account
    roles_data = run_aws_command(['iam', 'list-roles'], profile)
    
    sso_roles = []
    for role in roles_data.get('Roles', []):
        role_name = role['RoleName']
        
        # Check if role is from Identity Center
        if ('AWSReservedSSO_' in role_name or 
            'aws-reserved-sso' in role_name.lower() or
            '/aws-reserved/sso.amazonaws.com/' in role.get('Path', '')):
            
            # Extract permission set name
            if 'AWSReservedSSO_' in role_name:
                parts = role_name.split('_')
                permission_set = parts[1] if len(parts) >= 2 else role_name
            else:
                permission_set = role_name
            
            sso_roles.append({
                'AccountId': account_id,
                'RoleName': role_name,
                'PermissionSetName': permission_set,
                'RoleArn': role['Arn'],
                'Path': role['Path'],
                'CreateDate': role['CreateDate']
            })
    
    return sso_roles

def get_cloudtrail_sso_events(profile=None, days=7):
    """Get recent SSO login events from CloudTrail"""
    print("[INFO] Analyzing CloudTrail for SSO events...")
    
    # Look for AssumeRoleWithSAML events
    events_data = run_aws_command([
        'logs', 'filter-log-events',
        '--log-group-name', 'CloudTrail/SSO',
        '--filter-pattern', 'AssumeRoleWithSAML',
        '--max-items', '50'
    ], profile)
    
    users = set()
    for event in events_data.get('events', []):
        message = event.get('message', '')
        if 'userIdentity' in message and '@' in message:
            # Simple regex to extract email-like patterns
            import re
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', message)
            users.update(emails)
    
    return list(users)

def create_assignments_from_cli_data(accounts, profile=None):
    """Create assignments using only CLI commands"""
    all_assignments = []
    
    for account in accounts:
        account_id = account['Id']
        account_name = account['Name']
        
        # Get SSO roles for this account
        sso_roles = get_iam_roles_for_account(account_id, profile)
        
        for role in sso_roles:
            all_assignments.append({
                'AccountId': account_id,
                'AccountName': account_name,
                'RoleName': role['RoleName'],
                'PermissionSetName': role['PermissionSetName'],
                'PrincipalName': 'UNKNOWN_USER',  # To be filled manually
                'PrincipalType': 'USER',
                'RoleArn': role['RoleArn'],
                'CreateDate': role['CreateDate'],
                'Source': 'CLI_IAM_ANALYSIS'
            })
    
    return all_assignments

def create_user_mapping_helper(output_dir):
    """Create helper files for manual user mapping"""
    
    # Create a simple script to help with user discovery
    helper_script = os.path.join(output_dir, 'find_sso_users.sh')
    
    script_content = '''#!/bin/bash
# Helper script to find SSO users from CloudTrail
# Run this in each account or from management account

echo "=== Finding SSO Users from CloudTrail ==="

# Look for AssumeRoleWithSAML events (last 7 days)
aws logs filter-log-events \\
    --log-group-name CloudTrail-SSO \\
    --start-time $(date -d '7 days ago' +%s)000 \\
    --filter-pattern "AssumeRoleWithSAML" \\
    --query 'events[*].message' \\
    --output text | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' | sort -u

echo ""
echo "=== Finding SSO Users from CloudTrail Events ==="

# Alternative: Look at CloudTrail events directly
aws cloudtrail lookup-events \\
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithSAML \\
    --max-items 50 \\
    --query 'Events[*].CloudTrailEvent' \\
    --output text | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' | sort -u
'''
    
    with open(helper_script, 'w') as f:
        f.write(script_content)
    
    # Make executable on Unix systems
    try:
        os.chmod(helper_script, 0o755)
    except:
        pass
    
    print(f"[INFO] Created helper script: {helper_script}")
    
    # Create PowerShell version for Windows
    ps_script = os.path.join(output_dir, 'find_sso_users.ps1')
    
    ps_content = '''# PowerShell script to find SSO users from CloudTrail
Write-Host "=== Finding SSO Users from CloudTrail ==="

# Look for AssumeRoleWithSAML events
$events = aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithSAML --max-items 50 --query 'Events[*].CloudTrailEvent' --output text

# Extract email addresses
$emails = [regex]::Matches($events, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}') | ForEach-Object { $_.Value } | Sort-Object -Unique

Write-Host "Found SSO Users:"
$emails | ForEach-Object { Write-Host "  $_" }
'''
    
    with open(ps_script, 'w') as f:
        f.write(ps_content)
    
    print(f"[INFO] Created PowerShell helper: {ps_script}")

def main():
    parser = argparse.ArgumentParser(description="Analyze Identity Center using CLI only (AWS CLI 2.0.28 compatible)")
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument("--output", default="identity_center_assignments.csv", help="Output CSV file")
    args = parser.parse_args()
    
    print(f"[INFO] Using AWS CLI with profile: {args.profile or 'default'}")
    
    # Test AWS CLI access
    test_result = run_aws_command(['sts', 'get-caller-identity'], args.profile)
    if not test_result:
        print("[ERROR] Could not access AWS CLI or invalid credentials")
        return
    
    print(f"[INFO] Connected as: {test_result.get('Arn', 'Unknown')}")
    
    # Get organization accounts
    accounts = get_organization_accounts(args.profile)
    
    if not accounts:
        print("[ERROR] Could not retrieve organization accounts")
        print("[INFO] Make sure you're running from the management account")
        return
    
    print(f"[INFO] Found {len(accounts)} accounts in organization")
    
    # Create assignments from CLI data
    assignments = create_assignments_from_cli_data(accounts, args.profile)
    
    if assignments:
        # Write to CSV
        fieldnames = ['AccountId', 'AccountName', 'RoleName', 'PermissionSetName', 
                     'PrincipalName', 'PrincipalType', 'RoleArn', 'CreateDate', 'Source']
        
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(assignments)
        
        print(f"[SUCCESS] Created {args.output} with {len(assignments)} role assignments")
        
        # Create helper files
        output_dir = os.path.dirname(args.output) or '.'
        create_user_mapping_helper(output_dir)
        
        print("\n[NEXT STEPS]")
        print("1. Run the helper scripts to find actual SSO users:")
        print("   - Linux/Mac: ./find_sso_users.sh")
        print("   - Windows: .\\find_sso_users.ps1")
        print("2. Update the CSV file with real user identities")
        print("3. Replace 'UNKNOWN_USER' with actual email addresses")
        print("4. Use the completed file with the user journey tracing script")
        
    else:
        print("[WARNING] No Identity Center roles found")
        print("[INFO] This might mean:")
        print("  - Identity Center is not configured")
        print("  - No permission sets are assigned")
        print("  - Cross-account access is not available")

if __name__ == "__main__":
    main()