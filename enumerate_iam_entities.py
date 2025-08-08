#!/usr/bin/env python3

import subprocess
import json
import csv
from datetime import datetime
import argparse

def run_aws_command(command, profile=None):
    """Run AWS CLI command and return JSON output"""
    if profile:
        command += f" --profile {profile}"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError:
        return None
    except json.JSONDecodeError:
        return None

def get_account_id(profile=None):
    """Get current account ID"""
    result = run_aws_command("aws sts get-caller-identity", profile)
    if result:
        return result.get('Account', 'unknown')
    return 'unknown'

def enumerate_iam_users(profile=None):
    """Get all IAM users in account"""
    result = run_aws_command("aws iam list-users", profile)
    if result:
        return result.get('Users', [])
    return []

def enumerate_iam_groups(profile=None):
    """Get all IAM groups in account"""
    result = run_aws_command("aws iam list-groups", profile)
    if result:
        return result.get('Groups', [])
    return []

def enumerate_customer_managed_policies(profile=None):
    """Get customer managed policies"""
    result = run_aws_command("aws iam list-policies --scope Local", profile)
    if result:
        return result.get('Policies', [])
    return []

def get_user_last_activity(username, profile=None):
    """Get user's last activity date"""
    result = run_aws_command(f"aws iam get-user --user-name {username}", profile)
    if result and 'User' in result:
        # Try to get last activity from access keys
        keys_result = run_aws_command(f"aws iam list-access-keys --user-name {username}", profile)
        if keys_result and 'AccessKeyMetadata' in keys_result:
            for key in keys_result['AccessKeyMetadata']:
                last_used = run_aws_command(f"aws iam get-access-key-last-used --access-key-id {key['AccessKeyId']}", profile)
                if last_used and 'AccessKeyLastUsed' in last_used:
                    return last_used['AccessKeyLastUsed'].get('LastUsedDate', 'Never')
    return 'Unknown'

def analyze_user_risk(user, profile=None):
    """Analyze risk level of IAM user"""
    username = user['UserName']
    
    # Check for console access
    try:
        login_profile = run_aws_command(f"aws iam get-login-profile --user-name {username}", profile)
        has_console = login_profile is not None
    except:
        has_console = False
    
    # Check for access keys
    keys_result = run_aws_command(f"aws iam list-access-keys --user-name {username}", profile)
    access_key_count = len(keys_result.get('AccessKeyMetadata', [])) if keys_result else 0
    
    # Check for attached policies
    attached_policies = run_aws_command(f"aws iam list-attached-user-policies --user-name {username}", profile)
    policy_count = len(attached_policies.get('AttachedPolicies', [])) if attached_policies else 0
    
    # Determine risk level
    if has_console and access_key_count > 0:
        risk = 'HIGH'
        reason = 'Console access + API keys'
    elif has_console:
        risk = 'MEDIUM'
        reason = 'Console access enabled'
    elif access_key_count > 0:
        risk = 'MEDIUM' 
        reason = 'API access keys present'
    elif policy_count > 0:
        risk = 'LOW'
        reason = 'Has policies but no access method'
    else:
        risk = 'LOW'
        reason = 'No access configured'
    
    return risk, reason, has_console, access_key_count, policy_count

def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM entities in AWS account')
    parser.add_argument('--profile', required=True, help='AWS profile to use')
    parser.add_argument('--account-name', help='Friendly name for account (optional)')
    args = parser.parse_args()
    
    print(f"=== IAM Entity Enumeration ===")
    print(f"Profile: {args.profile}")
    
    # Get account info
    account_id = get_account_id(args.profile)
    account_name = args.account_name or account_id
    print(f"Account: {account_name} ({account_id})")
    
    # Enumerate entities
    users = enumerate_iam_users(args.profile)
    groups = enumerate_iam_groups(args.profile)
    policies = enumerate_customer_managed_policies(args.profile)
    
    print(f"\nFound:")
    print(f"  IAM Users: {len(users)}")
    print(f"  IAM Groups: {len(groups)}")
    print(f"  Customer Managed Policies: {len(policies)}")
    
    # Analyze users
    user_analysis = []
    if users:
        print(f"\nAnalyzing IAM users...")
        for user in users:
            username = user['UserName']
            created_date = user.get('CreateDate', 'Unknown')
            
            print(f"  Analyzing user: {username}")
            risk, reason, has_console, key_count, policy_count = analyze_user_risk(user, args.profile)
            last_activity = get_user_last_activity(username, args.profile)
            
            user_analysis.append({
                'AccountId': account_id,
                'AccountName': account_name,
                'UserName': username,
                'CreatedDate': created_date,
                'LastActivity': last_activity,
                'RiskLevel': risk,
                'RiskReason': reason,
                'ConsoleAccess': has_console,
                'AccessKeyCount': key_count,
                'AttachedPolicyCount': policy_count
            })
    
    # Save results
    output_file = f'iam_entities_{account_id}.csv'
    
    # User analysis
    if user_analysis:
        with open(f'iam_users_{account_id}.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['AccountId', 'AccountName', 'UserName', 'CreatedDate', 'LastActivity', 'RiskLevel', 'RiskReason', 'ConsoleAccess', 'AccessKeyCount', 'AttachedPolicyCount'])
            writer.writeheader()
            writer.writerows(user_analysis)
        print(f"User analysis saved to: iam_users_{account_id}.csv")
    
    # Summary
    with open(f'iam_summary_{account_id}.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['AccountId', 'AccountName', 'IAMUsers', 'IAMGroups', 'CustomerManagedPolicies', 'HighRiskUsers', 'MediumRiskUsers'])
        
        high_risk_users = len([u for u in user_analysis if u['RiskLevel'] == 'HIGH'])
        medium_risk_users = len([u for u in user_analysis if u['RiskLevel'] == 'MEDIUM'])
        
        writer.writerow([
            account_id,
            account_name,
            len(users),
            len(groups),
            len(policies),
            high_risk_users,
            medium_risk_users
        ])
    
    print(f"Summary saved to: iam_summary_{account_id}.csv")
    
    # Print summary
    if users:
        print(f"\n=== Risk Summary ===")
        risk_counts = {}
        for analysis in user_analysis:
            risk = analysis['RiskLevel']
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        for risk, count in sorted(risk_counts.items()):
            print(f"{risk} risk users: {count}")
        
        if high_risk_users > 0:
            print(f"\n⚠️  WARNING: {high_risk_users} high-risk IAM users found!")
            print("These users bypass Identity Center controls and should be reviewed immediately.")
    else:
        print(f"\n✅ GOOD: No IAM users found - proper SSO-only architecture")

if __name__ == "__main__":
    main()