#!/usr/bin/env python3

import json
import subprocess
import argparse
import csv
import time
from datetime import datetime
import os

# Track API call statistics
API_STATS = {"calls": 0, "timeouts": 0, "errors": 0, "cached": 0}
API_CACHE = {}

def run_aws_command(cmd, profile=None, region=None, retries=2):
    """Run AWS CLI command with retries and caching"""
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    if region and "--region" not in cmd:
        cmd.insert(1, "--region")
        cmd.insert(2, region)
    
    cmd_key = ' '.join(cmd)
    if cmd_key in API_CACHE:
        API_STATS["cached"] += 1
        return API_CACHE[cmd_key]
    
    API_STATS["calls"] += 1
    for attempt in range(retries + 1):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            API_CACHE[cmd_key] = result.stdout
            return result.stdout
        except subprocess.CalledProcessError as e:
            if "AccessDenied" in e.stderr or "UnauthorizedOperation" in e.stderr:
                print(f"Access denied: {e.stderr}")
                return None
            if attempt < retries:
                delay = 1 * (2 ** attempt)  # Exponential backoff
                print(f"Retrying command after {delay}s: {' '.join(cmd)}")
                time.sleep(delay)
            else:
                API_STATS["errors"] += 1
                return None
        except subprocess.TimeoutExpired:
            API_STATS["timeouts"] += 1
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
            else:
                return None
    return None

def get_account_info(profile=None):
    """Get basic account information"""
    cmd = ["aws", "sts", "get-caller-identity", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return {"AccountId": "Unknown", "Arn": "Unknown"}
    
    return json.loads(result)

def get_iam_summary(profile=None):
    """Get IAM summary statistics"""
    cmd = ["aws", "iam", "get-account-summary", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return {}
    
    return json.loads(result).get("SummaryMap", {})

def is_control_tower_managed(profile=None):
    """Check if account is managed by Control Tower"""
    # Check for Control Tower roles
    cmd = ["aws", "iam", "list-roles", "--path-prefix", "/aws-reserved/sso.amazonaws.com/", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if result:
        roles = json.loads(result).get("Roles", [])
        if roles:
            return True
    
    # Check for Control Tower StackSets
    cmd = ["aws", "cloudformation", "list-stack-instances", "--stack-set-name", "AWSControlTowerBP-*", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if result and "StackInstanceSummaries" in result:
        return True
    
    # Check for Control Tower tags on account
    cmd = ["aws", "organizations", "list-tags-for-resource", "--resource-id", get_account_info(profile).get("AccountId", ""), "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if result:
        tags = json.loads(result).get("Tags", [])
        for tag in tags:
            if tag.get("Key") == "aws-control-tower":
                return True
    
    return False

def count_identity_center_roles(profile=None):
    """Count IAM Identity Center managed roles"""
    cmd = ["aws", "iam", "list-roles", "--path-prefix", "/aws-reserved/sso.amazonaws.com/", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return 0
    
    roles = json.loads(result).get("Roles", [])
    return len(roles)

def get_all_roles(profile=None):
    """Get all IAM roles in the account"""
    cmd = ["aws", "iam", "list-roles", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    return json.loads(result).get("Roles", [])

def get_all_users(profile=None):
    """Get all IAM users in the account"""
    cmd = ["aws", "iam", "list-users", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    return json.loads(result).get("Users", [])

def get_all_groups(profile=None):
    """Get all IAM groups in the account"""
    cmd = ["aws", "iam", "list-groups", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    return json.loads(result).get("Groups", [])

def get_all_policies(profile=None):
    """Get all customer managed policies in the account"""
    cmd = ["aws", "iam", "list-policies", "--scope", "Local", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    return json.loads(result).get("Policies", [])

def get_password_policy(profile=None):
    """Get account password policy"""
    cmd = ["aws", "iam", "get-account-password-policy", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return None
    
    return json.loads(result).get("PasswordPolicy", {})

def get_account_aliases(profile=None):
    """Get account aliases"""
    cmd = ["aws", "iam", "list-account-aliases", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    return json.loads(result).get("AccountAliases", [])

def get_mfa_devices(profile=None):
    """Get MFA devices for all users"""
    cmd = ["aws", "iam", "list-virtual-mfa-devices", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    return json.loads(result).get("VirtualMFADevices", [])

def get_account_summary(profile=None):
    """Get a summary of account statistics"""
    print("[INFO] Gathering account summary statistics...")
    
    # Get account info
    account_info = get_account_info(profile)
    account_id = account_info.get("AccountId", "Unknown")
    
    # Get account aliases
    aliases = get_account_aliases(profile)
    account_name = aliases[0] if aliases else account_id
    
    # Get IAM summary
    iam_summary = get_iam_summary(profile)
    
    # Get roles, users, and groups
    roles = get_all_roles(profile)
    users = get_all_users(profile)
    groups = get_all_groups(profile)
    policies = get_all_policies(profile)
    
    # Count Identity Center roles
    identity_center_roles = count_identity_center_roles(profile)
    
    # Check if Control Tower managed
    is_ct_managed = is_control_tower_managed(profile)
    
    # Get MFA devices
    mfa_devices = get_mfa_devices(profile)
    
    # Calculate statistics
    total_roles = len(roles)
    total_users = len(users)
    total_groups = len(groups)
    total_policies = len(policies)
    
    # Calculate users with MFA
    users_with_mfa = 0
    for device in mfa_devices:
        if "User" in device:
            users_with_mfa += 1
    
    # Calculate service-linked roles
    service_linked_roles = 0
    for role in roles:
        if role.get("Path", "").startswith("/aws-service-role/"):
            service_linked_roles += 1
    
    # Calculate user-created roles
    user_created_roles = total_roles - service_linked_roles - identity_center_roles
    
    # Get password policy status
    password_policy = get_password_policy(profile)
    has_password_policy = password_policy is not None
    
    # Create summary
    summary = {
        "AccountId": account_id,
        "AccountName": account_name,
        "IsControlTowerManaged": is_ct_managed,
        "IAMStatistics": {
            "TotalRoles": total_roles,
            "IdentityCenterRoles": identity_center_roles,
            "ServiceLinkedRoles": service_linked_roles,
            "UserCreatedRoles": user_created_roles,
            "TotalUsers": total_users,
            "UsersWithMFA": users_with_mfa,
            "TotalGroups": total_groups,
            "TotalCustomPolicies": total_policies,
            "HasPasswordPolicy": has_password_policy
        }
    }
    
    return summary

def export_to_csv(summaries, filename):
    """Export account summaries to CSV file"""
    if not summaries:
        print(f"[WARNING] No summaries to export to {filename}")
        return
    
    # Flatten the nested structure for CSV
    flat_summaries = []
    for summary in summaries:
        flat_summary = {
            "AccountId": summary.get("AccountId"),
            "AccountName": summary.get("AccountName"),
            "IsControlTowerManaged": summary.get("IsControlTowerManaged")
        }
        
        # Add IAM statistics
        iam_stats = summary.get("IAMStatistics", {})
        for key, value in iam_stats.items():
            flat_summary[key] = value
        
        flat_summaries.append(flat_summary)
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=flat_summaries[0].keys())
        writer.writeheader()
        writer.writerows(flat_summaries)
    
    print(f"[INFO] Exported {len(flat_summaries)} account summaries to {filename}")

def print_summary(summary):
    """Print account summary in a readable format"""
    print("\n" + "=" * 50)
    print(f"ACCOUNT SUMMARY: {summary['AccountName']} ({summary['AccountId']})")
    print("=" * 50)
    
    print(f"Control Tower Managed: {summary['IsControlTowerManaged']}")
    
    iam_stats = summary.get("IAMStatistics", {})
    
    print("\nIAM STATISTICS:")
    print(f"  Roles:")
    print(f"    Total Roles: {iam_stats.get('TotalRoles', 0)}")
    print(f"    Identity Center Roles: {iam_stats.get('IdentityCenterRoles', 0)} ({(iam_stats.get('IdentityCenterRoles', 0) / max(1, iam_stats.get('TotalRoles', 0)) * 100):.1f}%)")
    print(f"    Service-Linked Roles: {iam_stats.get('ServiceLinkedRoles', 0)} ({(iam_stats.get('ServiceLinkedRoles', 0) / max(1, iam_stats.get('TotalRoles', 0)) * 100):.1f}%)")
    print(f"    User-Created Roles: {iam_stats.get('UserCreatedRoles', 0)} ({(iam_stats.get('UserCreatedRoles', 0) / max(1, iam_stats.get('TotalRoles', 0)) * 100):.1f}%)")
    
    print(f"\n  Users and Groups:")
    print(f"    Total Users: {iam_stats.get('TotalUsers', 0)}")
    print(f"    Users with MFA: {iam_stats.get('UsersWithMFA', 0)} ({(iam_stats.get('UsersWithMFA', 0) / max(1, iam_stats.get('TotalUsers', 0)) * 100):.1f}%)")
    print(f"    Total Groups: {iam_stats.get('TotalGroups', 0)}")
    
    print(f"\n  Policies:")
    print(f"    Customer Managed Policies: {iam_stats.get('TotalCustomPolicies', 0)}")
    print(f"    Password Policy Configured: {iam_stats.get('HasPasswordPolicy', False)}")
    
    print("\n" + "=" * 50)

def main():
    parser = argparse.ArgumentParser(description="Generate AWS account summary statistics")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--output", default="account_summary.csv", help="Output CSV file")
    parser.add_argument("--accounts", nargs="+", help="List of account names to analyze")
    parser.add_argument("--profiles", nargs="+", help="List of AWS profiles to use (must match accounts)")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting account summary analysis...")
    
    summaries = []
    
    # Check if multiple accounts are specified
    if args.accounts and args.profiles and len(args.accounts) == len(args.profiles):
        for account_name, profile in zip(args.accounts, args.profiles):
            print(f"\n[INFO] Analyzing account: {account_name} (profile: {profile})")
            summary = get_account_summary(profile)
            summary["AccountName"] = account_name  # Override with provided name
            summaries.append(summary)
            print_summary(summary)
    else:
        # Single account analysis
        summary = get_account_summary(args.profile)
        summaries.append(summary)
        print_summary(summary)
    
    # Always export to CSV
    if summaries:
        export_to_csv(summaries, args.output)
        print(f"\n[INFO] Summary exported to {args.output}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()