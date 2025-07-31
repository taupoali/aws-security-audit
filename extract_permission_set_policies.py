#!/usr/bin/env python3

import subprocess
import json
import csv
from pathlib import Path
import argparse

def run_aws_command(command, profile=None):
    """Run AWS CLI command and return JSON output"""
    if profile:
        command += f" --profile {profile}"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return None
    except json.JSONDecodeError:
        return None

def get_sso_instance(profile=None):
    """Get SSO instance ID and Identity Store ID"""
    result = run_aws_command("aws sso-admin list-instances", profile)
    if result and 'Instances' in result and len(result['Instances']) > 0:
        instance = result['Instances'][0]
        return instance['InstanceArn'], instance['IdentityStoreId']
    return None, None

def get_permission_sets_from_assignments(assignments_file):
    """Extract unique permission sets from assignments"""
    if not Path(assignments_file).exists():
        print(f"File not found: {assignments_file}")
        return set()
    
    permission_sets = set()
    with open(assignments_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            perm_set = row.get('PermissionSetName', '').strip()
            if perm_set:
                permission_sets.add(perm_set)
    
    print(f"Found {len(permission_sets)} unique permission sets")
    return permission_sets

def get_permission_set_arn(instance_arn, permission_set_name, profile=None):
    """Get permission set ARN from name"""
    result = run_aws_command(f"aws sso-admin list-permission-sets --instance-arn {instance_arn}", profile)
    if not result:
        return None
    
    # Get details for each permission set to find the matching name
    for perm_set_arn in result.get('PermissionSets', []):
        details = run_aws_command(f"aws sso-admin describe-permission-set --instance-arn {instance_arn} --permission-set-arn {perm_set_arn}", profile)
        if details and details.get('PermissionSet', {}).get('Name') == permission_set_name:
            return perm_set_arn
    
    return None

def get_customer_managed_policies(instance_arn, permission_set_arn, profile=None):
    """Get customer managed policies for a permission set"""
    result = run_aws_command(f"aws sso-admin list-customer-managed-policy-references-in-permission-set --instance-arn {instance_arn} --permission-set-arn {permission_set_arn}", profile)
    if result:
        return result.get('CustomerManagedPolicyReferences', [])
    return []

def get_policy_document(policy_name, policy_path, account_id, profile=None):
    """Get policy document from specific account"""
    policy_arn = f"arn:aws:iam::{account_id}:policy{policy_path}{policy_name}"
    
    # Get policy version
    policy_info = run_aws_command(f"aws iam get-policy --policy-arn {policy_arn}", profile)
    if not policy_info:
        return None
    
    default_version = policy_info['Policy']['DefaultVersionId']
    
    # Get policy document
    policy_version = run_aws_command(f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version}", profile)
    if not policy_version:
        return None
    
    return {
        'PolicyArn': policy_arn,
        'PolicyName': policy_name,
        'PolicyPath': policy_path,
        'AccountId': account_id,
        'VersionId': default_version,
        'PolicyDocument': policy_version['PolicyVersion']['Document']
    }

def analyze_policy_risk(policy_doc):
    """Analyze policy document for risk level"""
    if not policy_doc or 'Statement' not in policy_doc:
        return 'UNKNOWN'
    
    risk_level = 'LOW'
    
    for statement in policy_doc['Statement']:
        if statement.get('Effect') != 'Allow':
            continue
            
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for admin permissions
        if '*' in actions:
            if '*' in resources:
                return 'CRITICAL'
            else:
                risk_level = 'HIGH'
        
        # Check for high-risk actions
        high_risk = ['iam:*', 'sts:AssumeRole', 'organizations:*', 'sts:*']
        if any(any(risk in action for risk in high_risk) for action in actions):
            risk_level = 'HIGH' if risk_level != 'CRITICAL' else risk_level
        
        # Check for broad resource access
        elif '*' in resources and len(actions) > 3:
            risk_level = 'MEDIUM' if risk_level == 'LOW' else risk_level
    
    return risk_level

def main():
    parser = argparse.ArgumentParser(description='Extract customer managed policies from Identity Center permission sets')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--assignments-file', default='findings/identity_center_assignments.csv', 
                       help='Identity Center assignments CSV file')
    args = parser.parse_args()
    
    print("=== Permission Set Policy Extraction ===")
    
    # Get SSO instance
    instance_arn, identity_store_id = get_sso_instance(args.profile)
    if not instance_arn:
        print("Failed to get SSO instance")
        return
    
    print(f"Using SSO instance: {instance_arn}")
    
    # Get permission sets from assignments
    permission_sets = get_permission_sets_from_assignments(args.assignments_file)
    if not permission_sets:
        print("No permission sets found")
        return
    
    # Extract customer managed policies
    all_policies = []
    permission_set_policies = []
    
    for perm_set_name in permission_sets:
        print(f"\nProcessing permission set: {perm_set_name}")
        
        # Get permission set ARN
        perm_set_arn = get_permission_set_arn(instance_arn, perm_set_name, args.profile)
        if not perm_set_arn:
            print(f"  Could not find ARN for {perm_set_name}")
            continue
        
        # Get customer managed policies
        customer_policies = get_customer_managed_policies(instance_arn, perm_set_arn, args.profile)
        
        if customer_policies:
            print(f"  Found {len(customer_policies)} customer managed policies")
            
            for policy_ref in customer_policies:
                policy_name = policy_ref['Name']
                policy_path = policy_ref.get('Path', '/')
                
                # Need to determine which accounts this permission set is used in
                # For now, we'll record the policy reference and handle account-specific extraction separately
                permission_set_policies.append({
                    'PermissionSetName': perm_set_name,
                    'PermissionSetArn': perm_set_arn,
                    'PolicyName': policy_name,
                    'PolicyPath': policy_path,
                    'PolicyArn': f"arn:aws:iam::{{account_id}}:policy{policy_path}{policy_name}"
                })
                
                print(f"    - {policy_name} (path: {policy_path})")
        else:
            print(f"  No customer managed policies found")
    
    # Save permission set policy references
    if permission_set_policies:
        with open('permission_set_customer_policies.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['PermissionSetName', 'PermissionSetArn', 'PolicyName', 'PolicyPath', 'PolicyArn'])
            writer.writeheader()
            writer.writerows(permission_set_policies)
        
        print(f"\n=== Results ===")
        print(f"Found {len(permission_set_policies)} customer managed policy references")
        print(f"Across {len(set(p['PermissionSetName'] for p in permission_set_policies))} permission sets")
        
        print(f"\nFiles created:")
        print(f"- permission_set_customer_policies.csv (policy references)")
        print(f"\nNext step: Use this file with account-specific profiles to extract actual policy documents")
        
        # Show unique policies that need to be extracted
        unique_policies = set((p['PolicyName'], p['PolicyPath']) for p in permission_set_policies)
        print(f"\nUnique policies to extract: {len(unique_policies)}")
        for policy_name, policy_path in sorted(unique_policies):
            print(f"  - {policy_name} (path: {policy_path})")
    
    else:
        print("No customer managed policies found in any permission sets")

if __name__ == "__main__":
    main()