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

def load_permission_set_policies():
    """Load permission set customer policy references"""
    policy_file = Path("permission_set_customer_policies.csv")
    if not policy_file.exists():
        print(f"File not found: {policy_file}")
        print("Run extract_permission_set_policies.py first")
        return []
    
    policies = []
    with open(policy_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            policies.append(row)
    
    print(f"Loaded {len(policies)} permission set policy references")
    return policies

def load_assignments():
    """Load assignments to map permission sets to accounts"""
    assignments_file = Path("findings/identity_center_assignments.csv")
    if not assignments_file.exists():
        print(f"File not found: {assignments_file}")
        return []
    
    assignments = []
    with open(assignments_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignments.append(row)
    
    return assignments

def get_policy_document(policy_name, policy_path, profile=None):
    """Get policy document from current account"""
    policy_arn = f"arn:aws:iam::{get_account_id(profile)}:policy{policy_path}{policy_name}"
    
    # Get policy version
    policy_info = run_aws_command(f"aws iam get-policy --policy-arn {policy_arn}", profile)
    if not policy_info:
        return None
    
    default_version = policy_info['Policy']['DefaultVersionId']
    
    # Get policy document
    policy_version = run_aws_command(f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version}", profile)
    if not policy_version:
        return None
    
    return policy_version['PolicyVersion']['Document']

def get_account_id(profile=None):
    """Get current account ID"""
    result = run_aws_command("aws sts get-caller-identity", profile)
    if result:
        return result.get('Account')
    return 'unknown'

def analyze_policy_risk(policy_doc):
    """Analyze policy document for privilege level"""
    if not policy_doc or 'Statement' not in policy_doc:
        return 'UNKNOWN', []
    
    risk_level = 'LOW'
    risk_reasons = []
    
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
                return 'CRITICAL', ['Full administrative access (*:* on all resources)']
            else:
                risk_level = 'HIGH'
                risk_reasons.append('Wildcard actions on specific resources')
        
        # Check for high-risk actions
        high_risk_patterns = ['iam:*', 'sts:AssumeRole', 'organizations:*', 'sts:*']
        for pattern in high_risk_patterns:
            if any(pattern in action for action in actions):
                if risk_level not in ['CRITICAL', 'HIGH']:
                    risk_level = 'HIGH'
                risk_reasons.append(f'High-risk action pattern: {pattern}')
        
        # Check for broad resource access
        if '*' in resources and len(actions) > 3:
            if risk_level == 'LOW':
                risk_level = 'MEDIUM'
            risk_reasons.append('Broad resource access with multiple actions')
    
    return risk_level, risk_reasons

def main():
    parser = argparse.ArgumentParser(description='Analyze customer managed policies used by permission sets')
    parser.add_argument('--profile', required=True, help='AWS profile to use for current account')
    args = parser.parse_args()
    
    print("=== Permission Set Policy Analysis ===")
    print(f"Using profile: {args.profile}")
    
    # Get current account ID
    account_id = get_account_id(args.profile)
    print(f"Current account: {account_id}")
    
    # Load permission set policies and assignments
    permission_set_policies = load_permission_set_policies()
    assignments = load_assignments()
    
    if not permission_set_policies:
        return
    
    # Create mapping of permission sets to accounts
    perm_set_accounts = {}
    for assignment in assignments:
        perm_set = assignment['PermissionSetName']
        account = assignment['AccountId']
        if perm_set not in perm_set_accounts:
            perm_set_accounts[perm_set] = set()
        perm_set_accounts[perm_set].add(account)
    
    # Analyze policies for current account
    results = []
    
    for policy_ref in permission_set_policies:
        perm_set_name = policy_ref['PermissionSetName']
        policy_name = policy_ref['PolicyName']
        policy_path = policy_ref['PolicyPath']
        
        # Check if this permission set is used in current account
        if perm_set_name in perm_set_accounts and account_id in perm_set_accounts[perm_set_name]:
            print(f"\nAnalyzing: {perm_set_name} -> {policy_name}")
            
            # Get policy document
            policy_doc = get_policy_document(policy_name, policy_path, args.profile)
            
            if policy_doc:
                # Analyze risk
                risk_level, risk_reasons = analyze_policy_risk(policy_doc)
                
                results.append({
                    'AccountId': account_id,
                    'PermissionSetName': perm_set_name,
                    'PolicyName': policy_name,
                    'PolicyPath': policy_path,
                    'RiskLevel': risk_level,
                    'RiskReasons': '; '.join(risk_reasons),
                    'StatementCount': len(policy_doc.get('Statement', [])),
                    'PolicyDocument': json.dumps(policy_doc, indent=2)
                })
                
                print(f"  Risk Level: {risk_level}")
                if risk_reasons:
                    for reason in risk_reasons:
                        print(f"    - {reason}")
            else:
                print(f"  Failed to retrieve policy document")
                results.append({
                    'AccountId': account_id,
                    'PermissionSetName': perm_set_name,
                    'PolicyName': policy_name,
                    'PolicyPath': policy_path,
                    'RiskLevel': 'ERROR',
                    'RiskReasons': 'Failed to retrieve policy document',
                    'StatementCount': 0,
                    'PolicyDocument': ''
                })
    
    # Save results
    if results:
        output_file = f'permission_set_analysis_{account_id}.csv'
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['AccountId', 'PermissionSetName', 'PolicyName', 'PolicyPath', 'RiskLevel', 'RiskReasons', 'StatementCount', 'PolicyDocument'])
            writer.writeheader()
            writer.writerows(results)
        
        print(f"\n=== Results for Account {account_id} ===")
        print(f"Analyzed {len(results)} policies")
        
        risk_counts = {}
        for result in results:
            risk = result['RiskLevel']
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        for risk, count in sorted(risk_counts.items()):
            print(f"{risk} risk policies: {count}")
        
        print(f"\nResults saved to: {output_file}")
    else:
        print(f"No customer managed policies found for permission sets in account {account_id}")

if __name__ == "__main__":
    main()