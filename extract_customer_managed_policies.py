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
        print(f"Error running command: {command}")
        return None
    except json.JSONDecodeError:
        return None

def get_permission_set_policies(identity_center_file):
    """Extract customer managed policy ARNs from Identity Center assignments"""
    if not Path(identity_center_file).exists():
        print(f"File not found: {identity_center_file}")
        return {}
    
    policy_arns = set()
    with open(identity_center_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Look for customer managed policy references
            policy_details = row.get('PolicyDetails', '')
            if 'arn:aws:iam::' in policy_details and ':policy/' in policy_details:
                # Extract ARNs from policy details
                import re
                arns = re.findall(r'arn:aws:iam::\d+:policy/[^,\s"]+', policy_details)
                policy_arns.update(arns)
    
    print(f"Found {len(policy_arns)} customer managed policy references")
    return policy_arns

def extract_account_from_arn(arn):
    """Extract account ID from policy ARN"""
    parts = arn.split(':')
    return parts[4] if len(parts) > 4 else None

def get_policy_document(policy_arn, profile=None):
    """Get policy document for a customer managed policy"""
    account_id = extract_account_from_arn(policy_arn)
    policy_name = policy_arn.split('/')[-1]
    
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
        'AccountId': account_id,
        'VersionId': default_version,
        'PolicyDocument': policy_version['PolicyVersion']['Document']
    }

def analyze_policy_permissions(policy_doc):
    """Analyze policy document for privilege level"""
    if not policy_doc or 'Statement' not in policy_doc:
        return 'Unknown'
    
    risk_level = 'LOW'
    high_risk_actions = ['*', 'iam:*', 'sts:AssumeRole', 'organizations:*']
    admin_actions = ['*']
    
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
        if any(action in admin_actions for action in actions):
            if '*' in resources:
                return 'CRITICAL'
            else:
                risk_level = 'HIGH'
        
        # Check for high-risk actions
        elif any(any(risk in action for risk in high_risk_actions) for action in actions):
            risk_level = 'HIGH' if risk_level != 'CRITICAL' else risk_level
        
        # Check for broad resource access
        elif '*' in resources and len(actions) > 5:
            risk_level = 'MEDIUM' if risk_level == 'LOW' else risk_level
    
    return risk_level

def main():
    parser = argparse.ArgumentParser(description='Extract and analyze customer managed policies from Identity Center')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--identity-center-file', default='data_collected/identity_center_findings.csv', 
                       help='Identity Center findings CSV file')
    args = parser.parse_args()
    
    print("=== Customer Managed Policy Analysis ===")
    
    # Get policy ARNs from Identity Center data
    policy_arns = get_permission_set_policies(args.identity_center_file)
    
    if not policy_arns:
        print("No customer managed policies found in Identity Center data")
        return
    
    # Group policies by account
    policies_by_account = {}
    for arn in policy_arns:
        account_id = extract_account_from_arn(arn)
        if account_id:
            if account_id not in policies_by_account:
                policies_by_account[account_id] = []
            policies_by_account[account_id].append(arn)
    
    print(f"Found policies across {len(policies_by_account)} accounts")
    
    # Extract policy documents
    all_policies = []
    
    for account_id, arns in policies_by_account.items():
        print(f"\nProcessing account {account_id} ({len(arns)} policies)...")
        
        for arn in arns:
            print(f"  Extracting: {arn.split('/')[-1]}")
            
            policy_data = get_policy_document(arn, args.profile)
            if policy_data:
                # Analyze permissions
                risk_level = analyze_policy_permissions(policy_data['PolicyDocument'])
                policy_data['RiskLevel'] = risk_level
                
                all_policies.append(policy_data)
            else:
                print(f"    Failed to extract policy: {arn}")
    
    # Save results
    if all_policies:
        # Detailed policy documents
        with open('customer_managed_policies.json', 'w', encoding='utf-8') as f:
            json.dump(all_policies, f, indent=2, default=str)
        
        # Summary CSV
        with open('customer_managed_policies_summary.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['PolicyArn', 'PolicyName', 'AccountId', 'RiskLevel', 'StatementCount'])
            
            for policy in all_policies:
                statement_count = len(policy['PolicyDocument'].get('Statement', []))
                writer.writerow([
                    policy['PolicyArn'],
                    policy['PolicyName'], 
                    policy['AccountId'],
                    policy['RiskLevel'],
                    statement_count
                ])
        
        print(f"\n=== Results ===")
        print(f"Extracted {len(all_policies)} customer managed policies")
        
        risk_counts = {}
        for policy in all_policies:
            risk = policy['RiskLevel']
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        for risk, count in sorted(risk_counts.items()):
            print(f"{risk} risk policies: {count}")
        
        print(f"\nFiles created:")
        print(f"- customer_managed_policies.json (detailed policy documents)")
        print(f"- customer_managed_policies_summary.csv (risk summary)")
    
    else:
        print("No policies could be extracted")

if __name__ == "__main__":
    main()