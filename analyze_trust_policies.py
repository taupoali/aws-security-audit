#!/usr/bin/env python3

import subprocess
import json
import csv
from pathlib import Path
import argparse
from datetime import datetime
import urllib.parse

def run_aws_command(command, profile=None):
    """Run AWS CLI command and return JSON output"""
    if profile:
        command += f" --profile {profile}"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e.stderr}")
        return None
    except json.JSONDecodeError:
        return None

def get_account_id(profile=None):
    """Get current account ID"""
    result = run_aws_command("aws sts get-caller-identity", profile)
    if result:
        return result.get('Account', 'unknown')
    return 'unknown'

def list_iam_roles(profile=None):
    """Get all IAM roles with caching"""
    cache_file = Path(f"cache_roles_{profile or 'default'}.json")
    
    # Check cache first
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
                print(f"Using cached role data from {cache_file}")
                return cached_data
        except:
            pass
    
    print("Fetching IAM roles from AWS...")
    roles = []
    marker = None
    
    while True:
        cmd = "aws iam list-roles --max-items 100"
        if marker:
            cmd += f" --starting-token {marker}"
        
        result = run_aws_command(cmd, profile)
        if not result:
            break
        
        roles.extend(result.get('Roles', []))
        marker = result.get('NextToken')
        if not marker:
            break
        
        print(f"  Fetched {len(roles)} roles so far...")
    
    # Cache the results
    with open(cache_file, 'w') as f:
        json.dump(roles, f, indent=2, default=str)
    
    print(f"Cached {len(roles)} roles to {cache_file}")
    return roles

def analyze_trust_policy(trust_policy_doc):
    """Analyze trust policy document and extract principals"""
    if not trust_policy_doc or 'Statement' not in trust_policy_doc:
        return []
    
    principals = []
    
    for statement in trust_policy_doc['Statement']:
        if statement.get('Effect') != 'Allow':
            continue
        
        principal = statement.get('Principal', {})
        
        # Handle different principal formats
        if isinstance(principal, str):
            if principal == '*':
                principals.append({
                    'Type': 'Wildcard',
                    'Value': '*',
                    'RiskLevel': 'CRITICAL'
                })
        elif isinstance(principal, dict):
            # AWS principals (roles, users, accounts)
            if 'AWS' in principal:
                aws_principals = principal['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                
                for aws_principal in aws_principals:
                    if aws_principal == '*':
                        principals.append({
                            'Type': 'AWS_Wildcard',
                            'Value': '*',
                            'RiskLevel': 'CRITICAL'
                        })
                    elif ':root' in aws_principal:
                        principals.append({
                            'Type': 'AWS_Account',
                            'Value': aws_principal,
                            'RiskLevel': 'HIGH'
                        })
                    elif ':role/' in aws_principal:
                        principals.append({
                            'Type': 'AWS_Role',
                            'Value': aws_principal,
                            'RiskLevel': 'HIGH'
                        })
                    elif ':user/' in aws_principal:
                        principals.append({
                            'Type': 'AWS_User',
                            'Value': aws_principal,
                            'RiskLevel': 'MEDIUM'
                        })
                    else:
                        principals.append({
                            'Type': 'AWS_Other',
                            'Value': aws_principal,
                            'RiskLevel': 'MEDIUM'
                        })
            
            # Federated principals (SAML, OIDC)
            if 'Federated' in principal:
                fed_principals = principal['Federated']
                if isinstance(fed_principals, str):
                    fed_principals = [fed_principals]
                
                for fed_principal in fed_principals:
                    if 'saml-provider' in fed_principal:
                        if 'AWSSSO' in fed_principal:
                            principals.append({
                                'Type': 'SAML_SSO',
                                'Value': fed_principal,
                                'RiskLevel': 'LOW'
                            })
                        else:
                            principals.append({
                                'Type': 'SAML_Other',
                                'Value': fed_principal,
                                'RiskLevel': 'MEDIUM'
                            })
                    elif 'oidc-provider' in fed_principal:
                        principals.append({
                            'Type': 'OIDC',
                            'Value': fed_principal,
                            'RiskLevel': 'MEDIUM'
                        })
                    else:
                        principals.append({
                            'Type': 'Federated_Other',
                            'Value': fed_principal,
                            'RiskLevel': 'MEDIUM'
                        })
            
            # Service principals
            if 'Service' in principal:
                service_principals = principal['Service']
                if isinstance(service_principals, str):
                    service_principals = [service_principals]
                
                for service_principal in service_principals:
                    principals.append({
                        'Type': 'AWS_Service',
                        'Value': service_principal,
                        'RiskLevel': 'LOW'
                    })
    
    return principals

def main():
    parser = argparse.ArgumentParser(description='Analyze IAM role trust policies')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--clear-cache', action='store_true', help='Clear cached role data')
    parser.add_argument('--account-name', help='Friendly name for account')
    args = parser.parse_args()
    
    print("=== IAM Trust Policy Analysis ===")
    if args.profile:
        print(f"Using AWS profile: {args.profile}")
    
    # Clear cache if requested
    if args.clear_cache:
        cache_file = Path(f"cache_roles_{args.profile or 'default'}.json")
        if cache_file.exists():
            cache_file.unlink()
            print("Cleared role cache")
    
    # Get account info
    account_id = get_account_id(args.profile)
    account_name = args.account_name or account_id
    print(f"Account: {account_name} ({account_id})")
    
    # Get all roles
    roles = list_iam_roles(args.profile)
    if not roles:
        print("No roles found or failed to retrieve roles")
        return
    
    print(f"Analyzing trust policies for {len(roles)} roles...")
    
    # Analyze trust policies
    trust_analysis = []
    role_summary = []
    
    for i, role in enumerate(roles, 1):
        role_name = role['RoleName']
        role_arn = role['Arn']
        created_date = role.get('CreateDate', 'Unknown')
        
        print(f"  [{i}/{len(roles)}] Analyzing: {role_name}")
        
        # Parse trust policy
        trust_policy_doc = role.get('AssumeRolePolicyDocument')
        if trust_policy_doc:
            # URL decode if needed
            if isinstance(trust_policy_doc, str):
                trust_policy_doc = urllib.parse.unquote(trust_policy_doc)
                trust_policy_doc = json.loads(trust_policy_doc)
        
        principals = analyze_trust_policy(trust_policy_doc)
        
        # Determine overall risk level for role
        if not principals:
            role_risk = 'UNKNOWN'
        else:
            risk_levels = [p['RiskLevel'] for p in principals]
            if 'CRITICAL' in risk_levels:
                role_risk = 'CRITICAL'
            elif 'HIGH' in risk_levels:
                role_risk = 'HIGH'
            elif 'MEDIUM' in risk_levels:
                role_risk = 'MEDIUM'
            else:
                role_risk = 'LOW'
        
        # Role summary
        role_summary.append({
            'AccountId': account_id,
            'AccountName': account_name,
            'RoleName': role_name,
            'RoleArn': role_arn,
            'CreatedDate': created_date,
            'PrincipalCount': len(principals),
            'RiskLevel': role_risk,
            'PrincipalTypes': ', '.join(set(p['Type'] for p in principals))
        })
        
        # Detailed principal analysis
        for principal in principals:
            trust_analysis.append({
                'AccountId': account_id,
                'AccountName': account_name,
                'RoleName': role_name,
                'RoleArn': role_arn,
                'PrincipalType': principal['Type'],
                'PrincipalValue': principal['Value'],
                'RiskLevel': principal['RiskLevel']
            })
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Detailed trust analysis
    trust_file = f'trust_policy_analysis_{account_id}.csv'
    with open(trust_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['AccountId', 'AccountName', 'RoleName', 'RoleArn', 'PrincipalType', 'PrincipalValue', 'RiskLevel'])
        writer.writeheader()
        writer.writerows(trust_analysis)
    
    # Role summary
    summary_file = f'trust_policy_summary_{account_id}.csv'
    with open(summary_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['AccountId', 'AccountName', 'RoleName', 'RoleArn', 'CreatedDate', 'PrincipalCount', 'RiskLevel', 'PrincipalTypes'])
        writer.writeheader()
        writer.writerows(role_summary)
    
    print(f"\n=== Analysis Complete ===")
    print(f"Files created:")
    print(f"- {trust_file} (detailed principal analysis)")
    print(f"- {summary_file} (role summary)")
    
    # Statistics
    print(f"\n=== Trust Policy Statistics ===")
    print(f"Total roles analyzed: {len(roles)}")
    
    # Principal type counts
    principal_counts = {}
    for analysis in trust_analysis:
        ptype = analysis['PrincipalType']
        principal_counts[ptype] = principal_counts.get(ptype, 0) + 1
    
    print(f"\nPrincipal types found:")
    for ptype, count in sorted(principal_counts.items()):
        print(f"  {ptype}: {count}")
    
    # Risk level counts
    risk_counts = {}
    for summary in role_summary:
        risk = summary['RiskLevel']
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    print(f"\nRole risk distribution:")
    for risk, count in sorted(risk_counts.items()):
        print(f"  {risk}: {count}")
    
    # Key findings
    role_to_role_trusts = len([a for a in trust_analysis if a['PrincipalType'] == 'AWS_Role'])
    sso_only_roles = len([a for a in trust_analysis if a['PrincipalType'] == 'SAML_SSO'])
    
    print(f"\n=== Key Security Findings ===")
    print(f"Roles with role-to-role trust: {role_to_role_trusts}")
    print(f"Roles with SSO-only trust: {sso_only_roles}")
    
    if role_to_role_trusts == 0:
        print("✅ EXCELLENT: No role-to-role trust relationships found")
        print("   This proves privilege escalation via role chaining is impossible")
    else:
        print("⚠️  WARNING: Role-to-role trust relationships detected")
        print("   Review these for potential privilege escalation paths")

if __name__ == "__main__":
    main()