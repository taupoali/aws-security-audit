#!/usr/bin/env python3

import csv
from pathlib import Path
from collections import defaultdict
import argparse
import json

def load_cross_account_findings():
    """Load cross-account findings from all account subdirectories"""
    data_dir = Path("data_collected")
    all_findings = []
    
    if not data_dir.exists():
        print(f"Warning: {data_dir} not found")
        return []
    
    for subdir in data_dir.iterdir():
        if subdir.is_dir():
            findings_file = subdir / "cross_account_findings.csv"
            if findings_file.exists():
                source_account = subdir.name.split('-')[-1] if '-' in subdir.name else subdir.name
                
                with open(findings_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row['source_account'] = source_account
                        all_findings.append(row)
    
    print(f"Loaded {len(all_findings)} cross-account findings from account subdirectories")
    return all_findings

def load_trust_policy_analysis():
    """Load trust policy analysis from all accounts"""
    trust_files = list(Path('.').glob('trust_policy_analysis_*.csv'))
    all_trust_data = []
    
    for file in trust_files:
        with open(file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                all_trust_data.append(row)
    
    print(f"Loaded {len(all_trust_data)} trust policy entries from {len(trust_files)} accounts")
    return all_trust_data

def load_identity_center_assignments():
    """Load Identity Center assignments"""
    assignments_file = Path("findings/identity_center_assignments.csv")
    if not assignments_file.exists():
        print("Warning: identity_center_assignments.csv not found")
        return []
    
    assignments = []
    with open(assignments_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignments.append(row)
    
    print(f"Loaded {len(assignments)} Identity Center assignments")
    return assignments

def analyze_cross_account_role_assumptions(cross_account_findings, trust_data):
    """Analyze potential cross-account role assumption chains"""
    # Build role assumption map
    role_assumptions = defaultdict(list)
    
    for finding in cross_account_findings:
        source_account = finding['source_account']
        # Look for AssumeRole permissions in findings
        if 'AssumeRole' in finding.get('action', '') or 'sts:AssumeRole' in finding.get('permissions', ''):
            target_role = finding.get('target_role', '')
            target_account = finding.get('target_account', '')
            
            if target_role and target_account:
                role_assumptions[source_account].append({
                    'target_account': target_account,
                    'target_role': target_role,
                    'source_role': finding.get('source_role', ''),
                    'finding_details': finding
                })
    
    return role_assumptions

def analyze_cross_account_trust_relationships(trust_data):
    """Analyze cross-account trust relationships from trust policies"""
    cross_account_trusts = []
    
    for trust_entry in trust_data:
        if trust_entry['PrincipalType'] == 'AWS_Role':
            principal_value = trust_entry['PrincipalValue']
            role_account = trust_entry['AccountId']
            
            # Extract account from principal ARN
            if ':role/' in principal_value:
                try:
                    principal_account = principal_value.split(':')[4]
                    if principal_account != role_account:  # Cross-account trust
                        cross_account_trusts.append({
                            'trusting_account': role_account,
                            'trusting_role': trust_entry['RoleName'],
                            'trusted_account': principal_account,
                            'trusted_principal': principal_value,
                            'risk_level': trust_entry['RiskLevel']
                        })
                except:
                    pass
        
        elif trust_entry['PrincipalType'] == 'AWS_Account':
            principal_value = trust_entry['PrincipalValue']
            role_account = trust_entry['AccountId']
            
            # Extract account from root principal
            if ':root' in principal_value:
                try:
                    principal_account = principal_value.split(':')[4]
                    if principal_account != role_account:  # Cross-account trust
                        cross_account_trusts.append({
                            'trusting_account': role_account,
                            'trusting_role': trust_entry['RoleName'],
                            'trusted_account': principal_account,
                            'trusted_principal': principal_value,
                            'risk_level': trust_entry['RiskLevel']
                        })
                except:
                    pass
    
    return cross_account_trusts

def find_escalation_paths(cross_account_trusts, assignments):
    """Find potential escalation paths through cross-account access"""
    escalation_paths = []
    
    # Create account access map from Identity Center
    user_account_access = defaultdict(set)
    for assignment in assignments:
        principal_id = assignment['PrincipalId']
        account_id = assignment['AccountId']
        user_account_access[principal_id].add(account_id)
    
    # Analyze each cross-account trust
    for trust in cross_account_trusts:
        trusting_account = trust['trusting_account']
        trusted_account = trust['trusted_account']
        
        # Check if users have access to both accounts
        for principal_id, accounts in user_account_access.items():
            if trusted_account in accounts and trusting_account in accounts:
                escalation_paths.append({
                    'principal_id': principal_id,
                    'path_type': 'Cross-Account Role Trust',
                    'source_account': trusted_account,
                    'target_account': trusting_account,
                    'target_role': trust['trusting_role'],
                    'risk_level': trust['risk_level'],
                    'path_description': f"User in {trusted_account} could assume {trust['trusting_role']} in {trusting_account}"
                })
    
    return escalation_paths

def analyze_organization_attack_surface(cross_account_trusts, assignments):
    """Analyze organization-wide attack surface"""
    # Account connectivity analysis
    account_connections = defaultdict(set)
    for trust in cross_account_trusts:
        account_connections[trust['trusted_account']].add(trust['trusting_account'])
    
    # Multi-hop path detection with detailed role information
    multi_hop_paths = []
    
    # Create detailed trust mapping
    detailed_trusts = {}
    for trust in cross_account_trusts:
        key = f"{trust['trusted_account']}->{trust['trusting_account']}"
        if key not in detailed_trusts:
            detailed_trusts[key] = []
        detailed_trusts[key].append(trust)
    
    for source_account, direct_targets in account_connections.items():
        for target_account in direct_targets:
            # Check if target account can reach other accounts
            if target_account in account_connections:
                for final_target in account_connections[target_account]:
                    if final_target != source_account:  # Avoid circular paths
                        
                        # Get detailed trust information for each hop
                        hop1_key = f"{source_account}->{target_account}"
                        hop2_key = f"{target_account}->{final_target}"
                        
                        hop1_trusts = detailed_trusts.get(hop1_key, [])
                        hop2_trusts = detailed_trusts.get(hop2_key, [])
                        
                        # Create detailed path for each combination
                        for hop1_trust in hop1_trusts:
                            for hop2_trust in hop2_trusts:
                                multi_hop_paths.append({
                                    'source_account': source_account,
                                    'intermediate_account': target_account,
                                    'final_account': final_target,
                                    'hop_count': 2,
                                    'risk_level': 'HIGH',
                                    'hop1_trusting_role': hop1_trust['trusting_role'],
                                    'hop1_trusted_principal': hop1_trust['trusted_principal'],
                                    'hop2_trusting_role': hop2_trust['trusting_role'],
                                    'hop2_trusted_principal': hop2_trust['trusted_principal'],
                                    'attack_path': f"Principal in {source_account} → {hop1_trust['trusting_role']} in {target_account} → {hop2_trust['trusting_role']} in {final_target}"
                                })
    
    # User access breadth analysis
    user_access_breadth = defaultdict(set)
    for assignment in assignments:
        principal_id = assignment['PrincipalId']
        account_id = assignment['AccountId']
        user_access_breadth[principal_id].add(account_id)
    
    high_access_users = []
    for principal_id, accounts in user_access_breadth.items():
        if len(accounts) >= 5:  # Users with access to 5+ accounts
            high_access_users.append({
                'principal_id': principal_id,
                'account_count': len(accounts),
                'accounts': list(accounts),
                'risk_level': 'HIGH' if len(accounts) >= 10 else 'MEDIUM'
            })
    
    return {
        'account_connections': dict(account_connections),
        'multi_hop_paths': multi_hop_paths,
        'high_access_users': high_access_users
    }

def main():
    parser = argparse.ArgumentParser(description='Analyze cross-account escalation paths across organization')
    args = parser.parse_args()
    
    print("=== Cross-Account Escalation Analysis ===")
    
    # Load all data
    cross_account_findings = load_cross_account_findings()
    trust_data = load_trust_policy_analysis()
    assignments = load_identity_center_assignments()
    
    # Analyze cross-account trust relationships
    cross_account_trusts = analyze_cross_account_trust_relationships(trust_data)
    
    # Find potential escalation paths
    escalation_paths = find_escalation_paths(cross_account_trusts, assignments)
    
    # Analyze organization attack surface
    attack_surface = analyze_organization_attack_surface(cross_account_trusts, assignments)
    
    # Save cross-account trust analysis
    with open('cross_account_trust_relationships.csv', 'w', newline='', encoding='utf-8') as f:
        if cross_account_trusts:
            writer = csv.DictWriter(f, fieldnames=['trusting_account', 'trusting_role', 'trusted_account', 'trusted_principal', 'risk_level'])
            writer.writeheader()
            writer.writerows(cross_account_trusts)
    
    # Save escalation paths
    with open('cross_account_escalation_paths.csv', 'w', newline='', encoding='utf-8') as f:
        if escalation_paths:
            writer = csv.DictWriter(f, fieldnames=['principal_id', 'path_type', 'source_account', 'target_account', 'target_role', 'risk_level', 'path_description'])
            writer.writeheader()
            writer.writerows(escalation_paths)
    
    # Save multi-hop paths with detailed role information
    with open('cross_account_multi_hop_paths_detailed.csv', 'w', newline='', encoding='utf-8') as f:
        if attack_surface['multi_hop_paths']:
            writer = csv.DictWriter(f, fieldnames=['source_account', 'intermediate_account', 'final_account', 'hop_count', 'risk_level', 'hop1_trusting_role', 'hop1_trusted_principal', 'hop2_trusting_role', 'hop2_trusted_principal', 'attack_path'])
            writer.writeheader()
            writer.writerows(attack_surface['multi_hop_paths'])
    
    # Save high access users
    with open('cross_account_high_access_users.csv', 'w', newline='', encoding='utf-8') as f:
        if attack_surface['high_access_users']:
            fieldnames = ['principal_id', 'account_count', 'risk_level', 'accounts']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for user in attack_surface['high_access_users']:
                user_row = user.copy()
                user_row['accounts'] = ', '.join(user['accounts'])
                writer.writerow(user_row)
    
    # Generate summary
    print(f"\n=== Cross-Account Analysis Results ===")
    print(f"Cross-account trust relationships: {len(cross_account_trusts)}")
    print(f"Potential escalation paths: {len(escalation_paths)}")
    print(f"Multi-hop paths detected: {len(attack_surface['multi_hop_paths'])}")
    print(f"High-access users (5+ accounts): {len(attack_surface['high_access_users'])}")
    
    # Key security findings
    print(f"\n=== Security Assessment ===")
    if len(cross_account_trusts) == 0:
        print("✅ EXCELLENT: No cross-account role trust relationships found")
        print("   Cross-account privilege escalation via role chaining is impossible")
    else:
        print(f"⚠️  WARNING: {len(cross_account_trusts)} cross-account trust relationships detected")
        print("   Review these for potential privilege escalation risks")
    
    if len(escalation_paths) == 0:
        print("✅ GOOD: No direct escalation paths through cross-account trusts")
    else:
        print(f"⚠️  RISK: {len(escalation_paths)} potential escalation paths identified")
    
    if len(attack_surface['multi_hop_paths']) == 0:
        print("✅ GOOD: No multi-hop attack paths detected")
    else:
        print(f"⚠️  RISK: {len(attack_surface['multi_hop_paths'])} multi-hop paths possible")
        print(f"   Check cross_account_multi_hop_paths_detailed.csv for specific roles to fix")
    
    print(f"\nFiles created:")
    print(f"- cross_account_trust_relationships.csv (all cross-account trusts)")
    print(f"- cross_account_escalation_paths.csv (user escalation paths)") 
    print(f"- cross_account_multi_hop_paths_detailed.csv (detailed A→B→C paths with roles)")
    print(f"- cross_account_high_access_users.csv (users with broad access)")
    
    # Show remediation guidance
    if len(cross_account_trusts) > 0:
        print(f"\n=== Remediation Guidance ===")
        print(f"To fix cross-account trust relationships:")
        print(f"1. Review cross_account_trust_relationships.csv")
        print(f"2. For each trust, evaluate if it's necessary")
        print(f"3. Remove unnecessary trusts by modifying role trust policies")
        print(f"4. Replace with Identity Center assignments where possible")
        
    if len(attack_surface['multi_hop_paths']) > 0:
        print(f"\nTo fix multi-hop paths:")
        print(f"1. Review cross_account_multi_hop_paths_detailed.csv")
        print(f"2. Focus on 'hop1_trusting_role' and 'hop2_trusting_role' columns")
        print(f"3. Remove trust policies for these specific roles")
        print(f"4. Check 'attack_path' column for complete escalation description")

if __name__ == "__main__":
    main()