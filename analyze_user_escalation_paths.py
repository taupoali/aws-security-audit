#!/usr/bin/env python3

import csv
import json
from pathlib import Path
from collections import defaultdict
import argparse

def load_user_mappings():
    """Load Identity Center user mappings"""
    user_file = Path("data_collected/identity_center_user_mapping.csv")
    if not user_file.exists():
        print(f"Warning: {user_file} not found")
        return {}
    
    users = {}
    with open(user_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row['PrincipalId']] = {
                'username': row['Username'],
                'display_name': row['DisplayName']
            }
    
    print(f"Loaded {len(users)} user mappings")
    return users

def load_group_mappings():
    """Load Identity Center group mappings"""
    group_file = Path("identity_center_group_mapping.csv")
    if not group_file.exists():
        print(f"Warning: {group_file} not found")
        return {}, {}
    
    groups = {}
    group_members = defaultdict(list)
    
    with open(group_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            group_id = row['GroupId']
            if group_id not in groups:
                groups[group_id] = row['GroupName']
            
            if row['UserId']:  # Skip empty rows
                group_members[group_id].append(row['UserId'])
    
    print(f"Loaded {len(groups)} groups with memberships")
    return groups, group_members

def load_identity_center_assignments():
    """Load Identity Center assignments"""
    assignments_file = Path("data_collected/identity_center_assignments.csv")
    if not assignments_file.exists():
        print(f"Warning: {assignments_file} not found")
        return []
    
    assignments = []
    with open(assignments_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignments.append(row)
    
    print(f"Loaded {len(assignments)} Identity Center assignments")
    return assignments

def load_escalation_chains():
    """Load escalation chains from all account subdirectories"""
    data_dir = Path("data_collected")
    all_chains = []
    
    for subdir in data_dir.iterdir():
        if subdir.is_dir():
            chains_file = subdir / "escalation_chains.csv"
            if chains_file.exists():
                account_id = subdir.name.split('-')[-1] if '-' in subdir.name else subdir.name
                
                with open(chains_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row['source_account'] = account_id
                        all_chains.append(row)
    
    print(f"Loaded {len(all_chains)} escalation chains from account subdirectories")
    return all_chains

def get_user_roles(user_id, assignments, group_members):
    """Get all roles a user can access (direct + group memberships)"""
    user_roles = []
    
    # Direct assignments
    for assignment in assignments:
        if assignment['PrincipalType'] == 'USER' and assignment['PrincipalId'] == user_id:
            user_roles.append({
                'account_id': assignment.get('TargetId', assignment.get('AccountId', '')),
                'role_name': assignment.get('PermissionSetName', assignment.get('PermissionSet', '')),
                'assignment_type': 'Direct'
            })
    
    # Group assignments
    for group_id, members in group_members.items():
        if user_id in members:
            for assignment in assignments:
                if assignment['PrincipalType'] == 'GROUP' and assignment['PrincipalId'] == group_id:
                    user_roles.append({
                        'account_id': assignment.get('TargetId', assignment.get('AccountId', '')),
                        'role_name': assignment.get('PermissionSetName', assignment.get('PermissionSet', '')),
                        'assignment_type': f'Group: {group_id}'
                    })
    
    return user_roles

def find_user_escalation_paths(user_roles, escalation_chains):
    """Find escalation paths available to a user"""
    user_escalations = []
    
    for role in user_roles:
        account_id = role['account_id']
        role_name = role['role_name']
        
        # Find escalation chains starting from this role
        for chain in escalation_chains:
            if (chain['source_account'] == account_id and 
                chain['source_role'] == role_name):
                
                user_escalations.append({
                    'user_role': role,
                    'escalation': chain
                })
    
    return user_escalations

def main():
    parser = argparse.ArgumentParser(description='Analyze user-specific privilege escalation paths')
    parser.add_argument('--output', choices=['csv', 'json'], default='csv', help='Output format')
    args = parser.parse_args()
    
    print("=== User Escalation Path Analysis ===")
    
    # Load all data
    users = load_user_mappings()
    groups, group_members = load_group_mappings()
    assignments = load_identity_center_assignments()
    escalation_chains = load_escalation_chains()
    
    if not users or not assignments or not escalation_chains:
        print("Missing required data files")
        return
    
    # Analyze each user
    all_user_escalations = []
    
    for user_id, user_info in users.items():
        print(f"Analyzing user: {user_info['username']}")
        
        # Get user's roles
        user_roles = get_user_roles(user_id, assignments, group_members)
        
        # Find escalation paths
        user_escalations = find_user_escalation_paths(user_roles, escalation_chains)
        
        for escalation in user_escalations:
            all_user_escalations.append({
                'user_id': user_id,
                'username': user_info['username'],
                'display_name': user_info['display_name'],
                'source_account': escalation['user_role']['account_id'],
                'source_role': escalation['user_role']['role_name'],
                'assignment_type': escalation['user_role']['assignment_type'],
                'target_account': escalation['escalation']['target_account'],
                'target_role': escalation['escalation']['target_role'],
                'escalation_method': escalation['escalation']['escalation_method'],
                'risk_level': escalation['escalation']['risk_level'],
                'cross_account': escalation['escalation']['cross_account']
            })
    
    # Save results
    if args.output == 'csv':
        with open('user_escalation_analysis.csv', 'w', newline='', encoding='utf-8') as f:
            if all_user_escalations:
                writer = csv.DictWriter(f, fieldnames=all_user_escalations[0].keys())
                writer.writeheader()
                writer.writerows(all_user_escalations)
        
        print(f"\nResults saved to user_escalation_analysis.csv")
    
    elif args.output == 'json':
        with open('user_escalation_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(all_user_escalations, f, indent=2)
        
        print(f"\nResults saved to user_escalation_analysis.json")
    
    # Summary
    print(f"\n=== Summary ===")
    print(f"Total users analyzed: {len(users)}")
    print(f"Users with escalation paths: {len(set(e['user_id'] for e in all_user_escalations))}")
    print(f"Total escalation paths found: {len(all_user_escalations)}")
    print(f"Cross-account escalations: {len([e for e in all_user_escalations if e['cross_account'] == 'True'])}")
    
    # High-risk users
    high_risk_users = set()
    for escalation in all_user_escalations:
        if escalation['risk_level'] in ['HIGH', 'CRITICAL']:
            high_risk_users.add(escalation['username'])
    
    print(f"High-risk users: {len(high_risk_users)}")
    if high_risk_users:
        print("High-risk users:", ', '.join(sorted(high_risk_users)))

if __name__ == "__main__":
    main()