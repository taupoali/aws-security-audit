#!/usr/bin/env python3

import subprocess
import json
import csv
import sys
import argparse
from pathlib import Path

def run_aws_command(command, profile=None):
    """Run AWS CLI command and return JSON output"""
    if profile:
        command += f" --profile {profile}"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Error: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from command: {command}")
        print(f"Output: {result.stdout}")
        return None

def get_identity_store_id(profile=None):
    """Get the Identity Store ID"""
    print("Getting Identity Store ID...")
    result = run_aws_command("aws sso-admin list-instances", profile)
    if result and 'Instances' in result and len(result['Instances']) > 0:
        identity_store_id = result['Instances'][0]['IdentityStoreId']
        print(f"Found Identity Store ID: {identity_store_id}")
        return identity_store_id
    return None

def get_all_groups(identity_store_id, profile=None):
    """Get all groups from Identity Center"""
    print("Fetching all groups...")
    groups = []
    next_token = None
    
    while True:
        cmd = f"aws identitystore list-groups --identity-store-id {identity_store_id}"
        if next_token:
            cmd += f" --next-token {next_token}"
            
        result = run_aws_command(cmd, profile)
        if not result:
            break
            
        groups.extend(result.get('Groups', []))
        next_token = result.get('NextToken')
        if not next_token:
            break
    
    print(f"Found {len(groups)} groups")
    return groups

def get_group_memberships(identity_store_id, group_id, profile=None):
    """Get all members of a specific group"""
    members = []
    next_token = None
    
    while True:
        cmd = f"aws identitystore list-group-memberships --identity-store-id {identity_store_id} --group-id {group_id}"
        if next_token:
            cmd += f" --next-token {next_token}"
            
        result = run_aws_command(cmd, profile)
        if not result:
            break
            
        members.extend(result.get('GroupMemberships', []))
        next_token = result.get('NextToken')
        if not next_token:
            break
    
    return members

def get_user_details(identity_store_id, user_id, profile=None):
    """Get user details by ID"""
    cmd = f"aws identitystore describe-user --identity-store-id {identity_store_id} --user-id {user_id}"
    result = run_aws_command(cmd, profile)
    if result:
        return result.get('UserName', 'Unknown'), result.get('DisplayName', 'Unknown')
    return 'Unknown', 'Unknown'

def load_identity_center_assignments():
    """Load Identity Center assignments from CSV"""
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

def main():
    parser = argparse.ArgumentParser(description='Map Identity Center groups to members')
    parser.add_argument('--profile', help='AWS profile to use')
    args = parser.parse_args()
    
    print("=== Identity Center Group Mapping ===")
    if args.profile:
        print(f"Using AWS profile: {args.profile}")
    
    # Get Identity Store ID
    identity_store_id = get_identity_store_id(args.profile)
    if not identity_store_id:
        print("Failed to get Identity Store ID")
        sys.exit(1)
    
    # Load assignments to see which groups have assignments
    assignments = load_identity_center_assignments()
    assigned_groups = set()
    for assignment in assignments:
        if assignment.get('PrincipalType') == 'GROUP':
            assigned_groups.add(assignment.get('PrincipalId'))
    
    print(f"Found {len(assigned_groups)} groups with assignments")
    
    # Get all groups
    all_groups = get_all_groups(identity_store_id, args.profile)
    
    # Create group mapping
    group_mapping = []
    user_cache = {}  # Cache user details to avoid repeated API calls
    
    for i, group in enumerate(all_groups, 1):
        group_id = group['GroupId']
        group_name = group['DisplayName']
        
        print(f"Processing group {i}/{len(all_groups)}: {group_name}")
        
        # Get group memberships
        memberships = get_group_memberships(identity_store_id, group_id, args.profile)
        
        # Get user details for each member
        members = []
        for membership in memberships:
            member_id = membership['MemberId']['UserId']
            
            # Use cache to avoid repeated API calls
            if member_id not in user_cache:
                username, display_name = get_user_details(identity_store_id, member_id, args.profile)
                user_cache[member_id] = {'username': username, 'display_name': display_name}
            
            user_info = user_cache[member_id]
            members.append({
                'UserId': member_id,
                'UserName': user_info['username'],
                'DisplayName': user_info['display_name']
            })
        
        # Check if group has assignments
        has_assignments = group_id in assigned_groups
        
        group_mapping.append({
            'GroupId': group_id,
            'GroupName': group_name,
            'MemberCount': len(members),
            'HasAssignments': has_assignments,
            'Members': members
        })
    
    # Save detailed group mapping
    print("\nSaving group mapping...")
    with open('identity_center_group_mapping.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['GroupId', 'GroupName', 'MemberCount', 'HasAssignments', 'UserId', 'UserName', 'DisplayName'])
        
        for group in group_mapping:
            if group['Members']:
                for member in group['Members']:
                    writer.writerow([
                        group['GroupId'],
                        group['GroupName'],
                        group['MemberCount'],
                        group['HasAssignments'],
                        member['UserId'],
                        member['UserName'],
                        member['DisplayName']
                    ])
            else:
                # Empty group
                writer.writerow([
                    group['GroupId'],
                    group['GroupName'],
                    0,
                    group['HasAssignments'],
                    '',
                    '',
                    ''
                ])
    
    # Save summary
    with open('identity_center_group_summary.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['GroupId', 'GroupName', 'MemberCount', 'HasAssignments'])
        
        for group in group_mapping:
            writer.writerow([
                group['GroupId'],
                group['GroupName'],
                group['MemberCount'],
                group['HasAssignments']
            ])
    
    # Print summary
    print(f"\n=== Summary ===")
    print(f"Total groups: {len(group_mapping)}")
    print(f"Groups with assignments: {len([g for g in group_mapping if g['HasAssignments']])}")
    print(f"Groups with members: {len([g for g in group_mapping if g['MemberCount'] > 0])}")
    print(f"Total unique users across all groups: {len(user_cache)}")
    
    print(f"\nFiles created:")
    print(f"- identity_center_group_mapping.csv (detailed mapping)")
    print(f"- identity_center_group_summary.csv (summary)")

if __name__ == "__main__":
    main()