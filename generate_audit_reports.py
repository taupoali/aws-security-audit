#!/usr/bin/env python3

import csv
import json
from pathlib import Path
from collections import defaultdict
import argparse

def load_permission_set_analysis():
    """Load all permission set analysis files"""
    analysis_files = list(Path('.').glob('permission_set_analysis_*.csv'))
    all_analysis = []
    
    for file in analysis_files:
        with open(file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                all_analysis.append(row)
    
    print(f"Loaded {len(all_analysis)} permission set analyses from {len(analysis_files)} accounts")
    return all_analysis

def load_user_escalation_analysis():
    """Load user escalation analysis"""
    file_path = Path('user_escalation_analysis.csv')
    if not file_path.exists():
        print("Warning: user_escalation_analysis.csv not found")
        return []
    
    escalations = []
    with open(file_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            escalations.append(row)
    
    print(f"Loaded {len(escalations)} user escalation records")
    return escalations

def load_identity_center_assignments():
    """Load Identity Center assignments"""
    file_path = Path('findings/identity_center_assignments.csv')
    if not file_path.exists():
        print("Warning: identity_center_assignments.csv not found")
        return []
    
    assignments = []
    with open(file_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignments.append(row)
    
    print(f"Loaded {len(assignments)} Identity Center assignments")
    return assignments

def load_user_mappings():
    """Load user mappings"""
    file_path = Path('data_collected/identity_center_user_mapping.csv')
    if not file_path.exists():
        print("Warning: identity_center_user_mapping.csv not found")
        return {}
    
    users = {}
    with open(file_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row['PrincipalId']] = {
                'username': row['Username'],
                'display_name': row['DisplayName'],
                'email': row.get('Email', '')
            }
    
    print(f"Loaded {len(users)} user mappings")
    return users

def generate_least_privilege_report(permission_analysis):
    """Generate least privilege compliance report"""
    print("\nGenerating Least Privilege Compliance Report...")
    
    # Group by permission set and risk level
    perm_set_risks = defaultdict(lambda: {'accounts': set(), 'max_risk': 'LOW', 'violations': []})
    
    for analysis in permission_analysis:
        perm_set = analysis['PermissionSetName']
        account = analysis['AccountId']
        risk = analysis['RiskLevel']
        
        perm_set_risks[perm_set]['accounts'].add(account)
        
        # Track highest risk level
        risk_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'ERROR': 0}
        if risk_order.get(risk, 0) > risk_order.get(perm_set_risks[perm_set]['max_risk'], 0):
            perm_set_risks[perm_set]['max_risk'] = risk
        
        if risk in ['HIGH', 'CRITICAL'] and analysis['RiskReasons']:
            perm_set_risks[perm_set]['violations'].append({
                'account': account,
                'policy': analysis['PolicyName'],
                'reasons': analysis['RiskReasons']
            })
    
    # Generate report
    report = []
    for perm_set, data in perm_set_risks.items():
        report.append({
            'PermissionSetName': perm_set,
            'RiskLevel': data['max_risk'],
            'AccountCount': len(data['accounts']),
            'Accounts': ', '.join(sorted(data['accounts'])),
            'LeastPrivilegeCompliant': 'NO' if data['max_risk'] in ['HIGH', 'CRITICAL'] else 'YES',
            'ViolationCount': len(data['violations']),
            'ViolationDetails': '; '.join([f"{v['account']}:{v['policy']} - {v['reasons']}" for v in data['violations']])
        })
    
    # Sort by risk level
    risk_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'ERROR': 0}
    report.sort(key=lambda x: risk_order.get(x['RiskLevel'], 0), reverse=True)
    
    with open('audit_least_privilege_compliance.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['PermissionSetName', 'RiskLevel', 'AccountCount', 'Accounts', 'LeastPrivilegeCompliant', 'ViolationCount', 'ViolationDetails'])
        writer.writeheader()
        writer.writerows(report)
    
    print(f"Created audit_least_privilege_compliance.csv with {len(report)} permission sets")
    return report

def generate_elevated_privileges_report(permission_analysis, assignments, users):
    """Generate elevated privileges report"""
    print("\nGenerating Elevated Privileges Report...")
    
    # Find high-risk permission sets
    high_risk_perm_sets = set()
    for analysis in permission_analysis:
        if analysis['RiskLevel'] in ['HIGH', 'CRITICAL']:
            high_risk_perm_sets.add(analysis['PermissionSetName'])
    
    # Find users with elevated privileges
    elevated_users = []
    
    for assignment in assignments:
        perm_set = assignment['PermissionSetName']
        principal_id = assignment['PrincipalId']
        principal_type = assignment['PrincipalType']
        account_id = assignment['AccountId']
        
        # Check if this is a high-risk permission set
        if perm_set in high_risk_perm_sets:
            user_info = users.get(principal_id, {})
            
            elevated_users.append({
                'PrincipalId': principal_id,
                'PrincipalType': principal_type,
                'Username': user_info.get('username', 'Unknown'),
                'DisplayName': user_info.get('display_name', 'Unknown'),
                'Email': user_info.get('email', ''),
                'PermissionSetName': perm_set,
                'AccountId': account_id,
                'RiskJustification': f"Has access to {perm_set} which contains HIGH/CRITICAL risk policies"
            })
    
    with open('audit_elevated_privileges.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['PrincipalId', 'PrincipalType', 'Username', 'DisplayName', 'Email', 'PermissionSetName', 'AccountId', 'RiskJustification'])
        writer.writeheader()
        writer.writerows(elevated_users)
    
    print(f"Created audit_elevated_privileges.csv with {len(elevated_users)} elevated privilege assignments")
    return elevated_users

def generate_cross_account_access_report(assignments, users):
    """Generate cross-account access analysis"""
    print("\nGenerating Cross-Account Access Report...")
    
    # Group assignments by user
    user_access = defaultdict(list)
    
    for assignment in assignments:
        principal_id = assignment['PrincipalId']
        if assignment['PrincipalType'] == 'USER':
            user_access[principal_id].append(assignment)
    
    # Find users with multi-account access
    cross_account_users = []
    
    for principal_id, user_assignments in user_access.items():
        if len(set(a['AccountId'] for a in user_assignments)) > 1:  # Multi-account access
            user_info = users.get(principal_id, {})
            accounts = list(set(a['AccountId'] for a in user_assignments))
            perm_sets = list(set(a['PermissionSetName'] for a in user_assignments))
            
            cross_account_users.append({
                'PrincipalId': principal_id,
                'Username': user_info.get('username', 'Unknown'),
                'DisplayName': user_info.get('display_name', 'Unknown'),
                'Email': user_info.get('email', ''),
                'AccountCount': len(accounts),
                'Accounts': ', '.join(sorted(accounts)),
                'PermissionSets': ', '.join(sorted(perm_sets)),
                'TotalAssignments': len(user_assignments)
            })
    
    # Sort by account count (highest risk first)
    cross_account_users.sort(key=lambda x: x['AccountCount'], reverse=True)
    
    with open('audit_cross_account_access.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['PrincipalId', 'Username', 'DisplayName', 'Email', 'AccountCount', 'Accounts', 'PermissionSets', 'TotalAssignments'])
        writer.writeheader()
        writer.writerows(cross_account_users)
    
    print(f"Created audit_cross_account_access.csv with {len(cross_account_users)} cross-account users")
    return cross_account_users

def generate_executive_summary(least_privilege_report, elevated_users, cross_account_users):
    """Generate executive summary"""
    print("\nGenerating Executive Summary...")
    
    # Calculate statistics
    total_perm_sets = len(least_privilege_report)
    non_compliant_perm_sets = len([p for p in least_privilege_report if p['LeastPrivilegeCompliant'] == 'NO'])
    critical_perm_sets = len([p for p in least_privilege_report if p['RiskLevel'] == 'CRITICAL'])
    high_risk_perm_sets = len([p for p in least_privilege_report if p['RiskLevel'] == 'HIGH'])
    
    unique_elevated_users = len(set(u['PrincipalId'] for u in elevated_users if u['PrincipalType'] == 'USER'))
    unique_cross_account_users = len(cross_account_users)
    
    summary = [
        {'Metric': 'Total Permission Sets Analyzed', 'Value': total_perm_sets, 'Status': 'INFO'},
        {'Metric': 'Non-Least Privilege Compliant', 'Value': non_compliant_perm_sets, 'Status': 'HIGH' if non_compliant_perm_sets > 0 else 'LOW'},
        {'Metric': 'Critical Risk Permission Sets', 'Value': critical_perm_sets, 'Status': 'CRITICAL' if critical_perm_sets > 0 else 'LOW'},
        {'Metric': 'High Risk Permission Sets', 'Value': high_risk_perm_sets, 'Status': 'HIGH' if high_risk_perm_sets > 0 else 'LOW'},
        {'Metric': 'Users with Elevated Privileges', 'Value': unique_elevated_users, 'Status': 'HIGH' if unique_elevated_users > 0 else 'LOW'},
        {'Metric': 'Users with Cross-Account Access', 'Value': unique_cross_account_users, 'Status': 'MEDIUM' if unique_cross_account_users > 10 else 'LOW'},
        {'Metric': 'Least Privilege Compliance Rate', 'Value': f"{((total_perm_sets - non_compliant_perm_sets) / total_perm_sets * 100):.1f}%" if total_perm_sets > 0 else "0%", 'Status': 'HIGH' if non_compliant_perm_sets > total_perm_sets * 0.2 else 'LOW'}
    ]
    
    with open('audit_executive_summary.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Metric', 'Value', 'Status'])
        writer.writeheader()
        writer.writerows(summary)
    
    print(f"Created audit_executive_summary.csv")
    return summary

def main():
    parser = argparse.ArgumentParser(description='Generate consolidated audit reports')
    args = parser.parse_args()
    
    print("=== AWS Security Audit Report Generation ===")
    
    # Load all data
    permission_analysis = load_permission_set_analysis()
    user_escalations = load_user_escalation_analysis()
    assignments = load_identity_center_assignments()
    users = load_user_mappings()
    
    if not permission_analysis:
        print("No permission set analysis data found. Run analyze_permission_set_policies.py first.")
        return
    
    # Generate reports
    least_privilege_report = generate_least_privilege_report(permission_analysis)
    elevated_users = generate_elevated_privileges_report(permission_analysis, assignments, users)
    cross_account_users = generate_cross_account_access_report(assignments, users)
    executive_summary = generate_executive_summary(least_privilege_report, elevated_users, cross_account_users)
    
    print(f"\n=== Audit Reports Generated ===")
    print(f"1. audit_least_privilege_compliance.csv - Least privilege analysis")
    print(f"2. audit_elevated_privileges.csv - Users with elevated access")
    print(f"3. audit_cross_account_access.csv - Cross-account access patterns")
    print(f"4. audit_executive_summary.csv - Executive summary metrics")
    
    # Print key findings
    print(f"\n=== Key Findings ===")
    for item in executive_summary:
        status_indicator = "🔴" if item['Status'] in ['CRITICAL', 'HIGH'] else "🟡" if item['Status'] == 'MEDIUM' else "🟢"
        print(f"{status_indicator} {item['Metric']}: {item['Value']}")

if __name__ == "__main__":
    main()