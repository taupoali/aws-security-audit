#!/usr/bin/env python3

import csv
import os
import glob
from datetime import datetime
from collections import defaultdict

def load_account_data(data_dir):
    """Load CSV data from all account folders"""
    accounts = {}
    
    # Find all subdirectories in data_collected
    if not os.path.exists(data_dir):
        return accounts
    
    for item in os.listdir(data_dir):
        folder_path = os.path.join(data_dir, item)
        if os.path.isdir(folder_path):
            # Extract account ID from folder name (assumes folder ends with account ID)
            folder_name = os.path.basename(folder_path)
            # Look for 12-digit account ID at the end of folder name
            import re
            account_id_match = re.search(r'(\d{12})$', folder_name)
            if account_id_match:
                account_id = account_id_match.group(1)
                display_name = f"{folder_name} ({account_id})"
            else:
                # Fallback to folder name if no account ID pattern found
                display_name = folder_name
            
            accounts[display_name] = {}
            
            # Load relevant CSV files
            csv_files = {
                'iam_roles': 'iam_roles.csv',
                'escalation_chains': 'escalation_chains.csv', 
                'cross_account_access': 'cross_account_findings.csv',
                'identity_center': 'identity_center_assignments.csv'
            }
            
            for data_type, filename in csv_files.items():
                file_path = os.path.join(folder_path, filename)
                
                # Special handling for identity_center - check root directory if not found in account folder
                if data_type == 'identity_center' and not os.path.exists(file_path):
                    root_file_path = os.path.join(data_dir, filename)
                    if os.path.exists(root_file_path):
                        file_path = root_file_path
                        print(f"[INFO] Using organization-wide Identity Center file: {root_file_path}")
                
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', newline='', encoding='utf-8') as f:
                            reader = csv.DictReader(f)
                            accounts[display_name][data_type] = list(reader)
                    except Exception as e:
                        print(f"[WARNING] Failed to load {file_path}: {e}")
                        accounts[display_name][data_type] = []
                else:
                    accounts[display_name][data_type] = []
    
    return accounts

def extract_user_identities(accounts):
    """Extract all user identities from Identity Center assignments"""
    users = set()
    
    for account_name, data in accounts.items():
        for assignment in data.get('identity_center', []):
            # Look for user identifiers in various fields
            for field in ['PrincipalName', 'UserName', 'User', 'Principal', 'Subject']:
                if field in assignment and assignment[field]:
                    user_id = assignment[field].strip()
                    if '@' in user_id or 'user' in user_id.lower():
                        users.add(user_id)
    
    return sorted(users)

def find_user_roles(user_identity, accounts):
    """Find all roles a user can access across accounts"""
    user_roles = defaultdict(list)
    
    for account_name, data in accounts.items():
        # Check Identity Center assignments
        for assignment in data.get('identity_center', []):
            principal = assignment.get('PrincipalName') or assignment.get('UserName') or assignment.get('User', '')
            role_name = assignment.get('PermissionSetName') or assignment.get('RoleName') or assignment.get('Role', '')
            
            if user_identity.lower() in principal.lower() and role_name:
                user_roles[account_name].append({
                    'role_name': role_name,
                    'access_type': 'Identity Center Assignment',
                    'principal': principal,
                    'source': 'identity_center_assignments.csv'
                })
        
        # Check for direct IAM role assumptions (less common but possible)
        for role in data.get('iam_roles', []):
            trust_policy = str(role.get('TrustPolicy', '') + role.get('AssumeRolePolicyDocument', '')).lower()
            role_name = role.get('RoleName') or role.get('Role Name', '')
            
            if user_identity.lower() in trust_policy and role_name:
                user_roles[account_name].append({
                    'role_name': role_name,
                    'access_type': 'Direct IAM Trust Policy',
                    'principal': user_identity,
                    'source': 'iam_roles.csv'
                })
    
    return user_roles

def trace_escalation_paths(user_roles, accounts):
    """Trace privilege escalation paths from user's initial roles"""
    escalation_paths = []
    
    for account_name, roles in user_roles.items():
        account_data = accounts[account_name]
        
        for role_info in roles:
            initial_role = role_info['role_name']
            
            # Find escalation chains starting from this role
            for chain in account_data.get('escalation_chains', []):
                path = chain.get('Path') or chain.get('Chain', '')
                source_role = chain.get('RoleName') or chain.get('SourceRole', '')
                target_role = chain.get('Target Privileged Role') or chain.get('TargetRole', '')
                
                # Check if user's role is in the escalation path
                if initial_role in path or initial_role == source_role:
                    escalation_paths.append({
                        'user': role_info['principal'],
                        'start_account': account_name,
                        'start_role': initial_role,
                        'escalation_path': path,
                        'target_role': target_role,
                        'access_type': role_info['access_type'],
                        'risk_level': 'CRITICAL' if 'admin' in target_role.lower() else 'HIGH'
                    })
    
    return escalation_paths

def find_cross_account_access(user_roles, accounts):
    """Find cross-account access paths for user roles"""
    cross_account_paths = []
    
    for account_name, roles in user_roles.items():
        for role_info in roles:
            role_name = role_info['role_name']
            
            # Check all accounts for cross-account access to this role
            for target_account, target_data in accounts.items():
                if target_account == account_name:
                    continue
                
                for access in target_data.get('cross_account_access', []):
                    external_principal = access.get('Principal') or access.get('ExternalPrincipal', '')
                    target_role = access.get('RoleName') or access.get('Role Name', '')
                    
                    # Check if user's role can access target account
                    if role_name in external_principal or account_name in external_principal:
                        cross_account_paths.append({
                            'user': role_info['principal'],
                            'source_account': account_name,
                            'source_role': role_name,
                            'target_account': target_account,
                            'target_role': target_role,
                            'access_method': 'Cross-Account Role Assumption',
                            'risk_level': 'HIGH' if 'admin' in target_role.lower() else 'MEDIUM'
                        })
    
    return cross_account_paths

def generate_html_report(user_identity, user_roles, escalation_paths, cross_account_paths, output_file):
    """Generate HTML version of user journey report"""
    total_roles = sum(len(roles) for roles in user_roles.values())
    critical_risks = len([p for p in escalation_paths if p['risk_level'] == 'CRITICAL'])
    high_risks = len([p for p in escalation_paths + cross_account_paths if p['risk_level'] == 'HIGH'])
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>User Access Journey Analysis - {user_identity}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }}
        .user-info {{ background-color: #e8f4fd; padding: 15px; border-radius: 8px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #2c3e50; border-left: 4px solid #3498db; padding-left: 15px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 20px; background-color: #ecf0f1; border-radius: 8px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .account-section {{ background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .account-title {{ font-weight: bold; color: #495057; font-size: 1.1em; margin-bottom: 10px; }}
        .role-item {{ background-color: #e9ecef; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid #6c757d; }}
        .path-item {{ padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 5px solid; }}
        .critical {{ background-color: #f8d7da; border-left-color: #dc3545; }}
        .high {{ background-color: #fff3cd; border-left-color: #ffc107; }}
        .medium {{ background-color: #d1ecf1; border-left-color: #17a2b8; }}
        .risk-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white; }}
        .risk-critical {{ background-color: #dc3545; }}
        .risk-high {{ background-color: #ffc107; color: #212529; }}
        .risk-medium {{ background-color: #17a2b8; }}
        .path-flow {{ font-family: 'Courier New', monospace; background-color: #f1f3f4; padding: 8px; border-radius: 4px; margin: 8px 0; }}
        .no-findings {{ text-align: center; color: #6c757d; font-style: italic; padding: 20px; }}
        .actions {{ background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 15px; margin-top: 20px; }}
        .actions h3 {{ color: #155724; margin-top: 0; }}
        .actions ul {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>User Access Journey Analysis</h1>
            <div class="user-info">
                <h2>{user_identity}</h2>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{len(user_roles)}</div>
                <div>Accounts</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{total_roles}</div>
                <div>Total Roles</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{critical_risks}</div>
                <div>Critical Risks</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{high_risks}</div>
                <div>High Risks</div>
            </div>
        </div>

        <div class="section">
            <h2>Initial Access Summary</h2>
"""
    
    for account, roles in user_roles.items():
        html_content += f"""
            <div class="account-section">
                <div class="account-title">{account}</div>
"""
        for role in roles:
            html_content += f"""
                <div class="role-item">
                    <strong>{role['role_name']}</strong><br>
                    <small>{role['access_type']}</small>
                </div>
"""
        html_content += "</div>"
    
    html_content += "</div>"
    
    # Privilege Escalation Paths
    html_content += """
        <div class="section">
            <h2>Privilege Escalation Paths</h2>
"""
    
    if escalation_paths:
        for i, path in enumerate(escalation_paths, 1):
            risk_class = path['risk_level'].lower()
            html_content += f"""
            <div class="path-item {risk_class}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4>Path {i}</h4>
                    <span class="risk-badge risk-{risk_class}">{path['risk_level']} RISK</span>
                </div>
                <p><strong>User:</strong> {path['user']}</p>
                <p><strong>Start:</strong> {path['start_account']} → {path['start_role']}</p>
                <div class="path-flow">{path['escalation_path']}</div>
                <p><strong>Target:</strong> {path['target_role']}</p>
                <p><strong>Method:</strong> {path['access_type']}</p>
            </div>
"""
    else:
        html_content += '<div class="no-findings">No privilege escalation paths detected.</div>'
    
    html_content += "</div>"
    
    # Cross-Account Access
    html_content += """
        <div class="section">
            <h2>Cross-Account Access Paths</h2>
"""
    
    if cross_account_paths:
        for i, path in enumerate(cross_account_paths, 1):
            risk_class = path['risk_level'].lower()
            html_content += f"""
            <div class="path-item {risk_class}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4>Path {i}</h4>
                    <span class="risk-badge risk-{risk_class}">{path['risk_level']} RISK</span>
                </div>
                <p><strong>User:</strong> {path['user']}</p>
                <p><strong>Source:</strong> {path['source_account']} → {path['source_role']}</p>
                <p><strong>Target:</strong> {path['target_account']} → {path['target_role']}</p>
                <p><strong>Method:</strong> {path['access_method']}</p>
            </div>
"""
    else:
        html_content += '<div class="no-findings">No cross-account access paths detected.</div>'
    
    html_content += "</div>"
    
    # Actions section
    if critical_risks > 0 or high_risks > 0:
        html_content += f"""
        <div class="actions">
            <h3>🚨 Immediate Actions Required</h3>
            <ul>
                <li>Review and restrict high-risk escalation paths</li>
                <li>Implement additional conditions (MFA, IP restrictions)</li>
                <li>Consider time-based access for elevated privileges</li>
                <li>Enable detailed CloudTrail logging for this user</li>
            </ul>
        </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_user_journey_report(user_identity, accounts, output_file):
    """Generate comprehensive user journey report"""
    print(f"[INFO] Tracing access paths for user: {user_identity}")
    
    # Find user's initial roles
    user_roles = find_user_roles(user_identity, accounts)
    
    if not user_roles:
        print(f"[WARNING] No roles found for user: {user_identity}")
        return
    
    # Trace escalation paths
    escalation_paths = trace_escalation_paths(user_roles, accounts)
    
    # Find cross-account access
    cross_account_paths = find_cross_account_access(user_roles, accounts)
    
    # Generate report
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"USER ACCESS JOURNEY ANALYSIS: {user_identity}\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Initial Access Summary
        f.write("INITIAL ACCESS SUMMARY\n")
        f.write("-" * 30 + "\n")
        total_roles = sum(len(roles) for roles in user_roles.values())
        f.write(f"User has access to {total_roles} roles across {len(user_roles)} accounts\n\n")
        
        for account, roles in user_roles.items():
            f.write(f"Account: {account}\n")
            for role in roles:
                f.write(f"  - {role['role_name']} ({role['access_type']})\n")
            f.write("\n")
        
        # Privilege Escalation Paths
        if escalation_paths:
            f.write("PRIVILEGE ESCALATION PATHS\n")
            f.write("-" * 35 + "\n")
            f.write(f"Found {len(escalation_paths)} potential escalation paths:\n\n")
            
            for i, path in enumerate(escalation_paths, 1):
                f.write(f"{i}. {path['risk_level']} RISK\n")
                f.write(f"   User: {path['user']}\n")
                f.write(f"   Start: {path['start_account']} → {path['start_role']}\n")
                f.write(f"   Path: {path['escalation_path']}\n")
                f.write(f"   Target: {path['target_role']}\n")
                f.write(f"   Method: {path['access_type']}\n\n")
        else:
            f.write("PRIVILEGE ESCALATION PATHS\n")
            f.write("-" * 35 + "\n")
            f.write("No privilege escalation paths detected.\n\n")
        
        # Cross-Account Access
        if cross_account_paths:
            f.write("CROSS-ACCOUNT ACCESS PATHS\n")
            f.write("-" * 35 + "\n")
            f.write(f"Found {len(cross_account_paths)} cross-account access paths:\n\n")
            
            for i, path in enumerate(cross_account_paths, 1):
                f.write(f"{i}. {path['risk_level']} RISK\n")
                f.write(f"   User: {path['user']}\n")
                f.write(f"   Source: {path['source_account']} → {path['source_role']}\n")
                f.write(f"   Target: {path['target_account']} → {path['target_role']}\n")
                f.write(f"   Method: {path['access_method']}\n\n")
        else:
            f.write("CROSS-ACCOUNT ACCESS PATHS\n")
            f.write("-" * 35 + "\n")
            f.write("No cross-account access paths detected.\n\n")
        
        # Risk Summary
        critical_risks = len([p for p in escalation_paths if p['risk_level'] == 'CRITICAL'])
        high_risks = len([p for p in escalation_paths + cross_account_paths if p['risk_level'] == 'HIGH'])
        
        f.write("RISK SUMMARY\n")
        f.write("-" * 15 + "\n")
        f.write(f"Critical Risks: {critical_risks}\n")
        f.write(f"High Risks: {high_risks}\n")
        f.write(f"Total Risk Paths: {len(escalation_paths) + len(cross_account_paths)}\n\n")
        
        if critical_risks > 0 or high_risks > 0:
            f.write("IMMEDIATE ACTIONS REQUIRED:\n")
            f.write("1. Review and restrict high-risk escalation paths\n")
            f.write("2. Implement additional conditions (MFA, IP restrictions)\n")
            f.write("3. Consider time-based access for elevated privileges\n")
            f.write("4. Enable detailed CloudTrail logging for this user\n")

def main():
    data_dir = "data_collected"
    
    if not os.path.exists(data_dir):
        print(f"[ERROR] Data directory '{data_dir}' not found")
        return
    
    print("[INFO] Loading account data...")
    accounts = load_account_data(data_dir)
    
    if not accounts:
        print("[ERROR] No account data found")
        return
    
    print(f"[INFO] Loaded data from {len(accounts)} accounts")
    
    # Extract all user identities
    users = extract_user_identities(accounts)
    
    if not users:
        print("[WARNING] No user identities found in Identity Center assignments")
        print("[INFO] You can manually specify a user identity")
        user_identity = input("Enter user identity to trace: ").strip()
        if not user_identity:
            return
        users = [user_identity]
    else:
        print(f"[INFO] Found {len(users)} user identities:")
        for i, user in enumerate(users, 1):
            print(f"  {i}. {user}")
        
        choice = input(f"\nSelect user (1-{len(users)}) or enter custom identity: ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(users):
            user_identity = users[int(choice) - 1]
        else:
            user_identity = choice
    
    # Generate reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_user = user_identity.replace('@', '_').replace('.', '_')
    text_output = f"user_journey_{safe_user}_{timestamp}.txt"
    html_output = f"user_journey_{safe_user}_{timestamp}.html"
    
    generate_user_journey_report(user_identity, accounts, text_output)
    
    # Generate HTML report
    user_roles = find_user_roles(user_identity, accounts)
    if user_roles:
        escalation_paths = trace_escalation_paths(user_roles, accounts)
        cross_account_paths = find_cross_account_access(user_roles, accounts)
        generate_html_report(user_identity, user_roles, escalation_paths, cross_account_paths, html_output)
    
    print(f"\n[SUCCESS] User journey reports generated:")
    print(f"  Text: {text_output}")
    print(f"  HTML: {html_output}")

if __name__ == "__main__":
    main()