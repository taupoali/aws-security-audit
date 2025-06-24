#!/usr/bin/env python3

import json
import argparse
import subprocess
import csv
import time
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Track API call statistics
API_STATS = {"calls": 0, "timeouts": 0, "errors": 0, "cached": 0}
API_CACHE = {}

def run_aws_command(cmd, retries=2):
    """Run AWS CLI command with retries and caching"""
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

def get_account_id():
    """Get current AWS account ID"""
    result = run_aws_command(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"])
    return result.strip() if result else "unknown"

def get_all_roles():
    """Get all IAM roles in the account"""
    print("[INFO] Retrieving all IAM roles...")
    result = run_aws_command(["aws", "iam", "list-roles", "--output", "json"])
    if not result:
        print("[ERROR] Failed to retrieve IAM roles")
        return []
    
    roles_data = json.loads(result)
    roles = roles_data.get("Roles", [])
    print(f"[INFO] Found {len(roles)} IAM roles")
    return roles

def get_all_users():
    """Get all IAM users in the account"""
    print("[INFO] Retrieving all IAM users...")
    result = run_aws_command(["aws", "iam", "list-users", "--output", "json"])
    if not result:
        print("[ERROR] Failed to retrieve IAM users")
        return []
    
    users_data = json.loads(result)
    users = users_data.get("Users", [])
    print(f"[INFO] Found {len(users)} IAM users")
    return users

def get_role_policies(role_name):
    """Get all policies (inline and managed) attached to a role"""
    policies = []
    
    # Get inline policies
    inline_result = run_aws_command(["aws", "iam", "list-role-policies", "--role-name", role_name, "--output", "json"])
    if inline_result:
        policy_names = json.loads(inline_result).get("PolicyNames", [])
        for policy_name in policy_names:
            policy_result = run_aws_command([
                "aws", "iam", "get-role-policy", 
                "--role-name", role_name, 
                "--policy-name", policy_name,
                "--output", "json"
            ])
            if policy_result:
                policy_data = json.loads(policy_result)
                policies.append({
                    "PolicyName": policy_name,
                    "PolicyDocument": policy_data.get("PolicyDocument", {}),
                    "Type": "Inline"
                })
    
    # Get managed policies
    managed_result = run_aws_command([
        "aws", "iam", "list-attached-role-policies", 
        "--role-name", role_name,
        "--output", "json"
    ])
    if managed_result:
        attached_policies = json.loads(managed_result).get("AttachedPolicies", [])
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            policy_version_result = run_aws_command([
                "aws", "iam", "get-policy",
                "--policy-arn", policy_arn,
                "--output", "json"
            ])
            
            if policy_version_result:
                policy_data = json.loads(policy_version_result)
                default_version = policy_data.get("Policy", {}).get("DefaultVersionId")
                
                if default_version:
                    version_result = run_aws_command([
                        "aws", "iam", "get-policy-version",
                        "--policy-arn", policy_arn,
                        "--version-id", default_version,
                        "--output", "json"
                    ])
                    
                    if version_result:
                        version_data = json.loads(version_result)
                        policies.append({
                            "PolicyName": policy.get("PolicyName"),
                            "PolicyArn": policy_arn,
                            "PolicyDocument": version_data.get("PolicyVersion", {}).get("Document", {}),
                            "Type": "Managed"
                        })
    
    return policies

def get_user_policies(user_name):
    """Get all policies (inline and managed) attached to a user"""
    policies = []
    
    # Get inline policies
    inline_result = run_aws_command(["aws", "iam", "list-user-policies", "--user-name", user_name, "--output", "json"])
    if inline_result:
        policy_names = json.loads(inline_result).get("PolicyNames", [])
        for policy_name in policy_names:
            policy_result = run_aws_command([
                "aws", "iam", "get-user-policy", 
                "--user-name", user_name, 
                "--policy-name", policy_name,
                "--output", "json"
            ])
            if policy_result:
                policy_data = json.loads(policy_result)
                policies.append({
                    "PolicyName": policy_name,
                    "PolicyDocument": policy_data.get("PolicyDocument", {}),
                    "Type": "Inline"
                })
    
    # Get managed policies
    managed_result = run_aws_command([
        "aws", "iam", "list-attached-user-policies", 
        "--user-name", user_name,
        "--output", "json"
    ])
    if managed_result:
        attached_policies = json.loads(managed_result).get("AttachedPolicies", [])
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            policy_version_result = run_aws_command([
                "aws", "iam", "get-policy",
                "--policy-arn", policy_arn,
                "--output", "json"
            ])
            
            if policy_version_result:
                policy_data = json.loads(policy_version_result)
                default_version = policy_data.get("Policy", {}).get("DefaultVersionId")
                
                if default_version:
                    version_result = run_aws_command([
                        "aws", "iam", "get-policy-version",
                        "--policy-arn", policy_arn,
                        "--version-id", default_version,
                        "--output", "json"
                    ])
                    
                    if version_result:
                        version_data = json.loads(version_result)
                        policies.append({
                            "PolicyName": policy.get("PolicyName"),
                            "PolicyArn": policy_arn,
                            "PolicyDocument": version_data.get("PolicyVersion", {}).get("Document", {}),
                            "Type": "Managed"
                        })
    
    return policies

def get_role_trust_policy(role_name):
    """Get the trust policy for a role"""
    result = run_aws_command(["aws", "iam", "get-role", "--role-name", role_name, "--output", "json"])
    if result:
        role_data = json.loads(result)
        return role_data.get("Role", {}).get("AssumeRolePolicyDocument", {})
    return {}

def identify_elevated_privileges(roles, users):
    """Identify accounts and roles with elevated privileges"""
    print("[INFO] Identifying entities with elevated privileges...")
    elevated_entities = []
    
    # Define admin actions and services
    admin_actions = [
        "iam:*", "organizations:*", "s3:*", "ec2:*", "lambda:*", "dynamodb:*", 
        "kms:*", "cloudformation:*", "sts:*", "*"
    ]
    
    # Check roles
    for role in roles:
        role_name = role.get("RoleName")
        policies = get_role_policies(role_name)
        
        # Track admin permissions
        admin_permissions = []
        has_admin_access = False
        
        for policy in policies:
            policy_doc = policy.get("PolicyDocument", {})
            statements = policy_doc.get("Statement", [])
            
            if not isinstance(statements, list):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                actions = statement.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]
                    
                resources = statement.get("Resource", [])
                if not isinstance(resources, list):
                    resources = [resources]
                
                # Check for admin actions
                for action in actions:
                    if action == "*":
                        has_admin_access = True
                        admin_permissions.append({
                            "Action": action,
                            "Resources": resources,
                            "PolicyName": policy.get("PolicyName")
                        })
                    elif any(action.startswith(admin_action.rstrip("*")) for admin_action in admin_actions):
                        admin_permissions.append({
                            "Action": action,
                            "Resources": resources,
                            "PolicyName": policy.get("PolicyName")
                        })
        
        # Calculate privilege score (0-100)
        privilege_score = min(100, len(admin_permissions) * 5)
        if has_admin_access:
            privilege_score = 100
        
        if privilege_score > 50:  # Only include entities with significant privileges
            elevated_entities.append({
                "EntityType": "Role",
                "EntityName": role_name,
                "PrivilegeScore": privilege_score,
                "HasAdminAccess": has_admin_access,
                "AdminPermissionsCount": len(admin_permissions),
                "AdminPermissions": admin_permissions[:10]  # Limit to top 10 for readability
            })
    
    # Check users
    for user in users:
        user_name = user.get("UserName")
        policies = get_user_policies(user_name)
        
        # Track admin permissions
        admin_permissions = []
        has_admin_access = False
        
        for policy in policies:
            policy_doc = policy.get("PolicyDocument", {})
            statements = policy_doc.get("Statement", [])
            
            if not isinstance(statements, list):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                actions = statement.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]
                    
                resources = statement.get("Resource", [])
                if not isinstance(resources, list):
                    resources = [resources]
                
                # Check for admin actions
                for action in actions:
                    if action == "*":
                        has_admin_access = True
                        admin_permissions.append({
                            "Action": action,
                            "Resources": resources,
                            "PolicyName": policy.get("PolicyName")
                        })
                    elif any(action.startswith(admin_action.rstrip("*")) for admin_action in admin_actions):
                        admin_permissions.append({
                            "Action": action,
                            "Resources": resources,
                            "PolicyName": policy.get("PolicyName")
                        })
        
        # Calculate privilege score (0-100)
        privilege_score = min(100, len(admin_permissions) * 5)
        if has_admin_access:
            privilege_score = 100
        
        if privilege_score > 50:  # Only include entities with significant privileges
            elevated_entities.append({
                "EntityType": "User",
                "EntityName": user_name,
                "PrivilegeScore": privilege_score,
                "HasAdminAccess": has_admin_access,
                "AdminPermissionsCount": len(admin_permissions),
                "AdminPermissions": admin_permissions[:10]  # Limit to top 10 for readability
            })
    
    # Sort by privilege score (descending)
    elevated_entities.sort(key=lambda x: x["PrivilegeScore"], reverse=True)
    print(f"[INFO] Found {len(elevated_entities)} entities with elevated privileges")
    return elevated_entities

def analyze_trust_policy_conditions(roles):
    """Analyze conditions in trust policies for roles"""
    print("[INFO] Analyzing trust policy conditions...")
    condition_findings = []
    
    for role in roles:
        role_name = role.get("RoleName")
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        
        if not trust_policy:
            trust_policy = get_role_trust_policy(role_name)
        
        statements = trust_policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        # Track conditions
        has_conditions = False
        has_mfa_condition = False
        has_ip_restriction = False
        has_time_restriction = False
        has_external_id = False
        
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
                
            conditions = statement.get("Condition", {})
            if conditions:
                has_conditions = True
                
                # Check for MFA requirement
                if "aws:MultiFactorAuthPresent" in conditions.get("Bool", {}):
                    has_mfa_condition = True
                
                # Check for IP restrictions
                if "aws:SourceIp" in conditions:
                    has_ip_restriction = True
                
                # Check for time restrictions
                if "aws:CurrentTime" in conditions:
                    has_time_restriction = True
                
                # Check for external ID
                if "sts:ExternalId" in conditions:
                    has_external_id = True
            
            # Check principals
            principal = statement.get("Principal", {})
            aws_principal = principal.get("AWS", [])
            if not isinstance(aws_principal, list):
                aws_principal = [aws_principal]
            
            service_principal = principal.get("Service", [])
            if not isinstance(service_principal, list):
                service_principal = [service_principal]
            
            # Calculate security score based on conditions
            security_score = 0
            if has_mfa_condition:
                security_score += 30
            if has_ip_restriction:
                security_score += 25
            if has_time_restriction:
                security_score += 15
            if has_external_id:
                security_score += 20
            
            # Penalize for wildcards in principals
            if "*" in aws_principal:
                security_score -= 50
            
            # Add finding
            condition_findings.append({
                "RoleName": role_name,
                "HasConditions": has_conditions,
                "HasMfaCondition": has_mfa_condition,
                "HasIpRestriction": has_ip_restriction,
                "HasTimeRestriction": has_time_restriction,
                "HasExternalId": has_external_id,
                "SecurityScore": max(0, security_score),
                "Principals": {
                    "AWS": aws_principal,
                    "Service": service_principal
                }
            })
    
    print(f"[INFO] Analyzed trust policy conditions for {len(condition_findings)} roles")
    return condition_findings

def calculate_risk_scores(elevated_entities, condition_findings, chains=None):
    """Calculate risk scores for IAM configurations"""
    print("[INFO] Calculating risk scores...")
    risk_findings = []
    
    # Create lookup for condition findings
    condition_lookup = {finding["RoleName"]: finding for finding in condition_findings}
    
    # Create lookup for chain involvement
    chain_involvement = {}
    if chains:
        for chain in chains:
            for role in chain:
                if role not in chain_involvement:
                    chain_involvement[role] = 0
                chain_involvement[role] += 1
    
    # Analyze each entity with elevated privileges
    for entity in elevated_entities:
        entity_type = entity["EntityType"]
        entity_name = entity["EntityName"]
        privilege_score = entity["PrivilegeScore"]
        
        # Default values
        security_score = 50
        chain_count = 0
        
        # For roles, use condition findings
        if entity_type == "Role" and entity_name in condition_lookup:
            security_score = condition_lookup[entity_name]["SecurityScore"]
        
        # Check chain involvement
        if entity_name in chain_involvement:
            chain_count = chain_involvement[entity_name]
        
        # Calculate risk score (higher is riskier)
        # Formula: privilege_score * (100 - security_score) / 100 + (chain_count * 10)
        risk_score = (privilege_score * (100 - security_score) / 100) + (chain_count * 10)
        risk_score = min(100, risk_score)  # Cap at 100
        
        # Determine risk level
        risk_level = "Low"
        if risk_score >= 75:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
        
        # Generate remediation recommendations
        recommendations = []
        if privilege_score > 75:
            recommendations.append("Review and reduce permissions following least privilege principle")
        if entity_type == "Role" and security_score < 30:
            recommendations.append("Add conditions to trust policy (MFA, IP restrictions)")
        if chain_count > 0:
            recommendations.append("Review role assumption chain to prevent privilege escalation")
        if entity_type == "User" and privilege_score > 50:
            recommendations.append("Consider using roles instead of direct user permissions")
        
        # Add finding
        risk_findings.append({
            "EntityType": entity_type,
            "EntityName": entity_name,
            "PrivilegeScore": privilege_score,
            "SecurityScore": security_score,
            "ChainInvolvementCount": chain_count,
            "RiskScore": risk_score,
            "RiskLevel": risk_level,
            "Recommendations": recommendations
        })
    
    # Sort by risk score (descending)
    risk_findings.sort(key=lambda x: x["RiskScore"], reverse=True)
    print(f"[INFO] Generated risk analysis for {len(risk_findings)} entities")
    return risk_findings

def export_findings_to_csv(findings, filename):
    """Export findings to CSV file"""
    if not findings:
        print(f"[WARNING] No findings to export to {filename}")
        return False
        
    try:
        with open(filename, 'w', newline='') as csvfile:
            if isinstance(findings[0], dict):
                fieldnames = findings[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for finding in findings:
                    # Convert complex objects to strings
                    for key, value in finding.items():
                        if isinstance(value, (dict, list)):
                            finding[key] = json.dumps(value)
                    writer.writerow(finding)
            else:
                writer = csv.writer(csvfile)
                writer.writerow(["Findings"])
                for finding in findings:
                    writer.writerow([finding])
        print(f"[INFO] Exported findings to {filename}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to export findings to CSV: {e}")
        return False

def generate_html_report(elevated_entities, condition_findings, risk_findings, output_file="iam_risk_report.html"):
    """Generate HTML report with all findings"""
    try:
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AWS IAM Risk Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2, h3 { color: #232F3E; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
                th { background-color: #232F3E; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                .critical { background-color: #ff9999; }
                .high { background-color: #ffcc99; }
                .medium { background-color: #ffffcc; }
                .low { background-color: #ccffcc; }
                .section { margin-bottom: 30px; }
            </style>
        </head>
        <body>
            <h1>AWS IAM Risk Analysis Report</h1>
            <p>Generated on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            
            <div class="section">
                <h2>Risk Summary</h2>
                <table>
                    <tr>
                        <th>Risk Level</th>
                        <th>Count</th>
                    </tr>
        """
        
        # Count risk levels
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in risk_findings:
            risk_counts[finding["RiskLevel"]] += 1
        
        for level, count in risk_counts.items():
            html += f"""
                    <tr class="{level.lower()}">
                        <td>{level}</td>
                        <td>{count}</td>
                    </tr>
            """
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>Top Risk Findings</h2>
                <table>
                    <tr>
                        <th>Entity Type</th>
                        <th>Entity Name</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Recommendations</th>
                    </tr>
        """
        
        # Add top 10 risk findings
        for finding in risk_findings[:10]:
            risk_class = finding["RiskLevel"].lower()
            
            # Ensure recommendations are properly processed as a list
            recommendations = finding["Recommendations"]
            if isinstance(recommendations, str):
                # If it's a string (possibly JSON), try to parse it
                try:
                    recommendations = json.loads(recommendations)
                except:
                    recommendations = [recommendations]
            
            # Create HTML list items for each recommendation
            recommendations_list = ""
            for rec in recommendations:
                # Remove any quotes that might be around the recommendation
                if isinstance(rec, str):
                    rec = rec.strip('"')
                recommendations_list += f"<li>{rec}</li>"
                
            recommendations_html = f"<ul style='margin: 0; padding-left: 20px;'>{recommendations_list}</ul>"
            
            html += f"""
                    <tr class="{risk_class}">
                        <td>{finding["EntityType"]}</td>
                        <td>{finding["EntityName"]}</td>
                        <td>{finding["RiskScore"]:.1f}</td>
                        <td>{finding["RiskLevel"]}</td>
                        <td>{recommendations_html}</td>
                    </tr>
            """
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>Entities with Elevated Privileges</h2>
                <table>
                    <tr>
                        <th>Entity Type</th>
                        <th>Entity Name</th>
                        <th>Privilege Score</th>
                        <th>Has Admin Access</th>
                    </tr>
        """
        
        # Add entities with elevated privileges
        for entity in elevated_entities[:10]:  # Top 10
            html += f"""
                    <tr>
                        <td>{entity["EntityType"]}</td>
                        <td>{entity["EntityName"]}</td>
                        <td>{entity["PrivilegeScore"]}</td>
                        <td>{entity["HasAdminAccess"]}</td>
                    </tr>
            """
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>Trust Policy Condition Analysis</h2>
                <table>
                    <tr>
                        <th>Role Name</th>
                        <th>Has MFA</th>
                        <th>Has IP Restriction</th>
                        <th>Has External ID</th>
                        <th>Security Score</th>
                    </tr>
        """
        
        # Add trust policy condition findings
        for finding in sorted(condition_findings, key=lambda x: x["SecurityScore"])[:10]:  # Top 10 least secure
            html += f"""
                    <tr>
                        <td>{finding["RoleName"]}</td>
                        <td>{finding["HasMfaCondition"]}</td>
                        <td>{finding["HasIpRestriction"]}</td>
                        <td>{finding["HasExternalId"]}</td>
                        <td>{finding["SecurityScore"]}</td>
                    </tr>
            """
        
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"[INFO] Generated HTML report: {output_file}")
        return output_file
    except Exception as e:
        print(f"[ERROR] Failed to generate HTML report: {e}")
        return None

def load_escalation_chains(chains_file):
    """Load escalation chains from a CSV file"""
    chains = []
    try:
        with open(chains_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                path = row.get("Path", "")
                if path:
                    chains.append(path.split(" -> "))
        print(f"[INFO] Loaded {len(chains)} escalation chains from {chains_file}")
        return chains
    except Exception as e:
        print(f"[ERROR] Failed to load escalation chains: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Analyze IAM risk and security posture")
    parser.add_argument("--output-dir", default=".", help="Directory to save output files")
    parser.add_argument("--chains-file", help="CSV file with escalation chains from detect_chain_escalation_parallel.py")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting IAM risk analysis...")
    
    # Get all roles and users
    roles = get_all_roles()
    users = get_all_users()
    
    if not roles and not users:
        print("[ERROR] No roles or users found. Exiting.")
        return
    
    # Load escalation chains if provided
    chains = None
    if args.chains_file and os.path.exists(args.chains_file):
        chains = load_escalation_chains(args.chains_file)
    
    # Identify entities with elevated privileges
    elevated_entities = identify_elevated_privileges(roles, users)
    export_findings_to_csv(elevated_entities, f"{args.output_dir}/elevated_privileges.csv")
    
    # Analyze trust policy conditions
    condition_findings = analyze_trust_policy_conditions(roles)
    export_findings_to_csv(condition_findings, f"{args.output_dir}/trust_policy_conditions.csv")
    
    # Calculate risk scores
    risk_findings = calculate_risk_scores(elevated_entities, condition_findings, chains)
    export_findings_to_csv(risk_findings, f"{args.output_dir}/risk_analysis.csv")
    
    # Generate HTML report if requested
    if args.html_report:
        generate_html_report(
            elevated_entities, 
            condition_findings, 
            risk_findings,
            f"{args.output_dir}/iam_risk_report.html"
        )
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"[{end_time}] Analysis completed. Total duration: {duration}")
    
    # Print API statistics
    print("\n=== AWS API Call Statistics ===")
    print(f"Total API calls: {API_STATS['calls']}")
    print(f"Cached responses: {API_STATS['cached']}")
    print(f"Timeouts: {API_STATS['timeouts']}")
    print(f"Errors: {API_STATS['errors']}")
    success_rate = ((API_STATS['calls'] - API_STATS['timeouts'] - API_STATS['errors']) / max(1, API_STATS['calls']) * 100)
    print(f"Success rate: {success_rate:.1f}%")
    
    # Print summary of findings
    print("\n=== Risk Analysis Summary ===")
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in risk_findings:
        risk_counts[finding["RiskLevel"]] += 1
    
    for level, count in risk_counts.items():
        print(f"{level} risk: {count}")

if __name__ == "__main__":
    main()