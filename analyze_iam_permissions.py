#!/usr/bin/env python3

import json
import argparse
import subprocess
import csv
import time
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Track API call statistics
API_STATS = {"calls": 0, "timeouts": 0, "errors": 0, "cached": 0}
API_CACHE = {}

def run_aws_command(cmd, profile=None, retries=3):
    """Run AWS CLI command with retries and caching"""
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    cmd_key = ' '.join(cmd)
    if cmd_key in API_CACHE:
        API_STATS["cached"] += 1
        return API_CACHE[cmd_key]
    
    API_STATS["calls"] += 1
    
    # Backoff parameters
    base_delay = 1.0  # Start with 1 second
    max_delay = 30.0  # Maximum delay of 30 seconds
    
    # Function to create a readable command summary
    def create_cmd_summary(cmd):
        cmd_summary = ""
        profile_info = ""
        
        if len(cmd) >= 2 and cmd[0] == "aws":
            # Check if profile is being used
            if "--profile" in cmd:
                profile_idx = cmd.index("--profile")
                if profile_idx + 1 < len(cmd):
                    profile_info = f" (profile: {cmd[profile_idx+1]})"
            
            # Extract the AWS service (e.g., iam, s3, ec2)
            service_idx = 1
            if "--profile" in cmd and cmd.index("--profile") == 1:
                service_idx = 3  # Skip the profile parameter
            
            if len(cmd) > service_idx:
                cmd_summary = f"aws {cmd[service_idx]}"
            
            # Add the operation if available
            if len(cmd) > service_idx + 1:
                cmd_summary += f" {cmd[service_idx+1]}"
            
            # Add resource identifier if available
            for i in range(service_idx+2, len(cmd)-1):
                if cmd[i].startswith("--") and i+1 < len(cmd):
                    if cmd[i] in ["--role-name", "--user-name", "--policy-name", "--policy-arn"]:
                        cmd_summary += f" {cmd[i]} {cmd[i+1]}"
                        break
            
            # Add profile info at the end
            cmd_summary += profile_info
        else:
            # Fallback to showing first and last parts
            cmd_summary = f"{cmd[0]} ... {cmd[-1]}"
            
        return cmd_summary
    
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
                # True exponential backoff with jitter
                delay = min(max_delay, base_delay * (2 ** attempt))
                # Add jitter (±20%)
                jitter = delay * 0.2 * (2 * (0.5 - (time.time() % 1)) if time.time() % 1 > 0.5 else 0)
                actual_delay = delay + jitter
                
                cmd_summary = create_cmd_summary(cmd)
                print(f"Retrying command after {actual_delay:.2f}s (attempt {attempt+1}/{retries}): {cmd_summary}")
                time.sleep(actual_delay)
            else:
                API_STATS["errors"] += 1
                return None
        except subprocess.TimeoutExpired:
            API_STATS["timeouts"] += 1
            if attempt < retries:
                # Use same exponential backoff for timeouts
                delay = min(max_delay, base_delay * (2 ** attempt))
                # Add jitter (±20%)
                jitter = delay * 0.2 * (2 * (0.5 - (time.time() % 1)) if time.time() % 1 > 0.5 else 0)
                actual_delay = delay + jitter
                
                cmd_summary = create_cmd_summary(cmd)
                print(f"Command timed out, retrying after {actual_delay:.2f}s (attempt {attempt+1}/{retries}): {cmd_summary}")
                time.sleep(actual_delay)
            else:
                return None
    return None

def get_account_id(profile=None):
    """Get current AWS account ID"""
    result = run_aws_command(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], profile)
    return result.strip() if result else "unknown"

def get_all_roles(profile=None):
    """Get all IAM roles in the account"""
    print("[INFO] Retrieving all IAM roles...")
    result = run_aws_command(["aws", "iam", "list-roles", "--output", "json"], profile)
    if not result:
        print("[ERROR] Failed to retrieve IAM roles")
        return []
    
    roles_data = json.loads(result)
    roles = roles_data.get("Roles", [])
    print(f"[INFO] Found {len(roles)} IAM roles")
    return roles

def get_role_policies(role_name, profile=None):
    """Get all policies (inline and managed) attached to a role"""
    policies = []
    
    # Get inline policies
    inline_result = run_aws_command(["aws", "iam", "list-role-policies", "--role-name", role_name, "--output", "json"], profile)
    if inline_result:
        policy_names = json.loads(inline_result).get("PolicyNames", [])
        for policy_name in policy_names:
            policy_result = run_aws_command([
                "aws", "iam", "get-role-policy", 
                "--role-name", role_name, 
                "--policy-name", policy_name,
                "--output", "json"
            ], profile)
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
    ], profile)
    if managed_result:
        attached_policies = json.loads(managed_result).get("AttachedPolicies", [])
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            policy_version_result = run_aws_command([
                "aws", "iam", "get-policy",
                "--policy-arn", policy_arn,
                "--output", "json"
            ], profile)
            
            if policy_version_result:
                policy_data = json.loads(policy_version_result)
                default_version = policy_data.get("Policy", {}).get("DefaultVersionId")
                
                if default_version:
                    version_result = run_aws_command([
                        "aws", "iam", "get-policy-version",
                        "--policy-arn", policy_arn,
                        "--version-id", default_version,
                        "--output", "json"
                    ], profile)
                    
                    if version_result:
                        version_data = json.loads(version_result)
                        policies.append({
                            "PolicyName": policy.get("PolicyName"),
                            "PolicyArn": policy_arn,
                            "PolicyDocument": version_data.get("PolicyVersion", {}).get("Document", {}),
                            "Type": "Managed"
                        })
    
    return policies

def get_role_trust_policy(role_name, profile=None):
    """Get the trust policy for a role"""
    result = run_aws_command(["aws", "iam", "get-role", "--role-name", role_name, "--output", "json"], profile)
    if result:
        role_data = json.loads(result)
        return role_data.get("Role", {}).get("AssumeRolePolicyDocument", {})
    return {}

def analyze_cross_account_access(roles, profile=None):
    """Analyze cross-account access in roles"""
    print("[INFO] Analyzing cross-account access...")
    current_account = get_account_id(profile)
    cross_account_findings = []
    
    for role in roles:
        role_name = role.get("RoleName")
        
        # Check trust policy for cross-account access
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        trust_statements = trust_policy.get("Statement", [])
        if not isinstance(trust_statements, list):
            trust_statements = [trust_statements]
            
        for statement in trust_statements:
            if statement.get("Effect") != "Allow":
                continue
                
            principal = statement.get("Principal", {})
            aws_principal = principal.get("AWS", [])
            
            if not aws_principal:
                continue
                
            if not isinstance(aws_principal, list):
                aws_principal = [aws_principal]
                
            for principal_value in aws_principal:
                if principal_value == "*":
                    cross_account_findings.append({
                        "RoleName": role_name,
                        "FindingType": "TrustPolicy",
                        "Issue": "Role can be assumed by any AWS account",
                        "Principal": "*"
                    })
                elif "arn:aws:iam::" in principal_value and not principal_value.startswith(f"arn:aws:iam::{current_account}:"):
                    external_account = principal_value.split(":")[4]
                    cross_account_findings.append({
                        "RoleName": role_name,
                        "FindingType": "TrustPolicy",
                        "Issue": f"Role can be assumed by external account {external_account}",
                        "Principal": principal_value
                    })
        
        # Check role policies for cross-account access
        policies = get_role_policies(role_name, profile)
        for policy in policies:
            policy_doc = policy.get("PolicyDocument", {})
            statements = policy_doc.get("Statement", [])
            
            if not isinstance(statements, list):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                    
                resources = statement.get("Resource", [])
                if not isinstance(resources, list):
                    resources = [resources]
                    
                for resource in resources:
                    if isinstance(resource, str) and "arn:aws" in resource:
                        # Check if resource belongs to another account
                        if "arn:aws:iam::" in resource and not resource.startswith(f"arn:aws:iam::{current_account}:"):
                            external_account = resource.split(":")[4]
                            cross_account_findings.append({
                                "RoleName": role_name,
                                "FindingType": "ResourceAccess",
                                "Issue": f"Role has access to resources in external account {external_account}",
                                "Resource": resource,
                                "PolicyName": policy.get("PolicyName"),
                                "PolicyType": policy.get("Type")
                            })
    
    print(f"[INFO] Found {len(cross_account_findings)} cross-account access findings")
    return cross_account_findings

def analyze_role_permissions(roles, profile=None):
    """Analyze role permissions for least privilege assessment"""
    print("[INFO] Analyzing role permissions...")
    permission_findings = []
    
    # Define high-risk permissions
    high_risk_actions = {
        "iam:*", "s3:*", "ec2:*", "lambda:*", "dynamodb:*", "kms:*", 
        "secretsmanager:*", "cloudformation:*", "sts:*", "*"
    }
    
    # Define service categories for grouping
    service_categories = {
        "Data": ["s3", "dynamodb", "rds", "redshift", "athena", "glue"],
        "Compute": ["ec2", "lambda", "ecs", "eks", "batch"],
        "Security": ["iam", "kms", "secretsmanager", "acm", "waf"],
        "Networking": ["vpc", "route53", "elb", "apigateway"],
        "Management": ["cloudformation", "cloudwatch", "config", "organizations"]
    }
    
    for role in roles:
        role_name = role.get("RoleName")
        policies = get_role_policies(role_name, profile)
        
        # Track permissions by service
        service_permissions = {}
        wildcard_permissions = []
        admin_permissions = []
        total_permissions = 0
        
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
                
                for action in actions:
                    total_permissions += 1
                    
                    # Track service usage
                    if ":" in action:
                        service = action.split(":")[0]
                        if service not in service_permissions:
                            service_permissions[service] = 0
                        service_permissions[service] += 1
                    
                    # Check for wildcard permissions
                    if "*" in action:
                        wildcard_permissions.append({
                            "Action": action,
                            "Resources": resources,
                            "PolicyName": policy.get("PolicyName"),
                            "PolicyType": policy.get("Type")
                        })
                    
                    # Check for admin permissions
                    if action in high_risk_actions:
                        admin_permissions.append({
                            "Action": action,
                            "Resources": resources,
                            "PolicyName": policy.get("PolicyName"),
                            "PolicyType": policy.get("Type")
                        })
        
        # Calculate service category coverage
        category_coverage = {}
        for category, services in service_categories.items():
            category_services = [s for s in service_permissions.keys() if s in services]
            category_coverage[category] = len(category_services) / len(services) if services else 0
        
        # Determine if role follows least privilege
        follows_least_privilege = len(wildcard_permissions) == 0 and len(admin_permissions) < 3
        
        # Add findings
        permission_findings.append({
            "RoleName": role_name,
            "TotalPermissions": total_permissions,
            "UniqueServices": len(service_permissions),
            "WildcardPermissions": len(wildcard_permissions),
            "AdminPermissions": len(admin_permissions),
            "ServiceCoverage": service_permissions,
            "CategoryCoverage": category_coverage,
            "FollowsLeastPrivilege": follows_least_privilege,
            "Details": {
                "WildcardPermissions": wildcard_permissions,
                "AdminPermissions": admin_permissions
            }
        })
    
    print(f"[INFO] Completed permission analysis for {len(permission_findings)} roles")
    return permission_findings

def analyze_role_pass_permissions(roles, profile=None):
    """Analyze roles that can pass roles to services"""
    print("[INFO] Analyzing role pass permissions...")
    pass_role_findings = []
    
    for role in roles:
        role_name = role.get("RoleName")
        policies = get_role_policies(role_name, profile)
        
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
                
                # Check for PassRole permission
                if "iam:PassRole" in actions or "iam:*" in actions or "*" in actions:
                    pass_role_findings.append({
                        "RoleName": role_name,
                        "FindingType": "PassRole",
                        "Resources": resources,
                        "PolicyName": policy.get("PolicyName"),
                        "PolicyType": policy.get("Type")
                    })
    
    print(f"[INFO] Found {len(pass_role_findings)} roles with PassRole permissions")
    return pass_role_findings

def export_findings_to_csv(findings, filename):
    """Export findings to CSV file"""
    if not findings:
        print(f"[WARNING] No findings to export to {filename}")
        return False
        
    try:
        with open(filename, 'w', newline='') as csvfile:
            if isinstance(findings[0], dict):
                # Get all possible field names from all findings
                all_keys = set()
                for finding in findings:
                    all_keys.update(finding.keys())
                
                fieldnames = list(all_keys)
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                for finding in findings:
                    # Convert complex objects to strings
                    row_data = {}
                    for key in fieldnames:
                        if key in finding:
                            value = finding[key]
                            if isinstance(value, (dict, list)):
                                row_data[key] = json.dumps(value)
                            else:
                                row_data[key] = value
                        else:
                            row_data[key] = ""
                    
                    writer.writerow(row_data)
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

def main():
    parser = argparse.ArgumentParser(description="Analyze IAM permissions for security audit")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--output-dir", default=".", help="Directory to save output files")
    parser.add_argument("--cross-account", action="store_true", help="Analyze cross-account access")
    parser.add_argument("--least-privilege", action="store_true", help="Analyze adherence to least privilege")
    parser.add_argument("--pass-role", action="store_true", help="Analyze PassRole permissions")
    parser.add_argument("--all", action="store_true", help="Run all analyses")
    parser.add_argument("--max-workers", type=int, default=5, help="Maximum number of parallel workers")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting IAM permission analysis...")
    
    # Get all roles
    roles = get_all_roles(args.profile)
    if not roles:
        print("[ERROR] No roles found. Exiting.")
        return
    
    # Run selected analyses
    if args.all or args.cross_account:
        cross_account_findings = analyze_cross_account_access(roles, args.profile)
        export_findings_to_csv(cross_account_findings, f"{args.output_dir}/cross_account_findings.csv")
    
    if args.all or args.least_privilege:
        permission_findings = analyze_role_permissions(roles, args.profile)
        export_findings_to_csv(permission_findings, f"{args.output_dir}/permission_findings.csv")
    
    if args.all or args.pass_role:
        pass_role_findings = analyze_role_pass_permissions(roles, args.profile)
        export_findings_to_csv(pass_role_findings, f"{args.output_dir}/pass_role_findings.csv")
    
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

if __name__ == "__main__":
    main()