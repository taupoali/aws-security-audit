#!/usr/bin/env python3

import json
import subprocess
import argparse
import csv
import time
from datetime import datetime

# Track API call statistics
API_STATS = {"calls": 0, "timeouts": 0, "errors": 0, "cached": 0}
API_CACHE = {}

def run_aws_command(cmd, profile=None, region=None, retries=2):
    """Run AWS CLI command with retries and caching"""
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    if region and "--region" not in cmd:
        cmd.insert(1, "--region")
        cmd.insert(2, region)
    
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

def get_identity_center_instance(profile=None):
    """Get IAM Identity Center instance"""
    cmd = ["aws", "sso-admin", "list-instances", "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return None
    
    instances = json.loads(result).get("Instances", [])
    if not instances:
        return None
    
    return instances[0]

def get_identity_source(instance_arn, profile=None):
    """Get identity source for IAM Identity Center"""
    cmd = ["aws", "identitystore", "describe-identity-source", "--identity-store-id", instance_arn, "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return None
    
    return json.loads(result)

def get_permission_sets(instance_arn, profile=None):
    """Get permission sets from IAM Identity Center"""
    cmd = ["aws", "sso-admin", "list-permission-sets", "--instance-arn", instance_arn, "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    permission_set_arns = json.loads(result).get("PermissionSets", [])
    permission_sets = []
    
    for ps_arn in permission_set_arns:
        # Get permission set details
        details_cmd = ["aws", "sso-admin", "describe-permission-set", "--instance-arn", instance_arn, "--permission-set-arn", ps_arn, "--output", "json"]
        details_result = run_aws_command(details_cmd, profile)
        
        if details_result:
            permission_set = json.loads(details_result).get("PermissionSet", {})
            
            # Get inline policy
            inline_cmd = ["aws", "sso-admin", "get-inline-policy-for-permission-set", "--instance-arn", instance_arn, "--permission-set-arn", ps_arn, "--output", "json"]
            inline_result = run_aws_command(inline_cmd, profile)
            
            inline_policy = None
            if inline_result:
                inline_policy = json.loads(inline_result).get("InlinePolicy")
            
            # Get managed policies
            managed_cmd = ["aws", "sso-admin", "list-managed-policies-in-permission-set", "--instance-arn", instance_arn, "--permission-set-arn", ps_arn, "--output", "json"]
            managed_result = run_aws_command(managed_cmd, profile)
            
            managed_policies = []
            if managed_result:
                managed_policies = json.loads(managed_result).get("AttachedManagedPolicies", [])
            
            # Get customer managed policies
            customer_cmd = ["aws", "sso-admin", "list-customer-managed-policy-references-in-permission-set", "--instance-arn", instance_arn, "--permission-set-arn", ps_arn, "--output", "json"]
            customer_result = run_aws_command(customer_cmd, profile)
            
            customer_policies = []
            if customer_result:
                customer_policies = json.loads(customer_result).get("CustomerManagedPolicyReferences", [])
            
            # Add all details to permission set
            permission_set["InlinePolicy"] = inline_policy
            permission_set["ManagedPolicies"] = managed_policies
            permission_set["CustomerManagedPolicies"] = customer_policies
            permission_sets.append(permission_set)
    
    return permission_sets

def get_account_assignments(instance_arn, permission_set_arn, profile=None):
    """Get account assignments for a permission set"""
    cmd = ["aws", "sso-admin", "list-accounts-for-provisioned-permission-set", "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn, "--output", "json"]
    result = run_aws_command(cmd, profile)
    
    if not result:
        return []
    
    account_ids = json.loads(result).get("AccountIds", [])
    assignments = []
    
    for account_id in account_ids:
        # Get assignments for this account
        assign_cmd = ["aws", "sso-admin", "list-account-assignments", "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn, "--account-id", account_id, "--output", "json"]
        assign_result = run_aws_command(assign_cmd, profile)
        
        if assign_result:
            account_assignments = json.loads(assign_result).get("AccountAssignments", [])
            for assignment in account_assignments:
                assignment["AccountId"] = account_id
                assignments.append(assignment)
    
    return assignments

def analyze_permission_set(permission_set):
    """Analyze a permission set for security issues"""
    findings = []
    
    # Check for admin access
    name = permission_set.get("Name", "Unknown")
    ps_arn = permission_set.get("PermissionSetArn", "Unknown")
    
    # Check if this is the AdministratorAccess permission set
    if name == "AdministratorAccess" or "AdministratorAccess" in str(permission_set.get("ManagedPolicies", [])):
        findings.append({
            "PermissionSetName": name,
            "PermissionSetArn": ps_arn,
            "Severity": "High",
            "Issue": "Permission set grants administrator access",
            "Recommendation": "Ensure administrator access is strictly limited and follows least privilege"
        })
    
    # Check inline policy for overly permissive statements
    inline_policy = permission_set.get("InlinePolicy")
    if inline_policy:
        try:
            if isinstance(inline_policy, str):
                policy_doc = json.loads(inline_policy)
            else:
                policy_doc = inline_policy
                
            statements = policy_doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]
                
            for statement in statements:
                if statement.get("Effect") == "Allow":
                    actions = statement.get("Action", [])
                    if not isinstance(actions, list):
                        actions = [actions]
                        
                    resources = statement.get("Resource", [])
                    if not isinstance(resources, list):
                        resources = [resources]
                    
                    # Check for wildcard permissions
                    if "*" in actions:
                        findings.append({
                            "PermissionSetName": name,
                            "PermissionSetArn": ps_arn,
                            "Severity": "High",
                            "Issue": "Inline policy contains wildcard action (*)",
                            "Recommendation": "Replace wildcard with specific actions following least privilege"
                        })
                    
                    # Check for wildcard resources
                    if "*" in resources:
                        findings.append({
                            "PermissionSetName": name,
                            "PermissionSetArn": ps_arn,
                            "Severity": "Medium",
                            "Issue": "Inline policy contains wildcard resource (*)",
                            "Recommendation": "Restrict resources to specific ARNs where possible"
                        })
                    
                    # Check for sensitive actions
                    sensitive_prefixes = ["iam:", "organizations:", "kms:", "secretsmanager:"]
                    for action in actions:
                        for prefix in sensitive_prefixes:
                            if action.startswith(prefix) and action.endswith("*"):
                                findings.append({
                                    "PermissionSetName": name,
                                    "PermissionSetArn": ps_arn,
                                    "Severity": "Medium",
                                    "Issue": f"Inline policy grants broad {prefix} permissions",
                                    "Recommendation": f"Restrict {prefix} permissions to specific actions"
                                })
        except Exception as e:
            findings.append({
                "PermissionSetName": name,
                "PermissionSetArn": ps_arn,
                "Severity": "Low",
                "Issue": f"Error parsing inline policy: {e}",
                "Recommendation": "Verify policy syntax and structure"
            })
    
    # Check session duration
    session_duration = permission_set.get("SessionDuration")
    if session_duration and "PT12H" in session_duration:
        findings.append({
            "PermissionSetName": name,
            "PermissionSetArn": ps_arn,
            "Severity": "Low",
            "Issue": "Long session duration (12 hours)",
            "Recommendation": "Consider reducing session duration for improved security"
        })
    
    return findings

def analyze_identity_center(profile=None):
    """Analyze IAM Identity Center configuration"""
    print("[INFO] Analyzing IAM Identity Center configuration...")
    
    # Get Identity Center instance
    instance = get_identity_center_instance(profile)
    if not instance:
        print("[ERROR] No IAM Identity Center instance found")
        return {
            "Status": "Error",
            "Message": "No IAM Identity Center instance found",
            "Findings": []
        }
    
    instance_arn = instance.get("InstanceArn")
    identity_store_id = instance.get("IdentityStoreId")
    
    print(f"[INFO] Found IAM Identity Center instance: {instance_arn}")
    
    # Get permission sets
    permission_sets = get_permission_sets(instance_arn, profile)
    print(f"[INFO] Found {len(permission_sets)} permission sets")
    
    # Analyze permission sets
    findings = []
    assignments = []
    
    for ps in permission_sets:
        # Analyze permission set
        ps_findings = analyze_permission_set(ps)
        findings.extend(ps_findings)
        
        # Get account assignments
        ps_arn = ps.get("PermissionSetArn")
        ps_assignments = get_account_assignments(instance_arn, ps_arn, profile)
        
        for assignment in ps_assignments:
            assignment["PermissionSetName"] = ps.get("Name")
            assignment["PermissionSetArn"] = ps_arn
        
        assignments.extend(ps_assignments)
    
    # Check for AD integration
    identity_source = get_identity_source(identity_store_id, profile)
    identity_source_type = "Unknown"
    
    if identity_source:
        identity_source_type = identity_source.get("Type", "Unknown")
    
    # Generate summary
    summary = {
        "InstanceArn": instance_arn,
        "IdentityStoreId": identity_store_id,
        "IdentitySourceType": identity_source_type,
        "PermissionSets": len(permission_sets),
        "AccountAssignments": len(assignments),
        "Findings": len(findings)
    }
    
    return {
        "Status": "Success",
        "Summary": summary,
        "PermissionSets": permission_sets,
        "Assignments": assignments,
        "Findings": findings
    }

def generate_recommendations(analysis_result):
    """Generate recommendations based on analysis results"""
    recommendations = []
    
    if analysis_result["Status"] != "Success":
        return recommendations
    
    # Check identity source
    identity_source_type = analysis_result["Summary"]["IdentitySourceType"]
    if identity_source_type == "EXTERNAL":
        recommendations.append({
            "Category": "Identity Source",
            "Priority": "Medium",
            "Recommendation": "Review external identity provider integration security",
            "Details": "Ensure secure SAML configuration and regular rotation of certificates"
        })
    
    # Check permission sets
    permission_sets = analysis_result["PermissionSets"]
    admin_permission_sets = [ps for ps in permission_sets if ps["Name"] == "AdministratorAccess"]
    
    if admin_permission_sets:
        recommendations.append({
            "Category": "Permission Sets",
            "Priority": "High",
            "Recommendation": "Review and limit AdministratorAccess permission set assignments",
            "Details": "Ensure only necessary users/groups have administrator access"
        })
    
    # Check for permission set best practices
    if len(permission_sets) < 3:
        recommendations.append({
            "Category": "Permission Sets",
            "Priority": "Medium",
            "Recommendation": "Create additional permission sets following job functions",
            "Details": "Implement least privilege by creating role-specific permission sets"
        })
    
    # Check findings
    findings = analysis_result["Findings"]
    high_severity_findings = [f for f in findings if f["Severity"] == "High"]
    
    if high_severity_findings:
        recommendations.append({
            "Category": "Security",
            "Priority": "High",
            "Recommendation": f"Address {len(high_severity_findings)} high severity findings",
            "Details": "Review and remediate overly permissive permission sets"
        })
    
    # General recommendations
    recommendations.append({
        "Category": "Process",
        "Priority": "Medium",
        "Recommendation": "Implement regular review of permission set assignments",
        "Details": "Periodically audit who has access to what accounts and permissions"
    })
    
    recommendations.append({
        "Category": "Security",
        "Priority": "Medium",
        "Recommendation": "Enable MFA for IAM Identity Center",
        "Details": "Ensure MFA is required for all users accessing AWS through Identity Center"
    })
    
    return recommendations

def export_to_csv(data, filename):
    """Export data to CSV file"""
    if not data:
        print(f"[WARNING] No data to export to {filename}")
        return
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    
    print(f"[INFO] Exported {len(data)} records to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Analyze AWS IAM Identity Center configuration")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--findings-output", default="identity_center_findings.csv", help="Findings output CSV file")
    parser.add_argument("--assignments-output", default="identity_center_assignments.csv", help="Assignments output CSV file")
    parser.add_argument("--recommendations-output", default="identity_center_recommendations.csv", help="Recommendations output CSV file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting IAM Identity Center analysis...")
    
    # Analyze Identity Center
    analysis_result = analyze_identity_center(args.profile)
    
    if analysis_result["Status"] != "Success":
        print(f"[ERROR] {analysis_result['Message']}")
        return
    
    # Generate recommendations
    recommendations = generate_recommendations(analysis_result)
    
    # Export results
    if analysis_result["Findings"]:
        export_to_csv(analysis_result["Findings"], args.findings_output)
    
    if analysis_result["Assignments"]:
        # Clean up assignments for CSV export
        assignments = []
        for assignment in analysis_result["Assignments"]:
            clean_assignment = {
                "AccountId": assignment.get("AccountId"),
                "PermissionSetName": assignment.get("PermissionSetName"),
                "PrincipalType": assignment.get("PrincipalType"),
                "PrincipalId": assignment.get("PrincipalId")
            }
            assignments.append(clean_assignment)
        
        export_to_csv(assignments, args.assignments_output)
    
    if recommendations:
        export_to_csv(recommendations, args.recommendations_output)
    
    # Print summary
    summary = analysis_result["Summary"]
    print("\n=== IAM Identity Center Summary ===")
    print(f"Identity Source Type: {summary['IdentitySourceType']}")
    print(f"Permission Sets: {summary['PermissionSets']}")
    print(f"Account Assignments: {summary['AccountAssignments']}")
    print(f"Security Findings: {summary['Findings']}")
    
    print("\n=== Recommendations ===")
    for recommendation in recommendations:
        print(f"[{recommendation['Priority']}] {recommendation['Category']}: {recommendation['Recommendation']}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()