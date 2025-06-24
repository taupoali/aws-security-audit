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

def run_aws_command(cmd, profile=None, retries=2):
    """Run AWS CLI command with retries and caching"""
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
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
            error_msg = e.stderr.strip()
            if "AccessDenied" in error_msg or "UnauthorizedOperation" in error_msg:
                print(f"Access denied: {error_msg}")
                return None
            if attempt < retries:
                delay = 1 * (2 ** attempt)  # Exponential backoff
                print(f"Retrying command after {delay}s: {' '.join(cmd)}")
                print(f"Error was: {error_msg}")
                time.sleep(delay)
            else:
                API_STATS["errors"] += 1
                print(f"Command failed after {retries+1} attempts: {' '.join(cmd)}")
                print(f"Error: {error_msg}")
                return None
        except subprocess.TimeoutExpired:
            API_STATS["timeouts"] += 1
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
            else:
                return None
    return None

def get_organization_details(profile=None):
    """Get AWS Organizations details"""
    cmd = ["aws", "organizations", "describe-organization", "--output", "json"]
    
    # Try with increased retries and debug output
    print("[INFO] Attempting to get organization details...")
    result = run_aws_command(cmd, profile, retries=3)
    
    if not result:
        print("[ERROR] Failed to get organization details. Make sure you have appropriate permissions.")
        print("[DEBUG] This could be due to:")
        print("  1. The profile doesn't have organizations:DescribeOrganization permission")
        print("  2. The AWS credentials have expired")
        print("  3. The account is not part of an AWS Organization")
        print("  4. Network connectivity issues")
        print("\nTry running this command manually to debug:")
        manual_cmd = " ".join(cmd)
        if profile:
            manual_cmd = f"aws --profile {profile} organizations describe-organization --output json"
        print(f"  {manual_cmd}")
        return None
    
    try:
        return json.loads(result).get("Organization")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse organization details: {e}")
        print(f"[DEBUG] Raw response: {result[:200]}...")  # Show first 200 chars
        return None

def get_organization_roots(profile=None):
    """Get AWS Organizations roots"""
    cmd = ["aws", "organizations", "list-roots", "--output", "json"]
    result = run_aws_command(cmd, profile)
    if not result:
        return []
    return json.loads(result).get("Roots", [])

def get_organizational_units(parent_id, profile=None):
    """Get AWS Organizations OUs under a parent"""
    cmd = ["aws", "organizations", "list-organizational-units-for-parent", "--parent-id", parent_id, "--output", "json"]
    result = run_aws_command(cmd, profile)
    if not result:
        return []
    return json.loads(result).get("OrganizationalUnits", [])

def get_accounts_for_parent(parent_id, profile=None):
    """Get AWS accounts under a parent (root or OU)"""
    cmd = ["aws", "organizations", "list-accounts-for-parent", "--parent-id", parent_id, "--output", "json"]
    result = run_aws_command(cmd, profile)
    if not result:
        return []
    return json.loads(result).get("Accounts", [])

def get_policies_for_target(target_id, filter_type="SERVICE_CONTROL_POLICY", profile=None):
    """Get policies attached to a target (account, OU, or root)"""
    cmd = ["aws", "organizations", "list-policies-for-target", "--target-id", target_id, "--filter", filter_type, "--output", "json"]
    result = run_aws_command(cmd, profile)
    if not result:
        return []
    return json.loads(result).get("Policies", [])

def get_policy_content(policy_id, profile=None):
    """Get the content of a policy"""
    cmd = ["aws", "organizations", "describe-policy", "--policy-id", policy_id, "--output", "json"]
    result = run_aws_command(cmd, profile)
    if not result:
        return None
    policy = json.loads(result).get("Policy", {})
    content = policy.get("Content", "{}")
    try:
        return json.loads(content)
    except:
        return {}

def analyze_scp(policy_content):
    """Analyze an SCP for common patterns and issues"""
    findings = []
    
    # Check if policy is empty or has no statements
    if not policy_content or "Statement" not in policy_content:
        findings.append({
            "Severity": "High",
            "Issue": "Empty policy or missing Statement",
            "Recommendation": "Ensure the policy has valid Statement elements"
        })
        return findings
    
    statements = policy_content.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    
    # Check for overly permissive statements
    for i, stmt in enumerate(statements):
        # Check for "Effect": "Allow" with broad actions
        if stmt.get("Effect") == "Allow" and ("Action" in stmt or "NotAction" in stmt):
            actions = stmt.get("Action", [])
            if not isinstance(actions, list):
                actions = [actions]
            
            not_actions = stmt.get("NotAction", [])
            if not isinstance(not_actions, list):
                not_actions = [not_actions]
            
            # Check for wildcard actions
            if "*" in actions:
                findings.append({
                    "Severity": "High",
                    "Issue": f"Statement {i+1} allows all actions ('*')",
                    "Recommendation": "Restrict to specific actions needed"
                })
            
            # Check for broad service permissions
            for action in actions:
                if action.endswith(":*"):
                    findings.append({
                        "Severity": "Medium",
                        "Issue": f"Statement {i+1} allows all actions for service: {action}",
                        "Recommendation": "Restrict to specific actions needed for this service"
                    })
        
        # Check for "Effect": "Deny" with limited scope
        if stmt.get("Effect") == "Deny":
            resources = stmt.get("Resource", [])
            if not isinstance(resources, list):
                resources = [resources]
            
            # Check if deny applies to limited resources
            if resources and all("*" not in r for r in resources):
                findings.append({
                    "Severity": "Low",
                    "Issue": f"Statement {i+1} has Deny effect with limited resource scope",
                    "Recommendation": "Consider if the Deny should apply more broadly"
                })
    
    # Check for common security services being restricted
    security_services = ["guardduty", "securityhub", "config", "cloudtrail", "iam"]
    for service in security_services:
        service_restricted = False
        for stmt in statements:
            if stmt.get("Effect") == "Deny":
                actions = stmt.get("Action", [])
                if not isinstance(actions, list):
                    actions = [actions]
                
                for action in actions:
                    if action.startswith(f"{service}:") or action == "*":
                        service_restricted = True
                        break
        
        if service_restricted:
            findings.append({
                "Severity": "High",
                "Issue": f"Policy restricts {service.upper()} service actions",
                "Recommendation": f"Ensure {service.upper()} service is not blocked for security operations"
            })
    
    # If no findings, policy looks good
    if not findings:
        findings.append({
            "Severity": "Info",
            "Issue": "No issues found in policy",
            "Recommendation": "Policy appears to follow best practices"
        })
    
    return findings

def build_organization_structure(profile=None):
    """Build the AWS Organizations structure"""
    org = get_organization_details(profile)
    if not org:
        print("[WARN] Could not retrieve organization details. Attempting to continue with limited functionality.")
        # Create a minimal structure to allow the script to continue
        structure = {
            "Organization": {"Id": "unknown", "MasterAccountId": "unknown"},
            "Roots": [],
            "OUs": [],
            "Accounts": []
        }
        
        # Try to get the root directly
        try:
            print("[INFO] Attempting to list policies directly...")
            cmd = ["aws", "organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY", "--output", "json"]
            if profile:
                cmd = ["aws", "--profile", profile] + cmd[1:]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                policies = json.loads(result.stdout).get("Policies", [])
                if policies:
                    print(f"[INFO] Found {len(policies)} policies directly. Will analyze these.")
                    # Create a dummy root to attach policies to
                    structure["Roots"] = [{
                        "Id": "r-dummy",
                        "Name": "Organization Root",
                        "Policies": policies
                    }]
                    return structure
        except Exception as e:
            print(f"[WARN] Failed to list policies directly: {e}")
        
        print("[ERROR] Cannot continue without organization structure or policies.")
        return None
    
    structure = {
        "Organization": org,
        "Roots": [],
        "OUs": [],
        "Accounts": []
    }
    
    # Get roots
    roots = get_organization_roots(profile)
    structure["Roots"] = roots
    
    # Process each root
    for root in roots:
        root_id = root.get("Id")
        
        # Get OUs under root
        ous = get_organizational_units(root_id, profile)
        for ou in ous:
            ou["ParentId"] = root_id
            ou["ParentType"] = "Root"
            structure["OUs"].append(ou)
            
            # Process nested OUs (one level deep)
            nested_ous = get_organizational_units(ou.get("Id"), profile)
            for nested_ou in nested_ous:
                nested_ou["ParentId"] = ou.get("Id")
                nested_ou["ParentType"] = "OU"
                structure["OUs"].append(nested_ou)
        
        # Get accounts under root
        accounts = get_accounts_for_parent(root_id, profile)
        for account in accounts:
            account["ParentId"] = root_id
            account["ParentType"] = "Root"
            structure["Accounts"].append(account)
    
    # Get accounts under each OU
    for ou in structure["OUs"]:
        accounts = get_accounts_for_parent(ou.get("Id"), profile)
        for account in accounts:
            account["ParentId"] = ou.get("Id")
            account["ParentType"] = "OU"
            structure["Accounts"].append(account)
    
    return structure

def analyze_scps_in_organization(profile=None):
    """Analyze SCPs in the AWS Organization"""
    print("[INFO] Building organization structure...")
    org_structure = build_organization_structure(profile)
    if not org_structure:
        return []
    
    print("[INFO] Analyzing Service Control Policies...")
    scp_findings = []
    
    # Analyze SCPs attached to roots
    for root in org_structure["Roots"]:
        root_id = root.get("Id")
        root_name = root.get("Name", "Unknown Root")
        
        policies = get_policies_for_target(root_id, profile=profile)
        for policy in policies:
            policy_id = policy.get("Id")
            policy_name = policy.get("Name")
            
            print(f"[INFO] Analyzing SCP: {policy_name} (attached to Root: {root_name})")
            policy_content = get_policy_content(policy_id, profile)
            analysis = analyze_scp(policy_content)
            
            for finding in analysis:
                scp_findings.append({
                    "PolicyId": policy_id,
                    "PolicyName": policy_name,
                    "TargetType": "Root",
                    "TargetId": root_id,
                    "TargetName": root_name,
                    "Severity": finding.get("Severity"),
                    "Issue": finding.get("Issue"),
                    "Recommendation": finding.get("Recommendation")
                })
    
    # Analyze SCPs attached to OUs
    for ou in org_structure["OUs"]:
        ou_id = ou.get("Id")
        ou_name = ou.get("Name", "Unknown OU")
        
        policies = get_policies_for_target(ou_id, profile=profile)
        for policy in policies:
            policy_id = policy.get("Id")
            policy_name = policy.get("Name")
            
            print(f"[INFO] Analyzing SCP: {policy_name} (attached to OU: {ou_name})")
            policy_content = get_policy_content(policy_id, profile)
            analysis = analyze_scp(policy_content)
            
            for finding in analysis:
                scp_findings.append({
                    "PolicyId": policy_id,
                    "PolicyName": policy_name,
                    "TargetType": "OU",
                    "TargetId": ou_id,
                    "TargetName": ou_name,
                    "Severity": finding.get("Severity"),
                    "Issue": finding.get("Issue"),
                    "Recommendation": finding.get("Recommendation")
                })
    
    # Analyze SCPs attached to accounts
    for account in org_structure["Accounts"]:
        account_id = account.get("Id")
        account_name = account.get("Name", "Unknown Account")
        
        policies = get_policies_for_target(account_id, profile=profile)
        for policy in policies:
            policy_id = policy.get("Id")
            policy_name = policy.get("Name")
            
            print(f"[INFO] Analyzing SCP: {policy_name} (attached to Account: {account_name})")
            policy_content = get_policy_content(policy_id, profile)
            analysis = analyze_scp(policy_content)
            
            for finding in analysis:
                scp_findings.append({
                    "PolicyId": policy_id,
                    "PolicyName": policy_name,
                    "TargetType": "Account",
                    "TargetId": account_id,
                    "TargetName": account_name,
                    "Severity": finding.get("Severity"),
                    "Issue": finding.get("Issue"),
                    "Recommendation": finding.get("Recommendation")
                })
    
    return scp_findings

def export_to_csv(findings, filename):
    """Export findings to CSV file"""
    if not findings:
        print(f"[WARNING] No findings to export to {filename}")
        return
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=findings[0].keys())
        writer.writeheader()
        writer.writerows(findings)
    
    print(f"[INFO] Exported {len(findings)} findings to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Analyze AWS Service Control Policies")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--output", default="scp_findings.csv", help="Output CSV file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting SCP analysis...")
    
    # Analyze SCPs
    findings = analyze_scps_in_organization(args.profile)
    
    # Export findings
    export_to_csv(findings, args.output)
    
    # Print summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        severity = finding.get("Severity")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    print("\n=== SCP Analysis Summary ===")
    print(f"Total findings: {len(findings)}")
    for severity, count in severity_counts.items():
        print(f"{severity} findings: {count}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()