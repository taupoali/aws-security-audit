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

def get_control_tower_status(profile=None, region="us-east-1"):
    """Check if Control Tower is enabled and get its status"""
    cmd = ["aws", "controltower", "get-landing-zone", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return None
    
    return json.loads(result)

def get_enabled_controls(profile=None, region="us-east-1"):
    """Get all enabled controls in Control Tower"""
    cmd = ["aws", "controltower", "list-enabled-controls", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return []
    
    return json.loads(result).get("enabledControls", [])

def get_control_details(control_id, profile=None, region="us-east-1"):
    """Get details for a specific control"""
    cmd = ["aws", "controltower", "get-control", "--control-identifier", control_id, "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return None
    
    return json.loads(result).get("control", {})

def get_registered_ous(profile=None, region="us-east-1"):
    """Get OUs registered with Control Tower"""
    cmd = ["aws", "controltower", "list-managed-organizational-units", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return []
    
    return json.loads(result).get("organizationalUnits", [])

def get_drift_status(profile=None, region="us-east-1"):
    """Check for drift in Control Tower resources"""
    cmd = ["aws", "controltower", "list-drifted-resources", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return []
    
    return json.loads(result).get("driftedResources", [])

def get_guardrails_status(profile=None, region="us-east-1"):
    """Get status of guardrails in Control Tower"""
    cmd = ["aws", "controltower", "list-guardrails", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return []
    
    return json.loads(result).get("guardrails", [])

def get_accounts_in_ou(ou_id, profile=None, region="us-east-1"):
    """Get accounts in an OU using Organizations API"""
    cmd = ["aws", "organizations", "list-accounts-for-parent", "--parent-id", ou_id, "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return []
    
    return json.loads(result).get("Accounts", [])

def analyze_control_tower(profile=None, region="us-east-1"):
    """Analyze Control Tower configuration"""
    print("[INFO] Analyzing AWS Control Tower configuration...")
    
    # Check if Control Tower is enabled
    ct_status = get_control_tower_status(profile, region)
    if not ct_status:
        print("[ERROR] Control Tower is not enabled or you don't have permissions to access it")
        return {
            "Status": "Error",
            "Message": "Control Tower is not enabled or you don't have permissions to access it"
        }
    
    landing_zone = ct_status.get("landingZone", {})
    print(f"[INFO] Control Tower Landing Zone: {landing_zone.get('name')} (Version: {landing_zone.get('version')})")
    
    # Get enabled controls
    enabled_controls = get_enabled_controls(profile, region)
    print(f"[INFO] Found {len(enabled_controls)} enabled controls")
    
    # Get control details
    controls = []
    for control in enabled_controls:
        control_id = control.get("controlIdentifier")
        details = get_control_details(control_id, profile, region)
        if details:
            controls.append(details)
    
    # Get registered OUs
    ous = get_registered_ous(profile, region)
    print(f"[INFO] Found {len(ous)} registered OUs")
    
    # Get accounts in each OU
    ou_accounts = {}
    for ou in ous:
        ou_id = ou.get("organizationalUnitId")
        accounts = get_accounts_in_ou(ou_id, profile, region)
        ou_accounts[ou_id] = accounts
        print(f"[INFO] Found {len(accounts)} accounts in OU {ou.get('organizationalUnitName')}")
    
    # Check for drift
    drifted_resources = get_drift_status(profile, region)
    print(f"[INFO] Found {len(drifted_resources)} drifted resources")
    
    # Get guardrails status
    guardrails = get_guardrails_status(profile, region)
    print(f"[INFO] Found {len(guardrails)} guardrails")
    
    # Analyze security controls
    security_findings = []
    
    # Check if mandatory security controls are enabled
    mandatory_controls = [
        "AWS-GR_AUDIT_BUCKET_DELETION_PROHIBITED",
        "AWS-GR_AUDIT_BUCKET_PUBLIC_READ_PROHIBITED",
        "AWS-GR_AUDIT_BUCKET_PUBLIC_WRITE_PROHIBITED",
        "AWS-GR_CLOUDTRAIL_ENABLED",
        "AWS-GR_ENCRYPTED_VOLUMES",
        "AWS-GR_IAM_USER_MFA_ENABLED",
        "AWS-GR_RESTRICT_ROOT_USER",
        "AWS-GR_ROOT_ACCOUNT_MFA_ENABLED"
    ]
    
    enabled_control_ids = [c.get("id") for c in controls]
    
    for control_id in mandatory_controls:
        if not any(control_id in c for c in enabled_control_ids):
            security_findings.append({
                "FindingType": "MissingControl",
                "Severity": "High",
                "ControlId": control_id,
                "Issue": f"Mandatory security control {control_id} is not enabled",
                "Recommendation": "Enable this control to improve security posture"
            })
    
    # Check for drift issues
    for resource in drifted_resources:
        security_findings.append({
            "FindingType": "Drift",
            "Severity": "Medium",
            "ResourceId": resource.get("resourceId", "Unknown"),
            "ResourceType": resource.get("resourceType", "Unknown"),
            "Issue": f"Resource has drifted from Control Tower configuration",
            "Recommendation": "Resolve drift to maintain security compliance"
        })
    
    # Check for guardrail compliance
    non_compliant_guardrails = [g for g in guardrails if g.get("complianceStatus") != "COMPLIANT"]
    for guardrail in non_compliant_guardrails:
        security_findings.append({
            "FindingType": "GuardrailViolation",
            "Severity": "Medium",
            "GuardrailId": guardrail.get("guardrailId", "Unknown"),
            "GuardrailName": guardrail.get("guardrailName", "Unknown"),
            "Issue": f"Guardrail is not compliant: {guardrail.get('guardrailName')}",
            "Recommendation": "Review and address guardrail compliance issues"
        })
    
    # Check Control Tower version
    ct_version = landing_zone.get("version")
    if ct_version and ct_version < "3.0":
        security_findings.append({
            "FindingType": "OutdatedVersion",
            "Severity": "Medium",
            "CurrentVersion": ct_version,
            "Issue": "Control Tower is running an outdated version",
            "Recommendation": "Update to the latest version for improved security features"
        })
    
    return {
        "Status": "Success",
        "LandingZone": landing_zone,
        "Controls": controls,
        "OrganizationalUnits": ous,
        "OUAccounts": ou_accounts,
        "DriftedResources": drifted_resources,
        "Guardrails": guardrails,
        "SecurityFindings": security_findings
    }

def generate_recommendations(analysis_result):
    """Generate recommendations based on analysis results"""
    if analysis_result["Status"] != "Success":
        return []
    
    recommendations = []
    
    # Check for security findings
    security_findings = analysis_result.get("SecurityFindings", [])
    high_severity_findings = [f for f in security_findings if f.get("Severity") == "High"]
    medium_severity_findings = [f for f in security_findings if f.get("Severity") == "Medium"]
    
    if high_severity_findings:
        recommendations.append({
            "Category": "Security",
            "Priority": "High",
            "Recommendation": f"Address {len(high_severity_findings)} high severity Control Tower findings",
            "Details": "Enable missing mandatory security controls"
        })
    
    if medium_severity_findings:
        recommendations.append({
            "Category": "Compliance",
            "Priority": "Medium",
            "Recommendation": f"Resolve {len(medium_severity_findings)} medium severity Control Tower findings",
            "Details": "Address drift and guardrail compliance issues"
        })
    
    # Check for drifted resources
    drifted_resources = analysis_result.get("DriftedResources", [])
    if drifted_resources:
        recommendations.append({
            "Category": "Governance",
            "Priority": "Medium",
            "Recommendation": f"Resolve drift in {len(drifted_resources)} resources",
            "Details": "Use Control Tower to re-register drifted resources"
        })
    
    # Check Control Tower version
    landing_zone = analysis_result.get("LandingZone", {})
    ct_version = landing_zone.get("version")
    if ct_version and ct_version < "3.0":
        recommendations.append({
            "Category": "Maintenance",
            "Priority": "Medium",
            "Recommendation": "Update Control Tower to the latest version",
            "Details": f"Current version ({ct_version}) is outdated"
        })
    
    # General recommendations
    recommendations.append({
        "Category": "Best Practice",
        "Priority": "Medium",
        "Recommendation": "Regularly review Control Tower guardrails",
        "Details": "Ensure guardrails are appropriate for your security requirements"
    })
    
    recommendations.append({
        "Category": "Process",
        "Priority": "Medium",
        "Recommendation": "Implement process for managing Control Tower drift",
        "Details": "Regular checks and remediation of drift to maintain security posture"
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
    parser = argparse.ArgumentParser(description="Analyze AWS Control Tower configuration")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region where Control Tower is deployed")
    parser.add_argument("--findings-output", default="control_tower_findings.csv", help="Findings output CSV file")
    parser.add_argument("--recommendations-output", default="control_tower_recommendations.csv", help="Recommendations output CSV file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting Control Tower analysis...")
    
    # Analyze Control Tower
    analysis_result = analyze_control_tower(args.profile, args.region)
    
    if analysis_result["Status"] != "Success":
        print(f"[ERROR] {analysis_result['Message']}")
        return
    
    # Generate recommendations
    recommendations = generate_recommendations(analysis_result)
    
    # Export results
    if analysis_result.get("SecurityFindings"):
        export_to_csv(analysis_result["SecurityFindings"], args.findings_output)
    
    if recommendations:
        export_to_csv(recommendations, args.recommendations_output)
    
    # Print summary
    print("\n=== Control Tower Summary ===")
    landing_zone = analysis_result.get("LandingZone", {})
    print(f"Landing Zone: {landing_zone.get('name')} (Version: {landing_zone.get('version')})")
    print(f"Enabled Controls: {len(analysis_result.get('Controls', []))}")
    print(f"Registered OUs: {len(analysis_result.get('OrganizationalUnits', []))}")
    print(f"Drifted Resources: {len(analysis_result.get('DriftedResources', []))}")
    print(f"Security Findings: {len(analysis_result.get('SecurityFindings', []))}")
    
    print("\n=== Recommendations ===")
    for recommendation in recommendations:
        print(f"[{recommendation['Priority']}] {recommendation['Category']}: {recommendation['Recommendation']}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()