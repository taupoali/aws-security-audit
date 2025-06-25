#!/usr/bin/env python3

import json
import subprocess
import argparse
import csv
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def get_regions(profile=None):
    """Get list of all AWS regions"""
    cmd = ["aws", "ec2", "describe-regions", "--query", "Regions[].RegionName", "--output", "json"]
    result = run_aws_command(cmd, profile)
    if result:
        return json.loads(result)
    return ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1"]

def get_account_id(profile=None):
    """Get current AWS account ID"""
    cmd = ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"]
    result = run_aws_command(cmd, profile)
    return result.strip() if result else "unknown"

def check_access_analyzer_status(region, profile=None):
    """Check if IAM Access Analyzer is enabled in a region"""
    cmd = ["aws", "accessanalyzer", "list-analyzers", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return {
            "Region": region,
            "Status": "Error",
            "Message": "Failed to check Access Analyzer status"
        }
    
    analyzers = json.loads(result).get("analyzers", [])
    if not analyzers:
        return {
            "Region": region,
            "Status": "Disabled",
            "Message": "IAM Access Analyzer is not enabled in this region"
        }
    
    # Check if there's an active analyzer
    active_analyzers = [a for a in analyzers if a.get("status") == "ACTIVE"]
    if not active_analyzers:
        return {
            "Region": region,
            "Status": "Inactive",
            "Message": "IAM Access Analyzer exists but is not active"
        }
    
    # Check analyzer type (account or organization)
    account_analyzers = [a for a in active_analyzers if a.get("type") == "ACCOUNT"]
    org_analyzers = [a for a in active_analyzers if a.get("type") == "ORGANIZATION"]
    
    if org_analyzers:
        return {
            "Region": region,
            "Status": "Enabled",
            "AnalyzerType": "Organization",
            "AnalyzerId": org_analyzers[0].get("arn"),
            "Message": "Organization-level IAM Access Analyzer is active"
        }
    elif account_analyzers:
        return {
            "Region": region,
            "Status": "Enabled",
            "AnalyzerType": "Account",
            "AnalyzerId": account_analyzers[0].get("arn"),
            "Message": "Account-level IAM Access Analyzer is active"
        }
    else:
        return {
            "Region": region,
            "Status": "Unknown",
            "Message": "IAM Access Analyzer exists but type is unknown"
        }

def get_access_analyzer_findings(analyzer_id, region, profile=None):
    """Get findings from IAM Access Analyzer"""
    cmd = ["aws", "accessanalyzer", "list-findings", "--analyzer-arn", analyzer_id, "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        return []
    
    findings = json.loads(result).get("findings", [])
    return findings

def analyze_findings(findings):
    """Analyze IAM Access Analyzer findings"""
    analyzed_findings = []
    
    for finding in findings:
        resource = finding.get("resource", "")
        resource_type = finding.get("resourceType", "")
        finding_id = finding.get("id", "")
        status = finding.get("status", "")
        created_at = finding.get("createdAt", "")
        
        # Convert timestamp to readable format
        if created_at:
            try:
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        # Get resource owner
        resource_owner = finding.get("resourceOwnerAccount", "")
        
        # Get action that can be performed by external principals
        actions = finding.get("action", [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Get external principal that can access the resource
        principal = "Unknown"
        condition = "None"
        
        if "principal" in finding:
            principal_data = finding.get("principal", {})
            if isinstance(principal_data, dict):
                if "AWS" in principal_data:
                    principal = principal_data["AWS"]
                elif "Service" in principal_data:
                    principal = principal_data["Service"]
                elif "Federated" in principal_data:
                    principal = principal_data["Federated"]
            else:
                principal = str(principal_data)
        
        # Check if there are conditions
        if "condition" in finding:
            condition = json.dumps(finding.get("condition", {}))
        
        # Determine severity based on resource type and actions
        severity = "Medium"  # Default
        
        # Higher severity for IAM, KMS, and S3 resources
        if resource_type in ["AWS::IAM::Role", "AWS::KMS::Key", "AWS::S3::Bucket"]:
            severity = "High"
        
        # Higher severity for admin actions
        admin_actions = ["iam:", "kms:", "s3:*", "ec2:*", "*:*"]
        for action in actions:
            if any(action.startswith(admin) for admin in admin_actions):
                severity = "High"
                break
        
        # Critical severity for public access to sensitive resources
        if principal == "*" and resource_type in ["AWS::S3::Bucket", "AWS::KMS::Key"]:
            severity = "Critical"
        
        analyzed_findings.append({
            "FindingId": finding_id,
            "ResourceType": resource_type,
            "Resource": resource,
            "ResourceOwner": resource_owner,
            "Actions": ", ".join(actions) if isinstance(actions, list) else actions,
            "ExternalPrincipal": principal,
            "Conditions": condition,
            "Status": status,
            "CreatedAt": created_at,
            "Severity": severity
        })
    
    return analyzed_findings

def check_region_analyzers(region, profile=None):
    """Check Access Analyzer in a region and get findings"""
    print(f"[INFO] Checking Access Analyzer in region: {region}")
    
    # Check if Access Analyzer is enabled
    analyzer_status = check_access_analyzer_status(region, profile)
    
    if analyzer_status["Status"] != "Enabled":
        return {
            "Status": analyzer_status,
            "Findings": []
        }
    
    # Get findings from the analyzer
    analyzer_id = analyzer_status.get("AnalyzerId")
    findings = get_access_analyzer_findings(analyzer_id, region, profile)
    analyzed_findings = analyze_findings(findings)
    
    print(f"[INFO] Found {len(analyzed_findings)} Access Analyzer findings in {region}")
    
    return {
        "Status": analyzer_status,
        "Findings": analyzed_findings
    }

def analyze_access_analyzer(profile=None, regions=None):
    """Analyze IAM Access Analyzer across regions"""
    if not regions:
        regions = get_regions(profile)
    
    print(f"[INFO] Analyzing IAM Access Analyzer across {len(regions)} regions")
    
    account_id = get_account_id(profile)
    print(f"[INFO] Account ID: {account_id}")
    
    all_results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_region = {executor.submit(check_region_analyzers, region, profile): region for region in regions}
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                print(f"[ERROR] Error analyzing region {region}: {e}")
    
    return all_results

def generate_recommendations(results):
    """Generate recommendations based on Access Analyzer results"""
    recommendations = []
    
    # Check if Access Analyzer is enabled in all regions
    disabled_regions = [r["Status"]["Region"] for r in results if r["Status"]["Status"] != "Enabled"]
    if disabled_regions:
        recommendations.append({
            "Category": "Access Analyzer Configuration",
            "Priority": "High",
            "Recommendation": f"Enable IAM Access Analyzer in regions: {', '.join(disabled_regions)}",
            "Rationale": "IAM Access Analyzer helps identify resources shared with external entities"
        })
    
    # Check if organization-level analyzer is used
    org_analyzers = [r for r in results if r["Status"].get("AnalyzerType") == "Organization"]
    if not org_analyzers and len(results) > 0:
        recommendations.append({
            "Category": "Access Analyzer Configuration",
            "Priority": "Medium",
            "Recommendation": "Consider using organization-level analyzers instead of account-level",
            "Rationale": "Organization-level analyzers provide visibility across all accounts in the organization"
        })
    
    # Analyze findings
    all_findings = []
    for result in results:
        all_findings.extend(result["Findings"])
    
    # Group findings by resource type
    resource_types = {}
    for finding in all_findings:
        resource_type = finding["ResourceType"]
        if resource_type not in resource_types:
            resource_types[resource_type] = []
        resource_types[resource_type].append(finding)
    
    # Generate recommendations for each resource type
    for resource_type, findings in resource_types.items():
        critical_findings = [f for f in findings if f["Severity"] == "Critical"]
        high_findings = [f for f in findings if f["Severity"] == "High"]
        
        if critical_findings:
            recommendations.append({
                "Category": f"{resource_type} Access",
                "Priority": "Critical",
                "Recommendation": f"Review and remediate {len(critical_findings)} critical external access findings for {resource_type}",
                "Rationale": "These resources have public or overly permissive access that could lead to data exposure"
            })
        
        if high_findings:
            recommendations.append({
                "Category": f"{resource_type} Access",
                "Priority": "High",
                "Recommendation": f"Review and remediate {len(high_findings)} high severity external access findings for {resource_type}",
                "Rationale": "These resources have external access that should be reviewed for least privilege"
            })
    
    # Add general recommendations
    if all_findings:
        recommendations.append({
            "Category": "Process",
            "Priority": "Medium",
            "Recommendation": "Implement regular review of Access Analyzer findings",
            "Rationale": "Regular reviews help maintain least privilege and prevent unintended access"
        })
    
    return recommendations

def export_to_csv(data, filename):
    """Export data to CSV file"""
    if not data:
        print(f"[WARNING] No data to export to {filename}")
        return
    
    # Get all possible fieldnames from all records
    fieldnames = set()
    for record in data:
        fieldnames.update(record.keys())
    fieldnames = sorted(list(fieldnames))
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    
    print(f"[INFO] Exported {len(data)} records to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Analyze IAM Access Analyzer findings")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--regions", nargs="+", help="AWS regions to analyze")
    parser.add_argument("--findings-output", default="access_analyzer_findings.csv", help="Findings output CSV file")
    parser.add_argument("--recommendations-output", default="access_analyzer_recommendations.csv", help="Recommendations output CSV file")
    parser.add_argument("--status-output", default="access_analyzer_status.csv", help="Status output CSV file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting IAM Access Analyzer analysis...")
    
    # Analyze Access Analyzer
    results = analyze_access_analyzer(args.profile, args.regions)
    
    # Extract findings, status, and generate recommendations
    all_findings = []
    all_status = []
    
    for result in results:
        all_findings.extend(result["Findings"])
        all_status.append(result["Status"])
    
    recommendations = generate_recommendations(results)
    
    # Export results
    if all_findings:
        export_to_csv(all_findings, args.findings_output)
    
    if all_status:
        export_to_csv(all_status, args.status_output)
    
    if recommendations:
        export_to_csv(recommendations, args.recommendations_output)
    
    # Print summary
    print("\n=== IAM Access Analyzer Summary ===")
    print(f"Regions analyzed: {len(results)}")
    print(f"Regions with Access Analyzer enabled: {len([r for r in results if r['Status']['Status'] == 'Enabled'])}")
    print(f"Total findings: {len(all_findings)}")
    
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in all_findings:
        severity = finding.get("Severity")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"{severity} findings: {count}")
    
    print("\n=== Recommendations ===")
    for recommendation in recommendations:
        print(f"[{recommendation['Priority']}] {recommendation['Category']}: {recommendation['Recommendation']}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()