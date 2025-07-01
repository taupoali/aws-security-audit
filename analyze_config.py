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
                delay = 1 * (2 ** attempt)
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

def check_config_service_status(region, profile=None):
    """Check AWS Config service status in a region"""
    findings = []
    
    # Check configuration recorders
    cmd = ["aws", "configservice", "describe-configuration-recorders", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        findings.append({
            "Region": region,
            "Component": "Configuration Recorder",
            "Status": "Error",
            "Name": "N/A",
            "Details": "Failed to retrieve configuration recorders"
        })
        return findings
    
    recorders = json.loads(result).get("ConfigurationRecorders", [])
    if not recorders:
        findings.append({
            "Region": region,
            "Component": "Configuration Recorder",
            "Status": "Not Configured",
            "Name": "N/A",
            "Details": "No configuration recorders found"
        })
    else:
        for recorder in recorders:
            name = recorder.get("name", "Unknown")
            role_arn = recorder.get("roleARN", "N/A")
            
            # Check if recorder is recording
            status_cmd = ["aws", "configservice", "describe-configuration-recorder-status", "--configuration-recorder-names", name, "--region", region, "--output", "json"]
            status_result = run_aws_command(status_cmd, profile, region)
            
            recording = False
            last_status = "Unknown"
            if status_result:
                status_data = json.loads(status_result).get("ConfigurationRecordersStatus", [])
                if status_data:
                    recording = status_data[0].get("recording", False)
                    last_status = status_data[0].get("lastStatus", "Unknown")
            
            findings.append({
                "Region": region,
                "Component": "Configuration Recorder",
                "Status": "Recording" if recording else "Not Recording",
                "Name": name,
                "Details": f"Role: {role_arn}, Last Status: {last_status}"
            })
    
    # Check delivery channels
    cmd = ["aws", "configservice", "describe-delivery-channels", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if result:
        channels = json.loads(result).get("DeliveryChannels", [])
        if not channels:
            findings.append({
                "Region": region,
                "Component": "Delivery Channel",
                "Status": "Not Configured",
                "Name": "N/A",
                "Details": "No delivery channels found"
            })
        else:
            for channel in channels:
                name = channel.get("name", "Unknown")
                s3_bucket = channel.get("s3BucketName", "N/A")
                
                # Check delivery channel status
                status_cmd = ["aws", "configservice", "describe-delivery-channel-status", "--delivery-channel-names", name, "--region", region, "--output", "json"]
                status_result = run_aws_command(status_cmd, profile, region)
                
                last_delivery_time = "Unknown"
                if status_result:
                    status_data = json.loads(status_result).get("DeliveryChannelsStatus", [])
                    if status_data:
                        last_delivery_time = status_data[0].get("lastSuccessfulDeliveryTime", "Unknown")
                
                findings.append({
                    "Region": region,
                    "Component": "Delivery Channel",
                    "Status": "Configured",
                    "Name": name,
                    "Details": f"S3 Bucket: {s3_bucket}, Last Delivery: {last_delivery_time}"
                })
    
    return findings

def get_config_rules(region, profile=None):
    """Get AWS Config rules in a region"""
    findings = []
    
    cmd = ["aws", "configservice", "describe-config-rules", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        findings.append({
            "Region": region,
            "RuleName": "N/A",
            "RuleType": "Error",
            "Source": "N/A",
            "ComplianceStatus": "Error",
            "Description": "Failed to retrieve Config rules"
        })
        return findings
    
    rules = json.loads(result).get("ConfigRules", [])
    if not rules:
        findings.append({
            "Region": region,
            "RuleName": "N/A",
            "RuleType": "None",
            "Source": "N/A",
            "ComplianceStatus": "N/A",
            "Description": "No Config rules found in this region"
        })
        return findings
    
    # Get compliance status for all rules
    compliance_cmd = ["aws", "configservice", "describe-compliance-by-config-rule", "--region", region, "--output", "json"]
    compliance_result = run_aws_command(compliance_cmd, profile, region)
    
    compliance_data = {}
    if compliance_result:
        compliance_info = json.loads(compliance_result).get("ComplianceByConfigRules", [])
        for item in compliance_info:
            rule_name = item.get("ConfigRuleName")
            compliance = item.get("Compliance", {})
            compliance_data[rule_name] = compliance.get("ComplianceType", "Unknown")
    
    for rule in rules:
        rule_name = rule.get("ConfigRuleName", "Unknown")
        source = rule.get("Source", {})
        source_identifier = source.get("SourceIdentifier", "Unknown")
        owner = source.get("Owner", "Unknown")
        description = rule.get("Description", "No description")
        
        # Determine rule type
        rule_type = "Custom"
        if owner == "AWS":
            rule_type = "AWS Managed"
        elif "SERVICE_LINKED" in owner:
            rule_type = "Service Linked"
        
        compliance_status = compliance_data.get(rule_name, "Unknown")
        
        findings.append({
            "Region": region,
            "RuleName": rule_name,
            "RuleType": rule_type,
            "Source": source_identifier,
            "ComplianceStatus": compliance_status,
            "Description": description
        })
    
    return findings

def get_conformance_packs(region, profile=None):
    """Get AWS Config conformance packs in a region"""
    findings = []
    
    cmd = ["aws", "configservice", "describe-conformance-packs", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        findings.append({
            "Region": region,
            "PackName": "N/A",
            "PackStatus": "Error",
            "ComplianceStatus": "Error",
            "RuleCount": 0,
            "Details": "Failed to retrieve conformance packs"
        })
        return findings
    
    packs = json.loads(result).get("ConformancePackDetails", [])
    if not packs:
        findings.append({
            "Region": region,
            "PackName": "N/A",
            "PackStatus": "None",
            "ComplianceStatus": "N/A",
            "RuleCount": 0,
            "Details": "No conformance packs found in this region"
        })
        return findings
    
    for pack in packs:
        pack_name = pack.get("ConformancePackName", "Unknown")
        pack_arn = pack.get("ConformancePackArn", "N/A")
        pack_status = pack.get("ConformancePackState", "Unknown")
        
        # Get compliance status for the pack
        compliance_cmd = ["aws", "configservice", "describe-conformance-pack-compliance", "--conformance-pack-name", pack_name, "--region", region, "--output", "json"]
        compliance_result = run_aws_command(compliance_cmd, profile, region)
        
        compliant_rules = 0
        non_compliant_rules = 0
        total_rules = 0
        
        if compliance_result:
            compliance_info = json.loads(compliance_result).get("ConformancePackRuleComplianceList", [])
            total_rules = len(compliance_info)
            for rule_compliance in compliance_info:
                compliance_type = rule_compliance.get("ComplianceType", "Unknown")
                if compliance_type == "COMPLIANT":
                    compliant_rules += 1
                elif compliance_type == "NON_COMPLIANT":
                    non_compliant_rules += 1
        
        compliance_status = "Unknown"
        if total_rules > 0:
            if non_compliant_rules == 0:
                compliance_status = "Compliant"
            elif compliant_rules == 0:
                compliance_status = "Non-Compliant"
            else:
                compliance_status = f"Partially Compliant ({compliant_rules}/{total_rules})"
        
        findings.append({
            "Region": region,
            "PackName": pack_name,
            "PackStatus": pack_status,
            "ComplianceStatus": compliance_status,
            "RuleCount": total_rules,
            "Details": f"Compliant: {compliant_rules}, Non-Compliant: {non_compliant_rules}"
        })
    
    return findings

def get_compliance_summary(region, profile=None):
    """Get overall compliance summary for a region"""
    findings = []
    
    # Get compliance summary by resource type
    cmd = ["aws", "configservice", "get-compliance-summary-by-resource-type", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        findings.append({
            "Region": region,
            "ResourceType": "N/A",
            "CompliantResources": 0,
            "NonCompliantResources": 0,
            "TotalResources": 0,
            "CompliancePercentage": 0
        })
        return findings
    
    summary = json.loads(result).get("ComplianceSummariesByResourceType", [])
    if not summary:
        findings.append({
            "Region": region,
            "ResourceType": "No Data",
            "CompliantResources": 0,
            "NonCompliantResources": 0,
            "TotalResources": 0,
            "CompliancePercentage": 0
        })
        return findings
    
    for item in summary:
        resource_type = item.get("ResourceType", "Unknown")
        compliance_summary = item.get("ComplianceSummary", {})
        
        compliant = compliance_summary.get("CompliantResourceCount", {}).get("CappedCount", 0)
        non_compliant = compliance_summary.get("NonCompliantResourceCount", {}).get("CappedCount", 0)
        total = compliant + non_compliant
        
        percentage = (compliant / total * 100) if total > 0 else 0
        
        findings.append({
            "Region": region,
            "ResourceType": resource_type,
            "CompliantResources": compliant,
            "NonCompliantResources": non_compliant,
            "TotalResources": total,
            "CompliancePercentage": round(percentage, 2)
        })
    
    return findings

def analyze_region_config(region, profile=None):
    """Analyze AWS Config in a single region"""
    print(f"[INFO] Analyzing AWS Config in region: {region}")
    
    results = {
        "service_status": check_config_service_status(region, profile),
        "config_rules": get_config_rules(region, profile),
        "conformance_packs": get_conformance_packs(region, profile),
        "compliance_summary": get_compliance_summary(region, profile)
    }
    
    return results

def analyze_config_across_regions(profile=None, regions=None):
    """Analyze AWS Config across multiple regions"""
    if not regions:
        regions = get_regions(profile)
    
    print(f"[INFO] Analyzing AWS Config across {len(regions)} regions")
    
    all_results = {
        "service_status": [],
        "config_rules": [],
        "conformance_packs": [],
        "compliance_summary": []
    }
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_region = {executor.submit(analyze_region_config, region, profile): region for region in regions}
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                for key in all_results:
                    all_results[key].extend(result[key])
                print(f"[INFO] Completed Config analysis for region: {region}")
            except Exception as e:
                print(f"[ERROR] Error analyzing region {region}: {e}")
    
    return all_results

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

def generate_summary_report(results):
    """Generate a summary report of AWS Config analysis"""
    report = []
    
    # Service Status Summary
    report.append("=== AWS Config Service Status Summary ===")
    regions_with_config = set()
    regions_recording = set()
    
    for status in results["service_status"]:
        region = status["Region"]
        component = status["Component"]
        status_value = status["Status"]
        
        if component == "Configuration Recorder":
            if status_value not in ["Error", "Not Configured"]:
                regions_with_config.add(region)
            if status_value == "Recording":
                regions_recording.add(region)
    
    report.append(f"Regions with Config enabled: {len(regions_with_config)}")
    report.append(f"Regions actively recording: {len(regions_recording)}")
    
    # Rules Summary
    report.append("\n=== Config Rules Summary ===")
    total_rules = len([r for r in results["config_rules"] if r["RuleName"] != "N/A"])
    aws_managed_rules = len([r for r in results["config_rules"] if r["RuleType"] == "AWS Managed"])
    custom_rules = len([r for r in results["config_rules"] if r["RuleType"] == "Custom"])
    
    report.append(f"Total Config rules: {total_rules}")
    report.append(f"AWS Managed rules: {aws_managed_rules}")
    report.append(f"Custom rules: {custom_rules}")
    
    # Conformance Packs Summary
    report.append("\n=== Conformance Packs Summary ===")
    total_packs = len([p for p in results["conformance_packs"] if p["PackName"] != "N/A"])
    active_packs = len([p for p in results["conformance_packs"] if p["PackStatus"] == "CREATE_COMPLETE"])
    
    report.append(f"Total conformance packs: {total_packs}")
    report.append(f"Active conformance packs: {active_packs}")
    
    # Compliance Summary
    report.append("\n=== Overall Compliance Summary ===")
    total_compliant = sum([c["CompliantResources"] for c in results["compliance_summary"]])
    total_non_compliant = sum([c["NonCompliantResources"] for c in results["compliance_summary"]])
    total_resources = total_compliant + total_non_compliant
    
    if total_resources > 0:
        overall_compliance = (total_compliant / total_resources) * 100
        report.append(f"Overall compliance rate: {overall_compliance:.2f}%")
        report.append(f"Compliant resources: {total_compliant}")
        report.append(f"Non-compliant resources: {total_non_compliant}")
    else:
        report.append("No compliance data available")
    
    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Analyze AWS Config service, rules, and compliance")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--regions", nargs="+", help="AWS regions to analyze")
    parser.add_argument("--service-status", default="config_service_status.csv", help="Service status output CSV file")
    parser.add_argument("--rules-output", default="config_rules.csv", help="Config rules output CSV file")
    parser.add_argument("--packs-output", default="conformance_packs.csv", help="Conformance packs output CSV file")
    parser.add_argument("--compliance-output", default="compliance_summary.csv", help="Compliance summary output CSV file")
    parser.add_argument("--summary-report", default="config_analysis_summary.txt", help="Summary report file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting AWS Config analysis...")
    if args.profile:
        print(f"Using AWS profile: {args.profile}")
    
    # Analyze AWS Config
    results = analyze_config_across_regions(args.profile, args.regions)
    
    # Export results to CSV
    export_to_csv(results["service_status"], args.service_status)
    export_to_csv(results["config_rules"], args.rules_output)
    export_to_csv(results["conformance_packs"], args.packs_output)
    export_to_csv(results["compliance_summary"], args.compliance_output)
    
    # Generate and save summary report
    summary_report = generate_summary_report(results)
    with open(args.summary_report, 'w') as f:
        f.write(summary_report)
    
    print(f"\nSummary report written to: {args.summary_report}")
    print("\n" + summary_report)
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")
    
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