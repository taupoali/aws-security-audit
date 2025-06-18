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

def check_cloudtrail_trails(region, profile=None):
    """Check CloudTrail trails in a region"""
    findings = []
    
    # Get trails in the region
    cmd = ["aws", "cloudtrail", "describe-trails", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    if not result:
        findings.append({
            "Service": "CloudTrail",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Error",
            "Issue": "Failed to retrieve CloudTrail trails",
            "Recommendation": "Ensure you have permissions to view CloudTrail trails"
        })
        return findings
    
    trails = json.loads(result).get("trailList", [])
    if not trails:
        findings.append({
            "Service": "CloudTrail",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Warning",
            "Issue": "No CloudTrail trails found in region",
            "Recommendation": "Consider setting up CloudTrail for comprehensive logging"
        })
        return findings
    
    # Check each trail
    for trail in trails:
        trail_name = trail.get("Name")
        trail_arn = trail.get("TrailARN")
        
        # Get trail status
        status_cmd = ["aws", "cloudtrail", "get-trail-status", "--name", trail_arn, "--region", region, "--output", "json"]
        status_result = run_aws_command(status_cmd, profile, region)
        
        if not status_result:
            findings.append({
                "Service": "CloudTrail",
                "Region": region,
                "ResourceId": trail_name,
                "Status": "Error",
                "Issue": "Failed to retrieve trail status",
                "Recommendation": "Check permissions and trail configuration"
            })
            continue
        
        status = json.loads(status_result)
        is_logging = status.get("IsLogging", False)
        
        # Check trail configuration
        issues = []
        recommendations = []
        
        if not is_logging:
            issues.append("Trail is not currently logging")
            recommendations.append("Enable logging for the trail")
        
        if not trail.get("IsMultiRegionTrail"):
            issues.append("Trail is not multi-region")
            recommendations.append("Consider using multi-region trails for comprehensive coverage")
        
        if not trail.get("LogFileValidationEnabled"):
            issues.append("Log file validation is not enabled")
            recommendations.append("Enable log file validation to ensure integrity")
        
        if not trail.get("KmsKeyId"):
            issues.append("Trail logs are not encrypted with KMS")
            recommendations.append("Enable KMS encryption for trail logs")
        
        if not trail.get("IncludeGlobalServiceEvents"):
            issues.append("Global service events are not included")
            recommendations.append("Include global service events for comprehensive logging")
        
        # Add finding
        if issues:
            findings.append({
                "Service": "CloudTrail",
                "Region": region,
                "ResourceId": trail_name,
                "Status": "Warning" if is_logging else "Critical",
                "Issue": "; ".join(issues),
                "Recommendation": "; ".join(recommendations)
            })
        else:
            findings.append({
                "Service": "CloudTrail",
                "Region": region,
                "ResourceId": trail_name,
                "Status": "Good",
                "Issue": "No issues found",
                "Recommendation": "Trail configuration follows best practices"
            })
    
    return findings

def check_cloudwatch_logs(region, profile=None):
    """Check CloudWatch Logs configuration"""
    findings = []
    
    # Get log groups
    cmd = ["aws", "logs", "describe-log-groups", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    if not result:
        findings.append({
            "Service": "CloudWatch Logs",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Error",
            "Issue": "Failed to retrieve CloudWatch log groups",
            "Recommendation": "Ensure you have permissions to view CloudWatch Logs"
        })
        return findings
    
    log_groups = json.loads(result).get("logGroups", [])
    if not log_groups:
        findings.append({
            "Service": "CloudWatch Logs",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Warning",
            "Issue": "No CloudWatch log groups found in region",
            "Recommendation": "Consider setting up CloudWatch Logs for service monitoring"
        })
        return findings
    
    # Check retention policies
    for log_group in log_groups:
        log_group_name = log_group.get("logGroupName")
        retention_days = log_group.get("retentionInDays")
        
        if not retention_days:
            findings.append({
                "Service": "CloudWatch Logs",
                "Region": region,
                "ResourceId": log_group_name,
                "Status": "Warning",
                "Issue": "No retention policy set (logs never expire)",
                "Recommendation": "Set appropriate retention policy based on compliance requirements"
            })
        elif retention_days < 90:
            findings.append({
                "Service": "CloudWatch Logs",
                "Region": region,
                "ResourceId": log_group_name,
                "Status": "Info",
                "Issue": f"Short retention period ({retention_days} days)",
                "Recommendation": "Consider longer retention for security and compliance"
            })
    
    return findings

def check_config_service(region, profile=None):
    """Check AWS Config service configuration"""
    findings = []
    
    # Check if Config is enabled
    cmd = ["aws", "configservice", "describe-configuration-recorders", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if not result:
        findings.append({
            "Service": "AWS Config",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Error",
            "Issue": "Failed to retrieve AWS Config recorders",
            "Recommendation": "Ensure you have permissions to view AWS Config"
        })
        return findings
    
    recorders = json.loads(result).get("ConfigurationRecorders", [])
    if not recorders:
        findings.append({
            "Service": "AWS Config",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Critical",
            "Issue": "AWS Config is not enabled in this region",
            "Recommendation": "Enable AWS Config for resource configuration tracking"
        })
        return findings
    
    # Check recorder status
    for recorder in recorders:
        recorder_name = recorder.get("name")
        
        # Check if recorder is recording
        status_cmd = ["aws", "configservice", "describe-configuration-recorder-status", "--configuration-recorder-names", recorder_name, "--region", region, "--output", "json"]
        status_result = run_aws_command(status_cmd, profile, region)
        
        if not status_result:
            findings.append({
                "Service": "AWS Config",
                "Region": region,
                "ResourceId": recorder_name,
                "Status": "Error",
                "Issue": "Failed to retrieve recorder status",
                "Recommendation": "Check permissions and recorder configuration"
            })
            continue
        
        status = json.loads(status_result).get("ConfigurationRecordersStatus", [])
        if not status:
            findings.append({
                "Service": "AWS Config",
                "Region": region,
                "ResourceId": recorder_name,
                "Status": "Critical",
                "Issue": "Recorder status not available",
                "Recommendation": "Check AWS Config configuration"
            })
            continue
        
        is_recording = status[0].get("recording", False)
        last_status = status[0].get("lastStatus", "")
        
        if not is_recording:
            findings.append({
                "Service": "AWS Config",
                "Region": region,
                "ResourceId": recorder_name,
                "Status": "Critical",
                "Issue": "AWS Config recorder is not recording",
                "Recommendation": "Start the AWS Config recorder"
            })
        elif last_status != "SUCCESS":
            findings.append({
                "Service": "AWS Config",
                "Region": region,
                "ResourceId": recorder_name,
                "Status": "Warning",
                "Issue": f"Last recording status: {last_status}",
                "Recommendation": "Check AWS Config recorder for errors"
            })
        else:
            # Check recorder configuration
            all_resource_types = recorder.get("recordingGroup", {}).get("allSupported", False)
            include_global = recorder.get("recordingGroup", {}).get("includeGlobalResourceTypes", False)
            
            issues = []
            recommendations = []
            
            if not all_resource_types:
                issues.append("Not recording all resource types")
                recommendations.append("Configure recorder to capture all supported resource types")
            
            if not include_global:
                issues.append("Global resource types not included")
                recommendations.append("Include global resource types in recording")
            
            if issues:
                findings.append({
                    "Service": "AWS Config",
                    "Region": region,
                    "ResourceId": recorder_name,
                    "Status": "Warning",
                    "Issue": "; ".join(issues),
                    "Recommendation": "; ".join(recommendations)
                })
            else:
                findings.append({
                    "Service": "AWS Config",
                    "Region": region,
                    "ResourceId": recorder_name,
                    "Status": "Good",
                    "Issue": "No issues found",
                    "Recommendation": "Config recorder follows best practices"
                })
    
    return findings

def check_vpc_flow_logs(region, profile=None):
    """Check VPC Flow Logs configuration"""
    findings = []
    
    # Get VPCs
    cmd = ["aws", "ec2", "describe-vpcs", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    if not result:
        findings.append({
            "Service": "VPC Flow Logs",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Error",
            "Issue": "Failed to retrieve VPCs",
            "Recommendation": "Ensure you have permissions to view VPCs"
        })
        return findings
    
    vpcs = json.loads(result).get("Vpcs", [])
    if not vpcs:
        return findings  # No VPCs, no findings needed
    
    # Check flow logs for each VPC
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")
        
        # Get flow logs for this VPC
        flow_cmd = ["aws", "ec2", "describe-flow-logs", "--filter", f"Name=resource-id,Values={vpc_id}", "--region", region, "--output", "json"]
        flow_result = run_aws_command(flow_cmd, profile, region)
        
        if not flow_result:
            findings.append({
                "Service": "VPC Flow Logs",
                "Region": region,
                "ResourceId": vpc_id,
                "Status": "Error",
                "Issue": "Failed to retrieve flow logs",
                "Recommendation": "Check permissions for VPC Flow Logs"
            })
            continue
        
        flow_logs = json.loads(flow_result).get("FlowLogs", [])
        if not flow_logs:
            findings.append({
                "Service": "VPC Flow Logs",
                "Region": region,
                "ResourceId": vpc_id,
                "Status": "Critical",
                "Issue": "VPC Flow Logs not enabled",
                "Recommendation": "Enable VPC Flow Logs for network traffic visibility"
            })
        else:
            # Check flow log configuration
            for flow_log in flow_logs:
                log_status = flow_log.get("FlowLogStatus")
                traffic_type = flow_log.get("TrafficType")
                
                if log_status != "ACTIVE":
                    findings.append({
                        "Service": "VPC Flow Logs",
                        "Region": region,
                        "ResourceId": vpc_id,
                        "Status": "Warning",
                        "Issue": f"Flow log status: {log_status}",
                        "Recommendation": "Check flow log configuration"
                    })
                elif traffic_type != "ALL":
                    findings.append({
                        "Service": "VPC Flow Logs",
                        "Region": region,
                        "ResourceId": vpc_id,
                        "Status": "Info",
                        "Issue": f"Only logging {traffic_type} traffic",
                        "Recommendation": "Consider logging ALL traffic for comprehensive visibility"
                    })
                else:
                    findings.append({
                        "Service": "VPC Flow Logs",
                        "Region": region,
                        "ResourceId": vpc_id,
                        "Status": "Good",
                        "Issue": "No issues found",
                        "Recommendation": "Flow logs configuration follows best practices"
                    })
    
    return findings

def check_region_logging(region, profile=None):
    """Check logging configuration in a region"""
    print(f"[INFO] Checking logging in region: {region}")
    
    findings = []
    findings.extend(check_cloudtrail_trails(region, profile))
    findings.extend(check_cloudwatch_logs(region, profile))
    findings.extend(check_config_service(region, profile))
    findings.extend(check_vpc_flow_logs(region, profile))
    
    return findings

def analyze_logging_practices(profile=None, regions=None):
    """Analyze logging practices across regions"""
    if not regions:
        regions = get_regions(profile)
    
    print(f"[INFO] Analyzing logging practices across {len(regions)} regions")
    
    all_findings = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_region = {executor.submit(check_region_logging, region, profile): region for region in regions}
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
                print(f"[INFO] Completed logging analysis for region: {region}")
            except Exception as e:
                print(f"[ERROR] Error analyzing region {region}: {e}")
    
    return all_findings

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
    parser = argparse.ArgumentParser(description="Analyze AWS logging practices")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--regions", nargs="+", help="AWS regions to analyze")
    parser.add_argument("--output", default="logging_findings.csv", help="Output CSV file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting logging analysis...")
    
    # Analyze logging practices
    findings = analyze_logging_practices(args.profile, args.regions)
    
    # Export findings
    export_to_csv(findings, args.output)
    
    # Print summary
    status_counts = {"Good": 0, "Info": 0, "Warning": 0, "Critical": 0, "Error": 0}
    for finding in findings:
        status = finding.get("Status")
        if status in status_counts:
            status_counts[status] += 1
    
    print("\n=== Logging Analysis Summary ===")
    print(f"Total findings: {len(findings)}")
    for status, count in status_counts.items():
        print(f"{status} findings: {count}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()