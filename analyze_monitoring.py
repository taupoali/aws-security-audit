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

def check_cloudwatch_alarms(region, profile=None):
    """Check CloudWatch alarms in a region"""
    findings = []
    
    # Get all alarms
    cmd = ["aws", "cloudwatch", "describe-alarms", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    if not result:
        findings.append({
            "Service": "CloudWatch Alarms",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Error",
            "Issue": "Failed to retrieve CloudWatch alarms",
            "Recommendation": "Ensure you have permissions to view CloudWatch alarms",
            "AlarmCount": 0,
            "AlarmsByNamespace": "{}",
            "AlarmsInAlarmState": 0
        })
        return findings
    
    alarms = json.loads(result).get("MetricAlarms", [])
    composite_alarms = json.loads(result).get("CompositeAlarms", [])
    
    if not alarms and not composite_alarms:
        findings.append({
            "Service": "CloudWatch Alarms",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Critical",
            "Issue": "No CloudWatch alarms found in region",
            "Recommendation": "Set up CloudWatch alarms for critical resources and metrics",
            "AlarmCount": 0,
            "AlarmsByNamespace": "{}",
            "AlarmsInAlarmState": 0
        })
        return findings
    
    # Track alarm statistics
    alarm_count = len(alarms) + len(composite_alarms)
    alarms_by_namespace = {}
    alarms_in_alarm_state = 0
    alarms_with_no_actions = 0
    
    # Check metric alarms
    for alarm in alarms:
        alarm_name = alarm.get("AlarmName")
        alarm_actions = alarm.get("AlarmActions", [])
        ok_actions = alarm.get("OKActions", [])
        insufficient_data_actions = alarm.get("InsufficientDataActions", [])
        state = alarm.get("StateValue")
        namespace = alarm.get("Namespace", "Unknown")
        
        # Track namespace statistics
        if namespace not in alarms_by_namespace:
            alarms_by_namespace[namespace] = 0
        alarms_by_namespace[namespace] += 1
        
        # Track alarm state
        if state == "ALARM":
            alarms_in_alarm_state += 1
        
        # Track alarms with no actions
        if not alarm_actions:
            alarms_with_no_actions += 1
        
        issues = []
        recommendations = []
        
        # Check if alarm has actions
        if not alarm_actions:
            issues.append("No alarm actions configured")
            recommendations.append("Configure actions to be taken when alarm state changes")
        
        # Check if alarm is in ALARM state
        if state == "ALARM":
            issues.append("Alarm is currently in ALARM state")
            recommendations.append("Investigate the cause of the alarm")
        
        # Check if alarm is in INSUFFICIENT_DATA state
        if state == "INSUFFICIENT_DATA":
            issues.append("Alarm is in INSUFFICIENT_DATA state")
            recommendations.append("Check metric data availability")
        
        # Add finding for problematic alarms
        if issues:
            findings.append({
                "Service": "CloudWatch Alarms",
                "Region": region,
                "ResourceId": alarm_name,
                "Status": "Warning" if state != "ALARM" else "Critical",
                "Issue": "; ".join(issues),
                "Recommendation": "; ".join(recommendations),
                "AlarmCount": 1,
                "AlarmsByNamespace": f"{{{namespace}: 1}}",
                "AlarmsInAlarmState": 1 if state == "ALARM" else 0
            })
    
    # Check if there are alarms for critical services
    critical_namespaces = ["AWS/EC2", "AWS/RDS", "AWS/Lambda", "AWS/ApiGateway", "AWS/ELB", "AWS/ApplicationELB", "AWS/NetworkELB"]
    covered_namespaces = set(alarm.get("Namespace") for alarm in alarms if alarm.get("Namespace"))
    
    for namespace in critical_namespaces:
        if namespace not in covered_namespaces:
            findings.append({
                "Service": "CloudWatch Alarms",
                "Region": region,
                "ResourceId": namespace,
                "Status": "Warning",
                "Issue": f"No alarms found for {namespace}",
                "Recommendation": f"Consider setting up alarms for critical {namespace} metrics",
                "AlarmCount": 0,
                "AlarmsByNamespace": f"{{{namespace}: 0}}",
                "AlarmsInAlarmState": 0
            })
    
    # Add a summary finding for the region
    findings.append({
        "Service": "CloudWatch Alarms",
        "Region": region,
        "ResourceId": "Summary",
        "Status": "Good" if alarm_count > 0 and alarms_in_alarm_state == 0 and alarms_with_no_actions == 0 else "Info",
        "Issue": f"Region has {alarm_count} alarms ({alarms_in_alarm_state} in ALARM state, {alarms_with_no_actions} with no actions)",
        "Recommendation": "Review alarms in ALARM state and ensure all alarms have actions configured",
        "AlarmCount": alarm_count,
        "AlarmsByNamespace": json.dumps(alarms_by_namespace),
        "AlarmsInAlarmState": alarms_in_alarm_state
    })
    
    return findings

def check_guardduty(region, profile=None):
    """Check GuardDuty configuration in a region"""
    findings = []
    
    # Check if GuardDuty is enabled
    cmd = ["aws", "guardduty", "list-detectors", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    if not result:
        findings.append({
            "Service": "GuardDuty",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Error",
            "Issue": "Failed to retrieve GuardDuty detectors",
            "Recommendation": "Ensure you have permissions to view GuardDuty"
        })
        return findings
    
    detectors = json.loads(result).get("DetectorIds", [])
    if not detectors:
        findings.append({
            "Service": "GuardDuty",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Critical",
            "Issue": "GuardDuty is not enabled in this region",
            "Recommendation": "Enable GuardDuty for threat detection"
        })
        return findings
    
    # Check each detector
    for detector_id in detectors:
        # Get detector details
        detector_cmd = ["aws", "guardduty", "get-detector", "--detector-id", detector_id, "--region", region, "--output", "json"]
        detector_result = run_aws_command(detector_cmd, profile, region)
        
        if not detector_result:
            findings.append({
                "Service": "GuardDuty",
                "Region": region,
                "ResourceId": detector_id,
                "Status": "Error",
                "Issue": "Failed to retrieve detector details",
                "Recommendation": "Check permissions for GuardDuty"
            })
            continue
        
        detector = json.loads(detector_result)
        status = detector.get("Status")
        
        if status != "ENABLED":
            findings.append({
                "Service": "GuardDuty",
                "Region": region,
                "ResourceId": detector_id,
                "Status": "Critical",
                "Issue": f"GuardDuty detector status: {status}",
                "Recommendation": "Enable the GuardDuty detector"
            })
            continue
        
        # Check data sources
        data_sources = detector.get("DataSources", {})
        issues = []
        recommendations = []
        
        # Check S3 logs
        s3_logs = data_sources.get("S3Logs", {}).get("Status", "DISABLED")
        if s3_logs != "ENABLED":
            issues.append("S3 logs data source is not enabled")
            recommendations.append("Enable S3 logs data source for better threat detection")
        
        # Check Kubernetes audit logs
        k8s_logs = data_sources.get("Kubernetes", {}).get("AuditLogs", {}).get("Status", "DISABLED")
        if k8s_logs != "ENABLED":
            issues.append("Kubernetes audit logs data source is not enabled")
            recommendations.append("Enable Kubernetes audit logs if you use EKS")
        
        # Check finding publishing frequency
        frequency = detector.get("FindingPublishingFrequency")
        if frequency != "FIFTEEN_MINUTES":
            issues.append(f"Finding publishing frequency is {frequency}")
            recommendations.append("Consider setting frequency to FIFTEEN_MINUTES for faster detection")
        
        # Check if findings are being exported to CloudWatch Events
        event_cmd = ["aws", "guardduty", "list-publishing-destinations", "--detector-id", detector_id, "--region", region, "--output", "json"]
        event_result = run_aws_command(event_cmd, profile, region)
        
        if event_result:
            destinations = json.loads(event_result).get("Destinations", [])
            if not destinations:
                issues.append("No publishing destinations configured")
                recommendations.append("Configure publishing to CloudWatch Events for automated response")
        
        # Add finding
        if issues:
            findings.append({
                "Service": "GuardDuty",
                "Region": region,
                "ResourceId": detector_id,
                "Status": "Warning",
                "Issue": "; ".join(issues),
                "Recommendation": "; ".join(recommendations)
            })
        else:
            findings.append({
                "Service": "GuardDuty",
                "Region": region,
                "ResourceId": detector_id,
                "Status": "Good",
                "Issue": "No issues found",
                "Recommendation": "GuardDuty configuration follows best practices"
            })
    
    return findings

def check_security_hub(region, profile=None):
    """Check Security Hub configuration in a region"""
    findings = []
    
    # Check if Security Hub is enabled
    cmd = ["aws", "securityhub", "get-enabled-standards", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    
    if result is None:
        # Try another command to confirm if Security Hub is enabled
        hub_cmd = ["aws", "securityhub", "describe-hub", "--region", region, "--output", "json"]
        hub_result = run_aws_command(hub_cmd, profile, region)
        
        if hub_result is None:
            findings.append({
                "Service": "Security Hub",
                "Region": region,
                "ResourceId": "N/A",
                "Status": "Critical",
                "Issue": "Security Hub is not enabled in this region",
                "Recommendation": "Enable Security Hub for security standards compliance"
            })
            return findings
    
    # Check enabled standards
    standards = []
    if result:
        standards = json.loads(result).get("StandardsSubscriptions", [])
    
    if not standards:
        findings.append({
            "Service": "Security Hub",
            "Region": region,
            "ResourceId": "N/A",
            "Status": "Warning",
            "Issue": "No security standards enabled in Security Hub",
            "Recommendation": "Enable security standards (CIS, AWS Foundational, PCI DSS)"
        })
    else:
        # Check which standards are enabled
        enabled_standards = set()
        for standard in standards:
            standard_name = standard.get("StandardsArn", "").split("/")[-1]
            enabled_standards.add(standard_name)
        
        # Check for common standards
        common_standards = {
            "aws-foundational-security-best-practices": "AWS Foundational Security Best Practices",
            "cis-aws-foundations-benchmark": "CIS AWS Foundations Benchmark",
            "pci-dss": "PCI DSS"
        }
        
        for std_id, std_name in common_standards.items():
            if std_id not in enabled_standards:
                findings.append({
                    "Service": "Security Hub",
                    "Region": region,
                    "ResourceId": "Standards",
                    "Status": "Warning",
                    "Issue": f"{std_name} standard is not enabled",
                    "Recommendation": f"Enable {std_name} standard for comprehensive security checks"
                })
    
    # Check if findings are being sent to EventBridge
    event_cmd = ["aws", "securityhub", "list-finding-aggregators", "--region", region, "--output", "json"]
    event_result = run_aws_command(event_cmd, profile, region)
    
    if event_result:
        aggregators = json.loads(event_result).get("FindingAggregators", [])
        if not aggregators:
            findings.append({
                "Service": "Security Hub",
                "Region": region,
                "ResourceId": "Aggregation",
                "Status": "Warning",
                "Issue": "Finding aggregation not configured",
                "Recommendation": "Configure finding aggregation for centralized visibility"
            })
    
    return findings

def check_cloudtrail_alarms(region, profile=None):
    """Check if there are CloudWatch alarms for CloudTrail events"""
    findings = []
    
    # Get CloudWatch alarms
    cmd = ["aws", "cloudwatch", "describe-alarms", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile, region)
    if not result:
        return findings
    
    alarms = json.loads(result).get("MetricAlarms", [])
    
    # Check for CloudTrail-specific alarms
    cloudtrail_alarms = [a for a in alarms if "CloudTrail" in a.get("MetricName", "") or "CloudTrail" in a.get("Namespace", "")]
    
    if not cloudtrail_alarms:
        # Check for common CloudTrail filter patterns in Log Metric Filters
        metric_cmd = ["aws", "logs", "describe-metric-filters", "--region", region, "--output", "json"]
        metric_result = run_aws_command(metric_cmd, profile, region)
        
        cloudtrail_metrics = []
        if metric_result:
            filters = json.loads(metric_result).get("metricFilters", [])
            cloudtrail_metrics = [f for f in filters if "CloudTrail" in f.get("filterPattern", "")]
        
        if not cloudtrail_metrics:
            findings.append({
                "Service": "CloudTrail Monitoring",
                "Region": region,
                "ResourceId": "N/A",
                "Status": "Critical",
                "Issue": "No CloudWatch alarms for CloudTrail events",
                "Recommendation": "Create alarms for critical CloudTrail events (e.g., root account usage, IAM policy changes)"
            })
    
    # Check for specific security-related CloudTrail alarms
    security_patterns = [
        "ConsoleLogin", "Root", "IAMUser", "DeleteTrail", "UpdateTrail", 
        "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy", "AttachRolePolicy",
        "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
        "DisableAlarmActions", "StopLogging"
    ]
    
    found_patterns = set()
    for alarm in cloudtrail_alarms:
        for pattern in security_patterns:
            if pattern in json.dumps(alarm):
                found_patterns.add(pattern)
    
    for pattern in security_patterns:
        if pattern not in found_patterns:
            findings.append({
                "Service": "CloudTrail Monitoring",
                "Region": region,
                "ResourceId": pattern,
                "Status": "Warning",
                "Issue": f"No alarm for CloudTrail {pattern} events",
                "Recommendation": f"Create alarm for {pattern} events to detect potential security issues"
            })
    
    return findings

def check_region_monitoring(region, profile=None):
    """Check monitoring configuration in a region"""
    print(f"[INFO] Checking monitoring in region: {region}")
    
    findings = []
    findings.extend(check_cloudwatch_alarms(region, profile))
    findings.extend(check_guardduty(region, profile))
    findings.extend(check_security_hub(region, profile))
    findings.extend(check_cloudtrail_alarms(region, profile))
    
    return findings

def analyze_monitoring_tools(profile=None, regions=None):
    """Analyze monitoring tools across regions"""
    if not regions:
        regions = get_regions(profile)
    
    print(f"[INFO] Analyzing monitoring tools across {len(regions)} regions")
    
    all_findings = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_region = {executor.submit(check_region_monitoring, region, profile): region for region in regions}
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
                print(f"[INFO] Completed monitoring analysis for region: {region}")
            except Exception as e:
                print(f"[ERROR] Error analyzing region {region}: {e}")
    
    return all_findings

def generate_recommendations(findings):
    """Generate overall recommendations based on findings"""
    recommendations = []
    
    # Count issues by service, region, and severity
    services = {}
    regions_by_service = {}
    
    for finding in findings:
        service = finding.get("Service")
        status = finding.get("Status")
        region = finding.get("Region", "unknown")
        
        # Track service status counts
        if service not in services:
            services[service] = {"Critical": 0, "Warning": 0, "Info": 0, "Error": 0, "Good": 0}
        
        if status in services[service]:
            services[service][status] += 1
        
        # Track regions by service and status
        if service not in regions_by_service:
            regions_by_service[service] = {
                "Enabled": set(),
                "Disabled": set(),
                "Issues": set()
            }
        
        # Track where services are enabled/disabled/have issues
        if status == "Good":
            regions_by_service[service]["Enabled"].add(region)
        elif status == "Critical" and "not enabled" in finding.get("Issue", "").lower():
            regions_by_service[service]["Disabled"].add(region)
        elif status in ["Critical", "Warning"]:
            regions_by_service[service]["Issues"].add(region)
            # If we have issues but service is running, it's still enabled
            if "not enabled" not in finding.get("Issue", "").lower():
                regions_by_service[service]["Enabled"].add(region)
    
    # Generate recommendations for each service with region details
    for service, counts in services.items():
        enabled_regions = regions_by_service[service]["Enabled"]
        disabled_regions = regions_by_service[service]["Disabled"]
        issue_regions = regions_by_service[service]["Issues"]
        
        if service == "GuardDuty":
            if disabled_regions:
                recommendations.append({
                    "Service": service,
                    "Priority": "High",
                    "Recommendation": f"Enable GuardDuty in {len(disabled_regions)} regions: {', '.join(sorted(disabled_regions))}",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
            elif issue_regions:
                recommendations.append({
                    "Service": service,
                    "Priority": "Medium",
                    "Recommendation": f"Optimize GuardDuty configuration in {len(issue_regions)} regions: {', '.join(sorted(issue_regions))}",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
            else:
                recommendations.append({
                    "Service": service,
                    "Priority": "Low",
                    "Recommendation": f"GuardDuty is properly configured in all {len(enabled_regions)} checked regions",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
        
        elif service == "Security Hub":
            if disabled_regions:
                recommendations.append({
                    "Service": service,
                    "Priority": "High",
                    "Recommendation": f"Enable Security Hub in {len(disabled_regions)} regions: {', '.join(sorted(disabled_regions))}",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
            elif issue_regions:
                recommendations.append({
                    "Service": service,
                    "Priority": "Medium",
                    "Recommendation": f"Enable all security standards in {len(issue_regions)} regions: {', '.join(sorted(issue_regions))}",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
            else:
                recommendations.append({
                    "Service": service,
                    "Priority": "Low",
                    "Recommendation": f"Security Hub is properly configured in all {len(enabled_regions)} checked regions",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
        
        elif service == "CloudWatch Alarms":
            if disabled_regions or issue_regions:
                recommendations.append({
                    "Service": service,
                    "Priority": "High",
                    "Recommendation": f"Set up CloudWatch alarms for critical resources in {len(disabled_regions) + len(issue_regions)} regions with issues",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
            else:
                recommendations.append({
                    "Service": service,
                    "Priority": "Low",
                    "Recommendation": f"CloudWatch alarms are properly configured in all {len(enabled_regions)} checked regions",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
        
        elif service == "CloudTrail Monitoring":
            if disabled_regions or issue_regions:
                recommendations.append({
                    "Service": service,
                    "Priority": "High",
                    "Recommendation": f"Create alarms for critical CloudTrail events in {len(disabled_regions) + len(issue_regions)} regions with issues",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
            else:
                recommendations.append({
                    "Service": service,
                    "Priority": "Low",
                    "Recommendation": f"CloudTrail monitoring is properly configured in all {len(enabled_regions)} checked regions",
                    "EnabledRegions": ", ".join(sorted(enabled_regions)) if enabled_regions else "None",
                    "DisabledRegions": ", ".join(sorted(disabled_regions)) if disabled_regions else "None",
                    "IssueRegions": ", ".join(sorted(issue_regions)) if issue_regions else "None"
                })
    
    # Add general recommendations
    recommendations.append({
        "Service": "General",
        "Priority": "Medium",
        "Recommendation": "Implement a centralized logging and monitoring solution",
        "EnabledRegions": "N/A",
        "DisabledRegions": "N/A",
        "IssueRegions": "N/A"
    })
    
    recommendations.append({
        "Service": "General",
        "Priority": "Medium",
        "Recommendation": "Create automated response workflows for critical alerts",
        "EnabledRegions": "N/A",
        "DisabledRegions": "N/A",
        "IssueRegions": "N/A"
    })
    
    return recommendations

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

def generate_summary_report(findings, recommendations):
    """Generate a detailed summary report"""
    # Group findings by service and region
    services_by_region = {}
    regions_by_service = {}
    alarm_counts_by_region = {}
    
    for finding in findings:
        service = finding.get("Service")
        region = finding.get("Region")
        status = finding.get("Status")
        
        # Skip if missing key data
        if not service or not region or not status:
            continue
        
        # Track services by region
        if region not in services_by_region:
            services_by_region[region] = {}
        if service not in services_by_region[region]:
            services_by_region[region][service] = {"Good": 0, "Info": 0, "Warning": 0, "Critical": 0, "Error": 0}
        services_by_region[region][service][status] += 1
        
        # Track regions by service
        if service not in regions_by_service:
            regions_by_service[service] = {}
        if region not in regions_by_service[service]:
            regions_by_service[service][region] = {"Good": 0, "Info": 0, "Warning": 0, "Critical": 0, "Error": 0}
        regions_by_service[service][region][status] += 1
        
        # Track CloudWatch alarm counts by region
        if service == "CloudWatch Alarms" and finding.get("ResourceId") == "Summary":
            alarm_counts_by_region[region] = {
                "AlarmCount": finding.get("AlarmCount", 0),
                "AlarmsInAlarmState": finding.get("AlarmsInAlarmState", 0),
                "AlarmsByNamespace": finding.get("AlarmsByNamespace", "{}")
            }
    
    # Generate the report
    report = []
    
    # Add header
    report.append("=== AWS Monitoring Analysis Summary Report ===\n")
    
    # Add CloudWatch Alarms section
    report.append("=== CloudWatch Alarms by Region ===")
    for region, counts in sorted(alarm_counts_by_region.items()):
        alarm_count = counts["AlarmCount"]
        alarms_in_alarm = counts["AlarmsInAlarmState"]
        
        # Try to parse the AlarmsByNamespace JSON
        try:
            alarms_by_namespace = json.loads(counts["AlarmsByNamespace"])
            namespace_str = ", ".join([f"{ns}: {count}" for ns, count in alarms_by_namespace.items()])
        except:
            namespace_str = "Error parsing namespace data"
        
        report.append(f"Region {region}: {alarm_count} alarms ({alarms_in_alarm} in ALARM state)")
        if namespace_str:
            report.append(f"  Namespaces: {namespace_str}")
    
    # Add Services by Region section
    report.append("\n=== Monitoring Services by Region ===")
    for region, services in sorted(services_by_region.items()):
        report.append(f"Region: {region}")
        for service, statuses in sorted(services.items()):
            status_str = ", ".join([f"{status}: {count}" for status, count in statuses.items() if count > 0])
            report.append(f"  {service}: {status_str}")
    
    # Add Recommendations section
    report.append("\n=== Recommendations ===")
    for recommendation in recommendations:
        service = recommendation.get("Service")
        priority = recommendation.get("Priority")
        rec_text = recommendation.get("Recommendation")
        enabled_regions = recommendation.get("EnabledRegions", "N/A")
        disabled_regions = recommendation.get("DisabledRegions", "N/A")
        issue_regions = recommendation.get("IssueRegions", "N/A")
        
        report.append(f"[{priority}] {service}: {rec_text}")
        if enabled_regions != "N/A":
            report.append(f"  Enabled in: {enabled_regions}")
        if disabled_regions != "N/A" and disabled_regions != "None":
            report.append(f"  Disabled in: {disabled_regions}")
        if issue_regions != "N/A" and issue_regions != "None":
            report.append(f"  Issues in: {issue_regions}")
    
    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Analyze AWS monitoring tools")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--regions", nargs="+", help="AWS regions to analyze")
    parser.add_argument("--output", default="monitoring_findings.csv", help="Output CSV file")
    parser.add_argument("--recommendations", default="monitoring_recommendations.csv", help="Recommendations CSV file")
    parser.add_argument("--summary", default="monitoring_summary.txt", help="Summary report file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting monitoring analysis...")
    
    # Analyze monitoring tools
    findings = analyze_monitoring_tools(args.profile, args.regions)
    
    # Generate recommendations
    recommendations = generate_recommendations(findings)
    
    # Export findings and recommendations
    export_to_csv(findings, args.output)
    export_to_csv(recommendations, args.recommendations)
    
    # Generate and save summary report
    summary_report = generate_summary_report(findings, recommendations)
    with open(args.summary, 'w') as f:
        f.write(summary_report)
    
    # Print summary
    status_counts = {"Good": 0, "Info": 0, "Warning": 0, "Critical": 0, "Error": 0}
    for finding in findings:
        status = finding.get("Status")
        if status in status_counts:
            status_counts[status] += 1
    
    print("\n=== Monitoring Analysis Summary ===")
    print(f"Total findings: {len(findings)}")
    for status, count in status_counts.items():
        print(f"{status} findings: {count}")
    
    print("\n=== Recommendations ===")
    for recommendation in recommendations:
        print(f"[{recommendation['Priority']}] {recommendation['Service']}: {recommendation['Recommendation']}")
        if "EnabledRegions" in recommendation and recommendation["EnabledRegions"] != "N/A":
            print(f"  Enabled in: {recommendation['EnabledRegions']}")
    
    print(f"\nDetailed summary report written to: {args.summary}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()