#!/usr/bin/env python3

import csv
import glob
import os
from datetime import datetime

# AWS service role patterns
AWS_SERVICE_ROLES = {
    "control_tower": {
        "patterns": ["AWSControlTowerExecution", "AWSControlTowerStackSetRole", "AWSControlTowerCloudTrailRole", "aws-controltower-", "AWSControlTowerAdmin"],
        "description": "AWS Control Tower service for centralized multi-account governance"
    },
    "identity_center": {
        "patterns": ["AWSReservedSSO_", "aws-reserved-sso", "AWSServiceRoleForSSO", "AWSServiceRoleForIdentityStore"],
        "description": "AWS IAM Identity Center (SSO) for centralized access management"
    },
    "account_factory": {
        "patterns": ["AWSControlTowerAccountFactory", "AccountFactory", "AWSAFTExecution", "aft-", "AFT-"],
        "description": "AWS Control Tower Account Factory for Terraform (AFT) - automated account provisioning framework"
    },
    "firewall_manager": {
        "patterns": ["AWSServiceRoleForFMS", "FMSServiceRole"],
        "description": "AWS Firewall Manager service for centralized firewall management"
    },
    "guardduty": {
        "patterns": ["AWSServiceRoleForAmazonGuardDuty", "GuardDutyServiceRole"],
        "description": "Amazon GuardDuty threat detection service"
    },
    "security_hub": {
        "patterns": ["AWSServiceRoleForSecurityHub", "SecurityHubServiceRole"],
        "description": "AWS Security Hub for centralized security findings management"
    }
}

def get_service_dependency(role_name):
    """Get service dependency for a role"""
    if not role_name:
        return "No service dependency identified"
    
    role_name_lower = role_name.lower()
    for service, service_info in AWS_SERVICE_ROLES.items():
        for pattern in service_info["patterns"]:
            if pattern.lower() in role_name_lower:
                return service_info["description"]
    
    return "No service dependency identified"

def get_role_name(row):
    """Extract role name from various possible fields"""
    for field in ["RoleName", "Role Name", "EntityName", "Resource", "ResourceId", "Resource ID"]:
        if field in row and row[field]:
            return str(row[field]).strip()
    return "Unknown"

def get_finding_description(row):
    """Extract finding description"""
    for field in ["Title", "Finding", "Issue", "Description", "Problem", "Summary"]:
        if field in row and row[field]:
            return str(row[field]).strip()
    return "Security finding detected"

def get_explicit_action(row, filename):
    """Generate explicit action based on finding"""
    role_name = get_role_name(row)
    description = get_finding_description(row).lower()
    filename_lower = filename.lower()
    
    # Check if it's an AWS service role
    service_dep = get_service_dependency(role_name)
    if service_dep != "No service dependency identified":
        return f"INFORMATIONAL: '{role_name}' is an AWS service role. Verify this configuration is required before making changes."
    
    # Generate specific actions based on content
    if "escalation" in description or "chain" in description:
        return f"Remove unnecessary AssumeRole permissions from '{role_name}' or add MFA/IP conditions to trust policy"
    elif "public" in description or "*" in str(row):
        return f"Remove public access permissions and implement IP restrictions for '{role_name}'"
    elif "cross-account" in description or "external" in description:
        return f"Review external access necessity for '{role_name}' and add conditions (MFA, IP, ExternalId) to trust policy"
    elif "compliance" in description or "failed" in description:
        return f"Address compliance violation for '{role_name}' according to security best practices"
    else:
        return f"Review and secure IAM permissions for '{role_name}'"

def process_csv_file(csv_file):
    """Process a single CSV file and return summary"""
    filename = os.path.basename(csv_file)
    print(f"[INFO] Processing: {filename}")
    
    try:
        with open(csv_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            data = list(reader)
    except Exception as e:
        print(f"[ERROR] Failed to load {filename}: {e}")
        return None
    
    if not data:
        return None
    
    findings = []
    for row in data:
        role_name = get_role_name(row)
        description = get_finding_description(row)
        service_dependency = get_service_dependency(role_name)
        action = get_explicit_action(row, filename)
        
        findings.append({
            "role_name": role_name,
            "description": description,
            "service_dependency": service_dependency,
            "action": action
        })
    
    return {
        "filename": filename,
        "count": len(findings),
        "findings": findings
    }

def generate_text_report(csv_summaries, output_file):
    """Generate text report"""
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AWS SECURITY AUDIT - CSV SUMMARY REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        total_findings = sum(summary["count"] for summary in csv_summaries if summary)
        f.write(f"Total CSV files processed: {len([s for s in csv_summaries if s])}\n")
        f.write(f"Total findings: {total_findings}\n\n")
        
        for summary in csv_summaries:
            if not summary:
                continue
                
            f.write(f"FILE: {summary['filename']}\n")
            f.write("-" * 60 + "\n")
            f.write(f"Findings: {summary['count']}\n\n")
            
            for i, finding in enumerate(summary['findings'], 1):
                f.write(f"{i}. Role/Resource: {finding['role_name']}\n")
                f.write(f"   Description: {finding['description']}\n")
                f.write(f"   Service Dependency: {finding['service_dependency']}\n")
                f.write(f"   Action: {finding['action']}\n\n")
            
            f.write("\n")

def generate_html_report(csv_summaries, output_file):
    """Generate HTML report"""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AWS Security Audit - CSV Summary Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }}
        .csv-section {{ margin-bottom: 40px; border: 1px solid #ddd; border-radius: 8px; padding: 20px; }}
        .csv-title {{ background-color: #3498db; color: white; padding: 10px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }}
        .finding {{ background-color: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .service-role {{ border-left-color: #28a745; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 20px; background-color: #ecf0f1; border-radius: 8px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AWS Security Audit - CSV Summary Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{len([s for s in csv_summaries if s])}</div>
                <div>CSV Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{sum(summary["count"] for summary in csv_summaries if summary)}</div>
                <div>Total Findings</div>
            </div>
        </div>
"""

    for summary in csv_summaries:
        if not summary:
            continue
            
        html_content += f"""
        <div class="csv-section">
            <div class="csv-title">
                <h2>{summary['filename']} ({summary['count']} findings)</h2>
            </div>
"""
        
        for i, finding in enumerate(summary['findings'], 1):
            service_class = "service-role" if finding['service_dependency'] != "No service dependency identified" else ""
            html_content += f"""
            <div class="finding {service_class}">
                <h4>{i}. {finding['role_name']}</h4>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>Service Dependency:</strong> {finding['service_dependency']}</p>
                <p><strong>Action:</strong> {finding['action']}</p>
            </div>
"""
        
        html_content += "</div>"

    html_content += """
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    print("[INFO] Starting CSV Summary Report Generator")
    
    # Find all CSV files in current directory
    csv_files = glob.glob("*.csv")
    
    if not csv_files:
        print("[ERROR] No CSV files found in current directory")
        return
    
    print(f"[INFO] Found {len(csv_files)} CSV files")
    
    # Process each CSV file
    csv_summaries = []
    for csv_file in csv_files:
        summary = process_csv_file(csv_file)
        csv_summaries.append(summary)
    
    # Generate reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    text_output = f"csv_summary_report_{timestamp}.txt"
    html_output = f"csv_summary_report_{timestamp}.html"
    
    generate_text_report(csv_summaries, text_output)
    generate_html_report(csv_summaries, html_output)
    
    print(f"\n[SUCCESS] Reports generated:")
    print(f"  Text: {text_output}")
    print(f"  HTML: {html_output}")
    
    valid_summaries = [s for s in csv_summaries if s]
    total_findings = sum(s["count"] for s in valid_summaries)
    print(f"\n[INFO] Processed {len(valid_summaries)} CSV files with {total_findings} total findings")

if __name__ == "__main__":
    main()