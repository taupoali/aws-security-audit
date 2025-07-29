#!/usr/bin/env python3

import csv
import glob
import os
import argparse
from datetime import datetime
from collections import defaultdict

# Critical finding patterns to look for
CRITICAL_PATTERNS = {
    "privilege_escalation": {
        "keywords": ["escalation", "chain", "admin", "root"],
        "severity": "CRITICAL",
        "description": "Privilege escalation paths found"
    },
    "public_admin_access": {
        "keywords": ["public", "*", "0.0.0.0/0", "admin", "full"],
        "severity": "CRITICAL", 
        "description": "Public access to administrative resources"
    },
    "failed_compliance": {
        "keywords": ["failed", "critical", "high", "non_compliant"],
        "severity": "HIGH",
        "description": "Failed security compliance checks"
    },
    "external_access": {
        "keywords": ["external", "cross-account", "assume", "trust"],
        "severity": "HIGH",
        "description": "External or cross-account access"
    }
}

def find_all_csv_files(directory):
    """Find all CSV files in directory"""
    pattern = os.path.join(directory, "*.csv")
    return glob.glob(pattern)

def load_csv_data(file_path):
    """Load CSV data"""
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []

# AWS service role patterns that should not be modified
AWS_SERVICE_ROLES = {
    "control_tower": [
        "AWSControlTowerExecution", "AWSControlTowerStackSetRole", "AWSControlTowerCloudTrailRole",
        "AWSControlTowerConfigAggregatorRoleForOrganizations", "aws-controltower-", "ControlTowerExecution",
        "AWSControlTowerBP-", "StackSet-AWSControlTower", "AWSControlTowerAdmin"
    ],
    "identity_center": [
        "AWSReservedSSO_", "aws-reserved-sso", "AWSServiceRoleForSSO", "AWSServiceRoleForIdentityStore",
        "AWSSSORoleForIdentityCenter", "PermissionSet", "AccountAssignment"
    ],
    "organizations": [
        "OrganizationAccountAccessRole", "AWSServiceRoleForOrganizations", "OrganizationFormationRole",
        "AWSOrganizationsServiceRole"
    ],
    "config": [
        "AWSServiceRoleForConfig", "aws-config-role", "ConfigRole", "AWSConfigRole"
    ],
    "cloudtrail": [
        "CloudTrail_CloudWatchLogsRole", "AWSServiceRoleForCloudTrail", "CloudTrailRole"
    ],
    "account_factory": [
        "AWSControlTowerAccountFactory", "AccountFactory", "ServiceCatalogEndUser", "AWSServiceCatalogEndUser"
    ]
}

# Expected configurations for AWS services (what should be considered normal)
EXPECTED_SERVICE_CONFIGS = {
    "control_tower_cross_account": {
        "description": "Control Tower requires cross-account access to manage member accounts",
        "expected_principals": ["organizations.amazonaws.com", "controltower.amazonaws.com"],
        "expected_permissions": ["*", "sts:AssumeRole", "organizations:*"]
    },
    "identity_center_wildcards": {
        "description": "Identity Center requires wildcard permissions for dynamic role creation",
        "expected_principals": ["sso.amazonaws.com", "identitystore.amazonaws.com"],
        "expected_permissions": ["*", "sts:AssumeRole", "sts:AssumeRoleWithSAML"]
    },
    "account_factory_permissions": {
        "description": "Account Factory requires broad permissions for account provisioning",
        "expected_principals": ["servicecatalog.amazonaws.com", "controltower.amazonaws.com"],
        "expected_permissions": ["organizations:*", "iam:*", "sts:AssumeRole"]
    }
}

def is_aws_service_role(role_name):
    """Check if a role is an AWS service role that should not be modified"""
    if not role_name:
        return False
    
    role_name_lower = role_name.lower()
    
    for service, patterns in AWS_SERVICE_ROLES.items():
        for pattern in patterns:
            if pattern.lower() in role_name_lower:
                return service
    return None

def is_expected_service_behavior(row, pattern, role_name):
    """Check if the finding represents expected AWS service behavior"""
    if not role_name:
        return None
    
    service_type = is_aws_service_role(role_name)
    if not service_type:
        return None
    
    row_str = str(row).lower()
    principal = str(row.get("Principal", "")).lower()
    
    # Check for expected Control Tower behavior
    if service_type == "control_tower":
        if pattern == "external_access" and any(svc in principal for svc in ["organizations.amazonaws.com", "controltower.amazonaws.com", "root"]):
            return "control_tower_cross_account"
        if pattern == "public_admin_access" and any(perm in row_str for perm in ["*", "organizations:", "sts:assumerole"]):
            return "control_tower_cross_account"
    
    # Check for expected Identity Center behavior
    if service_type == "identity_center":
        if pattern == "public_admin_access" and any(perm in row_str for perm in ["*", "sts:assumerole", "saml"]):
            return "identity_center_wildcards"
        if pattern == "external_access" and any(svc in principal for svc in ["sso.amazonaws.com", "identitystore.amazonaws.com"]):
            return "identity_center_wildcards"
    
    # Check for expected Account Factory behavior
    if service_type == "account_factory":
        if pattern == "public_admin_access" and any(perm in row_str for perm in ["organizations:", "iam:", "servicecatalog:"]):
            return "account_factory_permissions"
    
    return None

def get_service_dependency(pattern, row, role_name):
    """Determine service dependency for a finding"""
    # Check if this represents expected AWS service behavior
    expected_behavior = is_expected_service_behavior(row, pattern, role_name)
    if expected_behavior:
        if expected_behavior == "control_tower_cross_account":
            return "Control Tower function required - verify before changes"
        elif expected_behavior == "identity_center_wildcards":
            return "Identity Center function required - verify before changes"
        elif expected_behavior == "account_factory_permissions":
            return "Account Factory function required - verify before changes"
    
    # Check if this is an AWS service role (fallback)
    service_type = is_aws_service_role(role_name)
    if service_type:
        service_name = service_type.replace('_', ' ').title()
        return f"{service_name} service dependency - verify requirement"
    
    # Check for specific service dependencies based on content
    row_str = str(row).lower()
    if "passrole" in row_str:
        if "admin" in row_str or "*" in row_str:
            return "High privilege PassRole - review service necessity"
        else:
            return "PassRole permission - verify service requirement"
    
    if "assumerole" in row_str and "cross" in row_str:
        return "Cross-account access - verify business requirement"
    
    return "No service dependency identified"

def generate_actionable_response(pattern, row, filename):
    """Generate specific actionable response based on CSV data"""
    filename_lower = filename.lower()
    role_name = row.get("RoleName") or row.get("Role Name") or row.get("EntityName") or "Unknown"
    resource = row.get("Resource") or row.get("ResourceId") or row.get("Resource ID") or ""
    path = row.get("Path") or row.get("Chain") or ""
    target_role = row.get("Target Privileged Role") or row.get("TargetPrivilegedRole") or ""
    principal = row.get("Principal") or row.get("ExternalPrincipal") or row.get("External Principals") or ""
    title = row.get("Title") or row.get("Finding") or ""
    
    # Check if this represents expected AWS service behavior
    expected_behavior = is_expected_service_behavior(row, pattern, role_name)
    if expected_behavior:
        config_info = EXPECTED_SERVICE_CONFIGS.get(expected_behavior, {})
        description = config_info.get("description", "Required for AWS service functionality")
        return f"EXPECTED BEHAVIOR: '{role_name}' - {description}. This configuration is required and should not be modified."
    
    # Check if this is an AWS service role (fallback)
    service_type = is_aws_service_role(role_name)
    if service_type:
        return f"AWS SERVICE ROLE: '{role_name}' is an AWS {service_type.replace('_', ' ').title()} service role. Verify this configuration is required before making changes."
    
    if pattern == "privilege_escalation":
        if path and target_role:
            # Extract the chain steps
            chain_steps = path.split(" -> ") if " -> " in path else path.split("->") if "->" in path else [path]
            if len(chain_steps) > 1:
                return f"Remove AssumeRole permission from '{chain_steps[0]}' to '{chain_steps[1]}' or add MFA/IP conditions to break the escalation chain to '{target_role}'"
            else:
                return f"Remove direct AssumeRole permission allowing '{role_name}' to access '{target_role}'"
        elif target_role:
            return f"Remove AssumeRole permission allowing '{role_name}' to assume '{target_role}'"
        else:
            # Try to extract specific permissions that are excessive
            excessive_perms = []
            row_str = str(row).lower()
            
            # Look for admin-level permissions in the data
            admin_indicators = ['*', 'admin', 'full', 'all', 'iam:', 'organizations:', 's3:*', 'ec2:*']
            for indicator in admin_indicators:
                if indicator in row_str:
                    excessive_perms.append(indicator)
            
            # Check specific fields that might contain permissions
            for field in ['Actions', 'Action', 'Permissions', 'PolicyDocument', 'Statement']:
                if field in row and row[field]:
                    field_value = str(row[field])
                    if any(admin in field_value for admin in ['*', 'Admin', 'Full']):
                        excessive_perms.append(f"Field '{field}': {field_value[:100]}..." if len(field_value) > 100 else f"Field '{field}': {field_value}")
            
            if excessive_perms:
                perm_summary = ", ".join(excessive_perms[:3])  # Limit to first 3 items
                return f"Review and remove excessive IAM permissions from '{role_name}' that allow privilege escalation. Flagged permissions: {perm_summary}"
            else:
                return f"Review and remove excessive IAM permissions from '{role_name}' that allow privilege escalation"
    
    elif pattern == "public_admin_access":
        # Check if this is an AWS service role first
        service_type = is_aws_service_role(role_name)
        if service_type:
            return f"INFORMATIONAL: '{role_name}' is an AWS {service_type.replace('_', ' ').title()} service role. Wildcard permissions are required for service functionality. No action needed."
        
        if "s3" in filename_lower and resource:
            return f"Remove public-read/public-write ACL from S3 bucket '{resource}' and set bucket policy to deny public access"
        elif "iam" in filename_lower and role_name:
            # Try to show what specific wildcard access was found
            wildcard_details = []
            row_str = str(row)
            if "*" in row_str:
                # Extract context around wildcards
                for field in ['Principal', 'Action', 'Resource', 'Statement']:
                    if field in row and row[field] and "*" in str(row[field]):
                        wildcard_details.append(f"{field}: {str(row[field])[:50]}..." if len(str(row[field])) > 50 else f"{field}: {row[field]}")
            
            if wildcard_details:
                details = ", ".join(wildcard_details[:2])  # Limit to first 2 items
                return f"Remove wildcard (*) principals from trust policy of IAM role '{role_name}'. Found: {details}"
            else:
                return f"Remove wildcard (*) principals from trust policy of IAM role '{role_name}'"
        elif resource and "*" in str(row).lower():
            return f"Replace wildcard (*) permissions with specific principals/IPs for resource '{resource}'"
        else:
            return f"Remove public access by replacing '*' with specific AWS account IDs or IP ranges"
    
    elif pattern == "failed_compliance":
        if "security" in filename_lower and title:
            if "root" in title.lower():
                return f"Delete or secure root access keys - {title}"
            elif "mfa" in title.lower():
                return f"Enable MFA for the identified resource - {title}"
            elif "encryption" in title.lower():
                return f"Enable encryption for the resource - {title}"
            else:
                return f"Remediate Security Hub finding: {title}"
        elif "config" in filename_lower:
            rule_name = row.get("RuleName") or row.get("Rule Name") or "unknown rule"
            return f"Fix AWS Config rule violation for '{rule_name}' on resource '{resource or role_name}'"
        else:
            return f"Address compliance violation: {title or 'Review specific finding details'}"
    
    elif pattern == "external_access":
        # Check if this is an AWS service role first
        service_type = is_aws_service_role(role_name)
        if service_type:
            return f"INFORMATIONAL: '{role_name}' is an AWS {service_type.replace('_', ' ').title()} service role. Cross-account access is required for service functionality. No action needed."
        
        if principal and role_name:
            if "root" in principal:
                account_id = principal.split("::")[1].split(":")[0] if "::" in principal else "external account"
                return f"Review if root access from {account_id} is necessary for '{role_name}'. If required for Control Tower/SSO, no action needed. Otherwise, add ExternalId condition."
            else:
                return f"Add conditions (aws:SourceIp, aws:RequestedRegion, sts:ExternalId) to trust policy allowing '{principal}' access to '{role_name}'"
        else:
            return f"Review external access permissions for '{role_name}' and add restrictive conditions"
    
    else:
        if title:
            return f"Address security issue: {title}"
        elif resource:
            return f"Review and secure resource: {resource}"
        else:
            return f"Review IAM permissions for role: {role_name}"

def generate_problem_summary(row, filename, pattern):
    """Generate a simplified problem summary based on the finding"""
    filename_lower = filename.lower()
    
    # Extract key information for summary
    role_name = row.get("RoleName") or row.get("Role Name") or row.get("EntityName") or "Unknown"
    resource = row.get("Resource") or row.get("ResourceId") or row.get("Resource ID") or ""
    path = row.get("Path") or row.get("Chain") or ""
    title = row.get("Title") or row.get("Finding") or ""
    
    # Generate context-specific summaries
    if pattern == "privilege_escalation":
        if path:
            return f"Role '{role_name}' can escalate privileges via: {path}"
        else:
            return f"Role '{role_name}' has privilege escalation capability"
    
    elif pattern == "public_admin_access":
        if "s3" in filename_lower:
            return f"S3 bucket '{resource}' allows public administrative access"
        elif "iam" in filename_lower:
            return f"IAM role '{role_name}' grants public administrative permissions"
        else:
            return f"Resource '{resource or role_name}' has public administrative access"
    
    elif pattern == "failed_compliance":
        if "security" in filename_lower:
            return f"Security Hub compliance failure: {title or resource or role_name}"
        elif "config" in filename_lower:
            return f"AWS Config rule violation: {title or resource or role_name}"
        else:
            return f"Compliance check failed for: {resource or role_name or title}"
    
    elif pattern == "external_access":
        principal = row.get("Principal") or row.get("ExternalPrincipal") or row.get("External Principals") or "external entity"
        return f"Role '{role_name}' allows access from {principal}"
    
    else:
        # General finding
        if title:
            return f"Security issue: {title}"
        elif resource:
            return f"Security concern with resource: {resource}"
        else:
            return f"Security finding in role: {role_name}"

def analyze_finding_severity(row, filename):
    """Analyze a single finding for severity"""
    row_text = str(row).lower()
    filename_lower = filename.lower()
    role_name = row.get("RoleName") or row.get("Role Name") or row.get("EntityName") or "Unknown"
    
    # Check if this is an AWS service role - reduce severity if it is
    service_type = is_aws_service_role(role_name)
    
    # Check for critical patterns
    for pattern_name, pattern_info in CRITICAL_PATTERNS.items():
        if any(keyword in row_text or keyword in filename_lower for keyword in pattern_info["keywords"]):
            problem_summary = generate_problem_summary(row, filename, pattern_name)
            actionable_response = generate_actionable_response(pattern_name, row, filename)
            
            # Reduce severity for AWS service roles
            severity = pattern_info["severity"]
            if service_type:
                if severity == "CRITICAL":
                    severity = "LOW"  # Service roles with expected permissions
                elif severity == "HIGH":
                    severity = "LOW"
            
            return {
                "severity": severity,
                "reason": pattern_info["description"] + (f" (AWS {service_type.replace('_', ' ').title()} Service Role)" if service_type else ""),
                "pattern": pattern_name,
                "problem_summary": problem_summary,
                "actionable_response": actionable_response
            }
    
    problem_summary = generate_problem_summary(row, filename, "general")
    actionable_response = generate_actionable_response("general", row, filename)
    return {
        "severity": "MEDIUM", 
        "reason": "Standard security finding", 
        "pattern": "general",
        "problem_summary": problem_summary,
        "actionable_response": actionable_response
    }

def extract_key_info(row, filename):
    """Extract key information from a finding"""
    # Common field names to look for
    key_fields = [
        "RoleName", "Role Name", "EntityName", "Resource", "ResourceId", "Resource ID",
        "Title", "Finding", "Issue", "Description", "Path", "Chain", "Principal",
        "Service", "Region", "Account", "AccountId", "Severity", "Status"
    ]
    
    key_info = {}
    for field in key_fields:
        for actual_field in row.keys():
            if field.lower() in actual_field.lower():
                value = row[actual_field]
                if value and str(value).strip():
                    key_info[field] = str(value).strip()
                break
    
    # Add source file
    key_info["SourceFile"] = os.path.basename(filename)
    
    return key_info

def process_all_findings(csv_files):
    """Process all CSV files and extract critical findings"""
    all_findings = []
    
    for csv_file in csv_files:
        filename = os.path.basename(csv_file)
        print(f"[INFO] Processing: {filename}")
        
        data = load_csv_data(csv_file)
        if not data:
            continue
        
        for row in data:
            severity_info = analyze_finding_severity(row, filename)
            key_info = extract_key_info(row, csv_file)
            
            # Get service dependency
            service_dependency = get_service_dependency(severity_info["pattern"], row, key_info.get("RoleName", ""))
            
            finding = {
                "Severity": severity_info["severity"],
                "Reason": severity_info["reason"],
                "Pattern": severity_info["pattern"],
                "ProblemSummary": severity_info["problem_summary"],
                "ActionableResponse": severity_info["actionable_response"],
                "ServiceDependency": service_dependency,
                **key_info
            }
            
            all_findings.append(finding)
    
    return all_findings

def create_priority_summary(findings):
    """Create a prioritized summary of findings"""
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["Severity"], 4))
    
    # Separate trusted advisor findings
    trusted_advisor_findings = [f for f in findings if "trusted_advisor" in f.get("SourceFile", "").lower()]
    non_trusted_advisor_findings = [f for f in findings if "trusted_advisor" not in f.get("SourceFile", "").lower()]
    
    # Group by severity and pattern
    summary = {
        "critical_count": len([f for f in findings if f["Severity"] == "CRITICAL"]),
        "high_count": len([f for f in findings if f["Severity"] == "HIGH"]),
        "total_count": len(findings),
        "trusted_advisor_count": len(trusted_advisor_findings),
        "non_trusted_advisor_count": len(non_trusted_advisor_findings),
        "by_pattern": defaultdict(list),
        "by_source": defaultdict(int),
        "top_critical": []
    }
    
    # Group by pattern
    for finding in findings:
        pattern = finding["Pattern"]
        summary["by_pattern"][pattern].append(finding)
    
    # Group by source file
    for finding in findings:
        source = finding.get("SourceFile", "unknown")
        summary["by_source"][source] += 1
    
    # Get top 20 critical findings
    critical_findings = [f for f in findings if f["Severity"] == "CRITICAL"]
    summary["top_critical"] = critical_findings[:20]
    summary["all_findings"] = findings
    
    return summary

def generate_readable_report(summary, output_file, max_items=20):
    """Generate a human-readable priority report"""
    with open(output_file, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("AWS SECURITY AUDIT - PRIORITY FINDINGS REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Executive Summary
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 20 + "\n")
        f.write(f"Total Findings: {summary['total_count']}\n")
        f.write(f"Security Findings (excluding Trusted Advisor): {summary['non_trusted_advisor_count']}\n")
        f.write(f"Trusted Advisor Findings: {summary['trusted_advisor_count']}\n")
        f.write(f"Critical Findings: {summary['critical_count']}\n")
        f.write(f"High Priority Findings: {summary['high_count']}\n\n")
        
        if summary['critical_count'] > 0:
            f.write("*** IMMEDIATE ACTION REQUIRED - CRITICAL FINDINGS DETECTED ***\n\n")
        
        # Top Critical Findings
        if summary['top_critical']:
            f.write("TOP 20 CRITICAL FINDINGS (IMMEDIATE ATTENTION)\n")
            f.write("-" * 50 + "\n")
            for i, finding in enumerate(summary['top_critical'], 1):
                f.write(f"{i}. {finding.get('ProblemSummary', finding['Reason'])}\n")
                
                # Show key details
                key_details = []
                for key in ["RoleName", "Resource", "Title", "Path", "Principal"]:
                    if key in finding and finding[key]:
                        key_details.append(f"{key}: {finding[key]}")
                
                if key_details:
                    f.write(f"   Details: {' | '.join(key_details[:3])}\n")
                
                f.write(f"   Source: {finding.get('SourceFile', 'unknown')}\n")
                f.write(f"   Impact: {finding['Reason']}\n")
                f.write(f"   Service Dependency: {finding.get('ServiceDependency', 'None identified')}\n")
                f.write(f"   Action: {finding.get('ActionableResponse', 'Review and remediate')}\n\n")
        
        # Findings by Category
        f.write("FINDINGS BY SECURITY CATEGORY\n")
        f.write("-" * 35 + "\n")
        
        pattern_names = {
            "privilege_escalation": "Privilege Escalation",
            "public_admin_access": "Public Administrative Access", 
            "failed_compliance": "Failed Compliance Checks",
            "external_access": "External/Cross-Account Access",
            "general": "Other Security Issues"
        }
        
        for pattern, pattern_findings in summary['by_pattern'].items():
            if not pattern_findings:
                continue
                
            pattern_name = pattern_names.get(pattern, pattern.title())
            critical_count = len([f for f in pattern_findings if f["Severity"] == "CRITICAL"])
            high_count = len([f for f in pattern_findings if f["Severity"] == "HIGH"])
            
            f.write(f"{pattern_name}: {len(pattern_findings)} findings")
            if critical_count > 0:
                f.write(f" ({critical_count} CRITICAL)")
            if high_count > 0:
                f.write(f" ({high_count} HIGH)")
            f.write("\n")
            
            # Show top 10 critical findings for this category with full details
            critical_findings = [f for f in pattern_findings if f["Severity"] == "CRITICAL"]
            if critical_findings:
                f.write(f"   Top Critical Issues in {pattern_name}:\n")
                for i, finding in enumerate(critical_findings[:10], 1):
                    f.write(f"   {i}. {finding.get('ProblemSummary', 'Unknown issue')}\n")
                    
                    # Show key details
                    key_details = []
                    for key in ["RoleName", "Resource", "Title", "Path", "Principal"]:
                        if key in finding and finding[key]:
                            key_details.append(f"{key}: {finding[key]}")
                    
                    if key_details:
                        f.write(f"      Details: {' | '.join(key_details[:3])}\n")
                    
                    f.write(f"      Source: {finding.get('SourceFile', 'unknown')}\n")
                    f.write(f"      Impact: {finding['Reason']}\n")
                    f.write(f"      Action: {finding.get('ActionableResponse', 'Review and remediate')}\n\n")
            else:
                f.write("\n")
        
        f.write("\n")
        
        # High Priority Findings Summary (non-critical but important)
        high_priority_findings = [f for f in summary.get('all_findings', []) if f.get('Severity') == 'HIGH']
        if high_priority_findings:
            f.write("HIGH PRIORITY FINDINGS SUMMARY\n")
            f.write("-" * 35 + "\n")
            f.write(f"Found {len(high_priority_findings)} high priority security issues requiring attention:\n\n")
            
            for i, finding in enumerate(high_priority_findings[:15], 1):
                f.write(f"{i}. {finding.get('ProblemSummary', finding['Reason'])}\n")
                
                # Show key details
                key_details = []
                for key in ["RoleName", "Resource", "Title", "Path", "Principal"]:
                    if key in finding and finding[key]:
                        key_details.append(f"{key}: {finding[key]}")
                
                if key_details:
                    f.write(f"   Details: {' | '.join(key_details[:3])}\n")
                
                f.write(f"   Impact: {finding['Reason']}\n")
                f.write(f"   Action: {finding.get('ActionableResponse', 'Review and remediate')}\n\n")
        
        f.write("\n")
        
        # Chain Escalation Analysis
        f.write("PRIVILEGE ESCALATION CHAIN ANALYSIS\n")
        f.write("-" * 40 + "\n")
        
        # Get all escalation findings
        escalation_findings = [f for f in summary.get('all_findings', []) if f.get('Pattern') == 'privilege_escalation']
        
        if escalation_findings:
            f.write(f"Found {len(escalation_findings)} privilege escalation paths:\n\n")
            
            # Group by severity
            critical_chains = [f for f in escalation_findings if f.get('Severity') == 'CRITICAL']
            high_chains = [f for f in escalation_findings if f.get('Severity') == 'HIGH']
            
            if critical_chains:
                f.write(f"CRITICAL ESCALATION CHAINS ({len(critical_chains)}):\n")
                for i, finding in enumerate(critical_chains[:10], 1):
                    path = finding.get('Path') or finding.get('Chain') or 'Unknown path'
                    target = finding.get('Target Privileged Role') or finding.get('TargetPrivilegedRole') or 'Admin role'
                    f.write(f"{i}. {path} -> {target}\n")
                    f.write(f"   Action: {finding.get('ActionableResponse', 'Review escalation path')}\n\n")
            
            if high_chains:
                f.write(f"HIGH RISK ESCALATION CHAINS ({len(high_chains)}):\n")
                for i, finding in enumerate(high_chains[:5], 1):
                    path = finding.get('Path') or finding.get('Chain') or 'Unknown path'
                    target = finding.get('Target Privileged Role') or finding.get('TargetPrivilegedRole') or 'Privileged role'
                    f.write(f"{i}. {path} -> {target}\n")
                    f.write(f"   Action: {finding.get('ActionableResponse', 'Review escalation path')}\n\n")
            
            # Chain statistics
            f.write("ESCALATION CHAIN STATISTICS:\n")
            
            # Count chain lengths
            chain_lengths = {}
            for finding in escalation_findings:
                path = finding.get('Path') or finding.get('Chain') or ''
                if path:
                    length = len(path.split(' -> ')) if ' -> ' in path else len(path.split('->')) if '->' in path else 1
                    chain_lengths[length] = chain_lengths.get(length, 0) + 1
            
            if chain_lengths:
                f.write("Chain lengths:\n")
                for length, count in sorted(chain_lengths.items()):
                    f.write(f"  {length} steps: {count} chains\n")
            
            # Most common starting roles
            starting_roles = {}
            for finding in escalation_findings:
                path = finding.get('Path') or finding.get('Chain') or ''
                if path:
                    start_role = path.split(' -> ')[0] if ' -> ' in path else path.split('->')[0] if '->' in path else path
                    starting_roles[start_role] = starting_roles.get(start_role, 0) + 1
            
            if starting_roles:
                f.write("\nMost common starting roles:\n")
                sorted_roles = sorted(starting_roles.items(), key=lambda x: x[1], reverse=True)[:5]
                for role, count in sorted_roles:
                    f.write(f"  {role}: {count} chains\n")
            
        else:
            f.write("No privilege escalation chains detected.\n")
        
        f.write("\n")
        
        # Action Plan
        f.write("RECOMMENDED ACTION PLAN\n")
        f.write("-" * 25 + "\n")
        
        if summary['critical_count'] > 0:
            f.write("PHASE 1 - IMMEDIATE (0-7 days):\n")
            f.write(f"- Address all {summary['critical_count']} CRITICAL findings\n")
            f.write("- Focus on privilege escalation and public admin access\n")
            f.write("- Implement emergency access controls if needed\n\n")
        
        if summary['high_count'] > 0:
            f.write("PHASE 2 - SHORT TERM (1-4 weeks):\n")
            f.write(f"- Remediate {summary['high_count']} HIGH priority findings\n")
            f.write("- Review and strengthen access controls\n")
            f.write("- Implement additional monitoring\n\n")
        
        f.write("PHASE 3 - ONGOING:\n")
        f.write("- Regular security audits using these tools\n")
        f.write("- Continuous monitoring implementation\n")
        f.write("- Security awareness training\n\n")
        
        f.write("=" * 60 + "\n")
        f.write("END OF PRIORITY REPORT\n")
        f.write("=" * 60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Generate priority security findings report")
    parser.add_argument("--data-dir", default=".", help="Directory containing CSV files")
    parser.add_argument("--output", default="PRIORITY_SECURITY_REPORT.txt", help="Output report file")
    args = parser.parse_args()
    
    print(f"[INFO] Scanning for CSV files in: {args.data_dir}")
    
    # Find all CSV files
    csv_files = find_all_csv_files(args.data_dir)
    
    if not csv_files:
        print("[ERROR] No CSV files found")
        return
    
    print(f"[INFO] Found {len(csv_files)} CSV files")
    
    # Process all findings
    all_findings = process_all_findings(csv_files)
    
    if not all_findings:
        print("[ERROR] No findings processed")
        return
    
    # Create priority summary
    summary = create_priority_summary(all_findings)
    
    # Generate readable report
    generate_readable_report(summary, args.output)
    
    print(f"\n[SUCCESS] Priority report generated: {args.output}")
    print(f"[INFO] Total findings analyzed: {summary['total_count']}")
    print(f"[INFO] Critical findings: {summary['critical_count']}")
    print(f"[INFO] High priority findings: {summary['high_count']}")
    
    if summary['critical_count'] > 0:
        print(f"\n*** WARNING: {summary['critical_count']} CRITICAL findings require immediate attention! ***")

if __name__ == "__main__":
    main()