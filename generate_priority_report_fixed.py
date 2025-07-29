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

# AWS service role patterns with detailed service information
AWS_SERVICE_ROLES = {
    "control_tower": {
        "patterns": [
            "AWSControlTowerExecution", "AWSControlTowerStackSetRole", "AWSControlTowerCloudTrailRole",
            "AWSControlTowerConfigAggregatorRoleForOrganizations", "aws-controltower-", "ControlTowerExecution",
            "AWSControlTowerBP-", "StackSet-AWSControlTower", "AWSControlTowerAdmin", "AWSAFTExecution",
            "AWSControlTowerServiceRole", "AWSControlTowerLoggingRole", "AWSControlTowerSecurityRole"
        ],
        "description": "AWS Control Tower service for centralized multi-account governance",
        "function": "Manages account provisioning, guardrails, organizational compliance, and landing zone operations"
    },
    "identity_center": {
        "patterns": [
            "AWSReservedSSO_", "aws-reserved-sso", "AWSServiceRoleForSSO", "AWSServiceRoleForIdentityStore",
            "AWSSSORoleForIdentityCenter", "PermissionSet", "AccountAssignment"
        ],
        "description": "AWS IAM Identity Center (SSO) for centralized access management",
        "function": "Provides single sign-on and centralized permission management across AWS accounts"
    },
    "organizations": {
        "patterns": [
            "OrganizationAccountAccessRole", "AWSServiceRoleForOrganizations", "OrganizationFormationRole",
            "AWSOrganizationsServiceRole"
        ],
        "description": "AWS Organizations service for account management",
        "function": "Manages organizational units, accounts, and service control policies"
    },
    "config": {
        "patterns": [
            "AWSServiceRoleForConfig", "aws-config-role", "ConfigRole", "AWSConfigRole"
        ],
        "description": "AWS Config service for configuration compliance monitoring",
        "function": "Tracks resource configurations and evaluates compliance rules"
    },
    "cloudtrail": {
        "patterns": [
            "CloudTrail_CloudWatchLogsRole", "AWSServiceRoleForCloudTrail", "CloudTrailRole"
        ],
        "description": "AWS CloudTrail service for API logging and auditing",
        "function": "Records AWS API calls and delivers log files for security analysis"
    },
    "account_factory": {
        "patterns": [
            "AWSControlTowerAccountFactory", "AccountFactory", "ServiceCatalogEndUser", "AWSServiceCatalogEndUser",
            "AWSAFTExecution", "aft-", "AFT-"
        ],
        "description": "AWS Control Tower Account Factory for Terraform (AFT) - automated account provisioning framework",
        "function": "Orchestrates account creation, customizations, baseline configurations, and Terraform deployments across AWS accounts"
    },
    "firewall_manager": {
        "patterns": [
            "AWSServiceRoleForFMS", "FMSServiceRole", "FirewallManager"
        ],
        "description": "AWS Firewall Manager service for centralized firewall management",
        "function": "Manages WAF rules, security groups, and firewall policies across accounts"
    },
    "cloudformation_stacksets": {
        "patterns": [
            "AWSServiceRoleForCloudFormationStackSetsOrgMember", "StackSetsOrgMember", "CloudFormationStackSets"
        ],
        "description": "AWS CloudFormation StackSets for organization-wide deployments",
        "function": "Deploys CloudFormation stacks across multiple accounts and regions in organization"
    },
    "guardduty": {
        "patterns": [
            "AWSServiceRoleForAmazonGuardDuty", "GuardDutyServiceRole"
        ],
        "description": "Amazon GuardDuty threat detection service",
        "function": "Monitors for malicious activity and unauthorized behavior across AWS accounts"
    },
    "security_hub": {
        "patterns": [
            "AWSServiceRoleForSecurityHub", "SecurityHubServiceRole"
        ],
        "description": "AWS Security Hub for centralized security findings management",
        "function": "Aggregates security findings from multiple AWS security services"
    },
    "systems_manager": {
        "patterns": [
            "AWSServiceRoleForAmazonSSM", "SSMServiceRole", "SystemsManagerServiceRole"
        ],
        "description": "AWS Systems Manager for operational management",
        "function": "Manages EC2 instances, patches, and operational tasks across infrastructure"
    },
    "lambda_execution": {
        "patterns": [
            "lambda-execution-role", "LambdaExecutionRole", "aft-lambda-", "lambda-role-"
        ],
        "description": "AWS Lambda execution roles for serverless function operations",
        "function": "Provides Lambda functions with permissions to execute and access AWS services"
    },
    "codebuild": {
        "patterns": [
            "codebuild-", "CodeBuildServiceRole", "aft-codebuild-"
        ],
        "description": "AWS CodeBuild service for continuous integration and build automation",
        "function": "Compiles source code, runs tests, and produces deployment artifacts"
    },
    "codepipeline": {
        "patterns": [
            "codepipeline-", "CodePipelineServiceRole", "aft-pipeline-"
        ],
        "description": "AWS CodePipeline service for continuous delivery automation",
        "function": "Orchestrates build, test, and deployment workflows across environments"
    },
    "step_functions": {
        "patterns": [
            "StepFunctionsExecutionRole", "states-", "aft-states-"
        ],
        "description": "AWS Step Functions for workflow orchestration",
        "function": "Coordinates distributed applications and microservices using visual workflows"
    }
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
        "description": "Account Factory for Terraform (AFT) requires broad permissions for automated account provisioning and customization",
        "expected_principals": ["servicecatalog.amazonaws.com", "controltower.amazonaws.com", "lambda.amazonaws.com", "codebuild.amazonaws.com", "states.amazonaws.com"],
        "expected_permissions": ["organizations:*", "iam:*", "sts:AssumeRole", "servicecatalog:*", "ssm:*", "s3:*", "dynamodb:*"]
    }
}

def is_aws_service_role(role_name):
    """Check if a role is an AWS service role that should not be modified"""
    if not role_name:
        return None
    
    role_name_lower = role_name.lower()
    
    for service, service_info in AWS_SERVICE_ROLES.items():
        for pattern in service_info["patterns"]:
            if pattern.lower() in role_name_lower:
                return {
                    "service": service,
                    "description": service_info["description"],
                    "function": service_info["function"]
                }
    return None

def is_expected_service_behavior(row, pattern, role_name):
    """Check if the finding represents expected AWS service behavior"""
    if not role_name:
        return None
    
    service_info = is_aws_service_role(role_name)
    if not service_info:
        return None
    
    service_type = service_info["service"]
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
    """Determine service dependency for a finding with detailed context"""
    # Check if this represents expected AWS service behavior
    expected_behavior = is_expected_service_behavior(row, pattern, role_name)
    if expected_behavior:
        if expected_behavior == "control_tower_cross_account":
            return "Control Tower governance - required for multi-account management"
        elif expected_behavior == "identity_center_wildcards":
            return "Identity Center SSO - required for centralized access management"
        elif expected_behavior == "account_factory_permissions":
            return "Account Factory automation - required for account provisioning"
    
    # Check if this is an AWS service role with detailed context
    service_info = is_aws_service_role(role_name)
    if service_info:
        service_name = service_info["description"]
        function = service_info["function"]
        return f"{service_name} - {function}"
    
    # Check for specific service dependencies based on content
    row_str = str(row).lower()
    if "passrole" in row_str:
        if "admin" in row_str or "*" in row_str:
            return "High privilege PassRole - review service necessity and scope"
        else:
            return "PassRole permission - verify service requirement and least privilege"
    
    if "assumerole" in row_str and "cross" in row_str:
        return "Cross-account access - verify business requirement and add conditions"
    
    return "No service dependency identified - standard security review required"

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
    service_info = is_aws_service_role(role_name)
    if service_info:
        return f"AWS SERVICE ROLE: '{role_name}' is used by {service_info['description']}. {service_info['function']}. Verify this configuration is required before making changes."
    
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
        service_info = is_aws_service_role(role_name)
        if service_info:
            return f"INFORMATIONAL: '{role_name}' is used by {service_info['description']}. Wildcard permissions are required for service functionality. No action needed."
        
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
        service_info = is_aws_service_role(role_name)
        if service_info:
            return f"INFORMATIONAL: '{role_name}' is used by {service_info['description']}. Cross-account access is required for service functionality. No action needed."
        
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
    service_info = is_aws_service_role(role_name)
    
    # Check for critical patterns
    for pattern_name, pattern_info in CRITICAL_PATTERNS.items():
        if any(keyword in row_text or keyword in filename_lower for keyword in pattern_info["keywords"]):
            problem_summary = generate_problem_summary(row, filename, pattern_name)
            actionable_response = generate_actionable_response(pattern_name, row, filename)
            
            # Reduce severity for AWS service roles
            severity = pattern_info["severity"]
            if service_info:
                if severity == "CRITICAL":
                    severity = "LOW"  # Service roles with expected permissions
                elif severity == "HIGH":
                    severity = "LOW"
            
            return {
                "severity": severity,
                "reason": pattern_info["description"] + (f" ({service_info['description']})" if service_info else ""),
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
            
            # Get service dependency - try multiple role name fields
            role_for_dependency = (
                key_info.get("RoleName") or 
                key_info.get("Role Name") or 
                key_info.get("EntityName") or 
                row.get("RoleName") or 
                row.get("Role Name") or 
                row.get("EntityName") or 
                ""
            )
            service_dependency = get_service_dependency(severity_info["pattern"], row, role_for_dependency)
            
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
    
    # Get top critical findings
    critical_findings = [f for f in findings if f["Severity"] == "CRITICAL"]
    summary["top_critical"] = critical_findings
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
            f.write(f"TOP {min(len(summary['top_critical']), max_items)} CRITICAL FINDINGS (IMMEDIATE ATTENTION)\n")
            f.write("-" * 50 + "\n")
            for i, finding in enumerate(summary['top_critical'][:max_items], 1):
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
                for i, finding in enumerate(critical_findings[:max_items//2], 1):
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
                    f.write(f"      Service Dependency: {finding.get('ServiceDependency', 'None identified')}\n")
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
            
            for i, finding in enumerate(high_priority_findings[:max_items], 1):
                f.write(f"{i}. {finding.get('ProblemSummary', finding['Reason'])}\n")
                
                # Show key details
                key_details = []
                for key in ["RoleName", "Resource", "Title", "Path", "Principal"]:
                    if key in finding and finding[key]:
                        key_details.append(f"{key}: {finding[key]}")
                
                if key_details:
                    f.write(f"   Details: {' | '.join(key_details[:3])}\n")
                
                f.write(f"   Impact: {finding['Reason']}\n")
                f.write(f"   Service Dependency: {finding.get('ServiceDependency', 'None identified')}\n")
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
                for i, finding in enumerate(critical_chains[:max_items//2], 1):
                    path = finding.get('Path') or finding.get('Chain') or 'Unknown path'
                    target = finding.get('Target Privileged Role') or finding.get('TargetPrivilegedRole') or 'Admin role'
                    f.write(f"{i}. {path} -> {target}\n")
                    f.write(f"   Service Dependency: {finding.get('ServiceDependency', 'None identified')}\n")
                    f.write(f"   Action: {finding.get('ActionableResponse', 'Review escalation path')}\n\n")
            
            if high_chains:
                f.write(f"HIGH RISK ESCALATION CHAINS ({len(high_chains)}):\n")
                for i, finding in enumerate(high_chains[:max_items//3], 1):
                    path = finding.get('Path') or finding.get('Chain') or 'Unknown path'
                    target = finding.get('Target Privileged Role') or finding.get('TargetPrivilegedRole') or 'Privileged role'
                    f.write(f"{i}. {path} -> {target}\n")
                    f.write(f"   Service Dependency: {finding.get('ServiceDependency', 'None identified')}\n")
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

def generate_html_report(summary, output_file, max_items):
    """Generate HTML version of the priority report"""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AWS Security Audit - Priority Findings Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #2c3e50; border-left: 4px solid #3498db; padding-left: 15px; }}
        .critical {{ background-color: #ffebee; border-left: 4px solid #f44336; padding: 15px; margin: 10px 0; }}
        .high {{ background-color: #fff3e0; border-left: 4px solid #ff9800; padding: 15px; margin: 10px 0; }}
        .expected {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; padding: 15px; margin: 10px 0; }}
        .finding {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .finding-title {{ font-weight: bold; color: #2c3e50; margin-bottom: 10px; }}
        .finding-details {{ color: #666; margin: 5px 0; }}
        .action {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 10px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 20px; background-color: #ecf0f1; border-radius: 8px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AWS Security Audit - Priority Findings Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{summary['total_count']}</div>
                    <div>Total Findings</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{summary['non_trusted_advisor_count']}</div>
                    <div>Security Findings</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{summary['critical_count']}</div>
                    <div>Critical Findings</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{summary['high_count']}</div>
                    <div>High Priority</div>
                </div>
            </div>
        </div>
"""

    # Top Critical Findings
    if summary['top_critical']:
        html_content += f"""
        <div class="section">
            <h2>Top {min(len(summary['top_critical']), max_items)} Critical Findings</h2>
"""
        for i, finding in enumerate(summary['top_critical'][:max_items], 1):
            severity_class = "expected" if "EXPECTED BEHAVIOR" in finding.get('ActionableResponse', '') or "AWS SERVICE ROLE" in finding.get('ActionableResponse', '') else "critical"
            
            html_content += f"""
            <div class="finding {severity_class}">
                <div class="finding-title">{i}. {finding.get('ProblemSummary', finding['Reason'])}</div>
"""
            
            # Show key details
            key_details = []
            for key in ["RoleName", "Resource", "Title", "Path", "Principal"]:
                if key in finding and finding[key]:
                    key_details.append(f"{key}: {finding[key]}")
            
            if key_details:
                html_content += f'<div class="finding-details"><strong>Details:</strong> {" | ".join(key_details[:3])}</div>'
            
            html_content += f"""
                <div class="finding-details"><strong>Source:</strong> {finding.get('SourceFile', 'unknown')}</div>
                <div class="finding-details"><strong>Impact:</strong> {finding['Reason']}</div>
                <div class="finding-details"><strong>Service Dependency:</strong> {finding.get('ServiceDependency', 'None identified')}</div>
                <div class="action"><strong>Action:</strong> {finding.get('ActionableResponse', 'Review and remediate')}</div>
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
    parser = argparse.ArgumentParser(description="Generate priority security findings report")
    parser.add_argument("--data-dir", default=".", help="Directory containing CSV files")
    parser.add_argument("--output", default="PRIORITY_SECURITY_REPORT.txt", help="Output report file")
    parser.add_argument("--max", type=int, default=20, help="Maximum number of items to show in each section")
    parser.add_argument("--html", action="store_true", help="Generate HTML report in addition to text report")
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
    generate_readable_report(summary, args.output, args.max)
    
    # Generate HTML report if requested
    if args.html:
        html_output = args.output.replace('.txt', '.html')
        generate_html_report(summary, html_output, args.max)
        print(f"[SUCCESS] HTML report generated: {html_output}")
    
    print(f"\n[SUCCESS] Priority report generated: {args.output}")
    print(f"[INFO] Total findings analyzed: {summary['total_count']}")
    print(f"[INFO] Critical findings: {summary['critical_count']}")
    print(f"[INFO] High priority findings: {summary['high_count']}")
    
    if summary['critical_count'] > 0:
        print(f"\n*** WARNING: {summary['critical_count']} CRITICAL findings require immediate attention! ***")

if __name__ == "__main__":
    main()