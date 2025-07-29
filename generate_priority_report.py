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

def generate_actionable_response(pattern, row, filename):
    """Generate actionable response for each finding type"""
    filename_lower = filename.lower()
    role_name = row.get("RoleName") or row.get("Role Name") or row.get("EntityName") or "Unknown"
    resource = row.get("Resource") or row.get("ResourceId") or row.get("Resource ID") or ""
    
    if pattern == "privilege_escalation":
        return f"Remove unnecessary role assumption permissions or add conditions to trust policies for '{role_name}'"
    
    elif pattern == "public_admin_access":
        if "s3" in filename_lower:
            return f"Remove public access from S3 bucket '{resource}' and implement least-privilege bucket policies"
        else:
            return f"Remove public access permissions and implement IP restrictions or MFA requirements"
    
    elif pattern == "failed_compliance":
        if "security" in filename_lower:
            return "Review and remediate the specific Security Hub finding according to AWS security best practices"
        elif "config" in filename_lower:
            return "Update resource configuration to comply with AWS Config rule requirements"
        else:
            return "Address compliance violation by implementing required security controls"
    
    elif pattern == "external_access":
        return f"Review external access necessity for '{role_name}' and add conditions (MFA, IP, ExternalId) to trust policy"
    
    else:
        return "Review finding details and implement appropriate security controls based on the specific issue"

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
    
    # Check for critical patterns
    for pattern_name, pattern_info in CRITICAL_PATTERNS.items():
        if any(keyword in row_text or keyword in filename_lower for keyword in pattern_info["keywords"]):
            problem_summary = generate_problem_summary(row, filename, pattern_name)
            actionable_response = generate_actionable_response(pattern_name, row, filename)
            return {
                "severity": pattern_info["severity"],
                "reason": pattern_info["description"],
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
            
            finding = {
                "Severity": severity_info["severity"],
                "Reason": severity_info["reason"],
                "Pattern": severity_info["pattern"],
                "ProblemSummary": severity_info["problem_summary"],
                "ActionableResponse": severity_info["actionable_response"],
                **key_info
            }
            
            all_findings.append(finding)
    
    return all_findings

def create_priority_summary(findings):
    """Create a prioritized summary of findings"""
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["Severity"], 4))
    
    # Group by severity and pattern
    summary = {
        "critical_count": len([f for f in findings if f["Severity"] == "CRITICAL"]),
        "high_count": len([f for f in findings if f["Severity"] == "HIGH"]),
        "total_count": len(findings),
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
    
    # Get top 10 critical findings
    critical_findings = [f for f in findings if f["Severity"] == "CRITICAL"]
    summary["top_critical"] = critical_findings[:10]
    summary["all_findings"] = findings
    
    return summary

def generate_readable_report(summary, output_file):
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
        f.write(f"Critical Findings: {summary['critical_count']}\n")
        f.write(f"High Priority Findings: {summary['high_count']}\n\n")
        
        if summary['critical_count'] > 0:
            f.write("*** IMMEDIATE ACTION REQUIRED - CRITICAL FINDINGS DETECTED ***\n\n")
        
        # Top Critical Findings
        if summary['top_critical']:
            f.write("TOP 10 CRITICAL FINDINGS (IMMEDIATE ATTENTION)\n")
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
                f.write(f"   Action: {finding.get('ActionableResponse', 'Review and remediate')}\n\n")n\n")
        
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
        
        f.write("\n")
        
        # Findings by Source File with top critical finding
        f.write("FINDINGS BY AUDIT COMPONENT\n")
        f.write("-" * 30 + "\n")
        
        # Group findings by source file
        findings_by_source = defaultdict(list)
        for finding in summary.get('all_findings', []):
            source = finding.get('SourceFile', 'unknown')
            findings_by_source[source].append(finding)
        
        sorted_sources = sorted(summary['by_source'].items(), key=lambda x: x[1], reverse=True)
        for source, count in sorted_sources[:10]:
            f.write(f"{source}: {count} findings\n")
            
            # Find most critical finding in this source
            source_findings = findings_by_source.get(source, [])
            if source_findings:
                # Sort by severity
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                source_findings.sort(key=lambda x: severity_order.get(x["Severity"], 4))
                top_finding = source_findings[0]
                
                f.write(f"   Most Critical: {top_finding.get('ProblemSummary', 'Unknown issue')}\n")
                f.write(f"   Severity: {top_finding['Severity']}\n")
            f.write("\n")
        
        f.write("\n")
        
        # Action Plan
        f.write("RECOMMENDED ACTION PLAN\n")
        f.write("-" * 25 + "\n")
        
        if summary['critical_count'] > 0:
            f.write("PHASE 1 - IMMEDIATE (0-7 days):\n")
            f.write(f"• Address all {summary['critical_count']} CRITICAL findings\n")
            f.write("• Focus on privilege escalation and public admin access\n")
            f.write("• Implement emergency access controls if needed\n\n")
        
        if summary['high_count'] > 0:
            f.write("PHASE 2 - SHORT TERM (1-4 weeks):\n")
            f.write(f"• Remediate {summary['high_count']} HIGH priority findings\n")
            f.write("• Review and strengthen access controls\n")
            f.write("• Implement additional monitoring\n\n")
        
        f.write("PHASE 3 - ONGOING:\n")
        f.write("• Regular security audits using these tools\n")
        f.write("• Continuous monitoring implementation\n")
        f.write("• Security awareness training\n\n")
        
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