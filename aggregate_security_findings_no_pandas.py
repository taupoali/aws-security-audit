#!/usr/bin/env python3

import csv
import glob
import os
import argparse
from datetime import datetime
from collections import defaultdict, Counter

# Risk scoring matrix
RISK_SCORES = {
    # IAM Risks
    "escalation_chains": {"weight": 10, "category": "IAM"},
    "elevated_privileges": {"weight": 8, "category": "IAM"},
    "cross_account_findings": {"weight": 7, "category": "IAM"},
    
    # Public Resources
    "public_resources_analysis": {"weight": 9, "category": "Exposure"},
    "public_resources_report": {"weight": 9, "category": "Exposure"},
    
    # Monitoring Gaps
    "monitoring_findings": {"weight": 6, "category": "Monitoring"},
    "config_rules": {"weight": 5, "category": "Compliance"},
    
    # Security Hub
    "securityhub_failed_findings": {"weight": 7, "category": "Compliance"},
    "access_analyzer_findings": {"weight": 8, "category": "Access"}
}

def find_csv_files(directory):
    """Find all CSV files and categorize them"""
    csv_files = {}
    
    for pattern, config in RISK_SCORES.items():
        files = glob.glob(os.path.join(directory, f"*{pattern}*.csv"))
        if files:
            csv_files[pattern] = files
    
    return csv_files

def load_csv_data(file_path):
    """Load CSV data as list of dictionaries"""
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []

def extract_account_id(data, filename):
    """Extract account ID from data or filename"""
    if data and "AccountId" in data[0]:
        return data[0]["AccountId"]
    
    # Try to extract from filename (common patterns)
    if "account" in filename.lower():
        parts = filename.split("_")
        for part in parts:
            if part.isdigit() and len(part) == 12:
                return part
    
    return "unknown"

def calculate_risk_score(row, base_weight):
    """Calculate risk score based on content"""
    base_score = base_weight
    row_str = str(row).lower()
    
    # Boost score for critical findings
    if any(keyword in row_str for keyword in ["critical", "high", "admin", "public", "*"]):
        base_score += 3
    
    # Boost for privilege escalation
    if "escalation" in row_str or "chain" in row_str:
        base_score += 2
    
    # Boost for failed compliance
    if "failed" in row_str or "non_compliant" in row_str:
        base_score += 1
    
    return min(10, base_score)

def process_findings(csv_files):
    """Process all CSV files and create enriched findings"""
    all_findings = []
    
    for pattern, files in csv_files.items():
        config = RISK_SCORES[pattern]
        print(f"[INFO] Processing {len(files)} {pattern} files...")
        
        for file_path in files:
            filename = os.path.basename(file_path)
            data = load_csv_data(file_path)
            
            if not data:
                continue
            
            account_id = extract_account_id(data, filename)
            
            for row in data:
                # Add metadata
                enriched_row = row.copy()
                enriched_row["SourceFile"] = filename
                enriched_row["RiskCategory"] = config["category"]
                enriched_row["RiskWeight"] = config["weight"]
                enriched_row["AccountId"] = account_id
                enriched_row["RiskScore"] = calculate_risk_score(row, config["weight"])
                
                all_findings.append(enriched_row)
    
    return all_findings

def sort_findings_by_risk(findings):
    """Sort findings by risk score (highest first)"""
    return sorted(findings, key=lambda x: int(x.get("RiskScore", 0)), reverse=True)

def generate_executive_summary(findings):
    """Generate executive summary statistics"""
    if not findings:
        return {}
    
    total_findings = len(findings)
    critical_findings = len([f for f in findings if int(f.get("RiskScore", 0)) >= 9])
    high_findings = len([f for f in findings if int(f.get("RiskScore", 0)) >= 7])
    
    # Count unique accounts
    accounts = set(f.get("AccountId", "unknown") for f in findings)
    accounts_affected = len(accounts)
    
    # Calculate risk by category
    category_risks = defaultdict(int)
    for finding in findings:
        category = finding.get("RiskCategory", "Unknown")
        risk_score = int(finding.get("RiskScore", 0))
        category_risks[category] += risk_score
    
    # Sort categories by total risk
    top_risks = sorted(category_risks.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "accounts_affected": accounts_affected,
        "top_risks": top_risks
    }

def create_action_plan(findings):
    """Create prioritized action plan"""
    critical_findings = [f for f in findings if int(f.get("RiskScore", 0)) >= 9]
    high_findings = [f for f in findings if int(f.get("RiskScore", 0)) >= 7]
    
    actions = []
    
    # Group critical findings by category
    critical_by_category = defaultdict(list)
    for finding in critical_findings:
        category = finding.get("RiskCategory", "Unknown")
        critical_by_category[category].append(finding)
    
    # Create critical actions
    for category, cat_findings in critical_by_category.items():
        accounts = set(f.get("AccountId", "unknown") for f in cat_findings)
        actions.append({
            "Priority": "CRITICAL",
            "Category": category,
            "Count": len(cat_findings),
            "Timeline": "Immediate (0-7 days)",
            "Action": f"Address {len(cat_findings)} critical {category.lower()} findings",
            "Accounts": ", ".join(sorted(accounts))
        })
    
    # Group high findings by category (excluding those already in critical)
    high_by_category = defaultdict(list)
    for finding in high_findings:
        category = finding.get("RiskCategory", "Unknown")
        if category not in critical_by_category:  # Don't duplicate
            high_by_category[category].append(finding)
    
    # Create high priority actions
    for category, cat_findings in high_by_category.items():
        accounts = set(f.get("AccountId", "unknown") for f in cat_findings)
        actions.append({
            "Priority": "HIGH",
            "Category": category,
            "Count": len(cat_findings),
            "Timeline": "Short-term (7-30 days)",
            "Action": f"Remediate {len(cat_findings)} high-risk {category.lower()} issues",
            "Accounts": ", ".join(sorted(accounts))
        })
    
    return actions

def write_csv(data, filename, fieldnames=None):
    """Write data to CSV file"""
    if not data:
        print(f"[WARNING] No data to write to {filename}")
        return
    
    if not fieldnames:
        # Get all possible fieldnames from data
        fieldnames = set()
        for row in data:
            fieldnames.update(row.keys())
        fieldnames = sorted(list(fieldnames))
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Aggregate and prioritize AWS security findings")
    parser.add_argument("--data-dir", default=".", help="Directory containing CSV files")
    parser.add_argument("--output", default="security_findings_summary", help="Output file prefix")
    args = parser.parse_args()
    
    print(f"[INFO] Scanning for CSV files in: {args.data_dir}")
    
    # Find all CSV files
    csv_files = find_csv_files(args.data_dir)
    
    if not csv_files:
        print("[ERROR] No recognized CSV files found")
        return
    
    total_files = sum(len(files) for files in csv_files.values())
    print(f"[INFO] Found {total_files} CSV files")
    
    # Process all findings
    all_findings = process_findings(csv_files)
    
    if not all_findings:
        print("[ERROR] No data loaded from CSV files")
        return
    
    # Sort by risk score
    all_findings = sort_findings_by_risk(all_findings)
    
    # Generate outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Master findings file
    master_file = f"{args.output}_master_{timestamp}.csv"
    write_csv(all_findings, master_file)
    print(f"[INFO] Master findings saved to: {master_file}")
    
    # 2. Executive summary
    summary = generate_executive_summary(all_findings)
    
    # 3. Action plan
    action_plan = create_action_plan(all_findings)
    action_file = f"{args.output}_action_plan_{timestamp}.csv"
    action_fieldnames = ["Priority", "Category", "Count", "Timeline", "Action", "Accounts"]
    write_csv(action_plan, action_file, action_fieldnames)
    print(f"[INFO] Action plan saved to: {action_file}")
    
    # 4. Top 20 critical findings
    top_critical = all_findings[:20]
    critical_file = f"{args.output}_top_critical_{timestamp}.csv"
    write_csv(top_critical, critical_file)
    print(f"[INFO] Top critical findings saved to: {critical_file}")
    
    # 5. Summary report
    summary_file = f"{args.output}_executive_summary_{timestamp}.txt"
    with open(summary_file, 'w') as f:
        f.write("=== AWS SECURITY AUDIT EXECUTIVE SUMMARY ===\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total Findings: {summary['total_findings']}\n")
        f.write(f"Critical Findings: {summary['critical_findings']}\n")
        f.write(f"High Risk Findings: {summary['high_findings']}\n")
        f.write(f"Accounts Affected: {summary['accounts_affected']}\n\n")
        
        f.write("=== TOP RISK CATEGORIES ===\n")
        for category, score in summary['top_risks']:
            f.write(f"{category}: {score} total risk points\n")
        
        f.write("\n=== IMMEDIATE ACTIONS REQUIRED ===\n")
        critical_actions = [a for a in action_plan if a["Priority"] == "CRITICAL"]
        for action in critical_actions:
            f.write(f"• {action['Action']} across {action['Accounts'].count(',') + 1} accounts\n")
    
    print(f"[INFO] Executive summary saved to: {summary_file}")
    
    # Print summary to console
    print("\n=== EXECUTIVE SUMMARY ===")
    print(f"Total Findings: {summary['total_findings']}")
    print(f"Critical Findings: {summary['critical_findings']}")
    print(f"High Risk Findings: {summary['high_findings']}")
    print(f"Accounts Affected: {summary['accounts_affected']}")
    
    print("\n=== TOP RISK CATEGORIES ===")
    for category, score in summary['top_risks']:
        print(f"{category}: {score} total risk points")
    
    print("\n=== IMMEDIATE ACTIONS REQUIRED ===")
    critical_actions = [a for a in action_plan if a["Priority"] == "CRITICAL"]
    for action in critical_actions:
        account_count = action['Accounts'].count(',') + 1 if action['Accounts'] else 0
        print(f"• {action['Action']} across {account_count} accounts")

if __name__ == "__main__":
    main()