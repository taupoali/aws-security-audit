#!/usr/bin/env python3

import pandas as pd
import glob
import os
import argparse
from datetime import datetime

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

def load_and_tag_data(file_path, category, risk_weight):
    """Load CSV and add metadata"""
    try:
        df = pd.read_csv(file_path)
        
        # Extract account info from filename or path
        filename = os.path.basename(file_path)
        account_id = "unknown"
        
        # Try to extract account ID from filename or data
        if "AccountId" in df.columns:
            account_id = df["AccountId"].iloc[0] if not df.empty else "unknown"
        
        # Add metadata columns
        df["SourceFile"] = filename
        df["RiskCategory"] = category
        df["RiskWeight"] = risk_weight
        df["AccountId"] = account_id
        
        return df
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return pd.DataFrame()

def calculate_risk_score(row):
    """Calculate risk score based on content"""
    base_score = row.get("RiskWeight", 5)
    
    # Boost score for critical findings
    if any(keyword in str(row).lower() for keyword in ["critical", "high", "admin", "public", "*"]):
        base_score += 3
    
    # Boost for privilege escalation
    if "escalation" in str(row).lower() or "chain" in str(row).lower():
        base_score += 2
    
    return min(10, base_score)

def generate_executive_summary(all_findings):
    """Generate executive summary"""
    summary = {
        "total_findings": len(all_findings),
        "critical_findings": len(all_findings[all_findings["RiskScore"] >= 9]),
        "high_findings": len(all_findings[all_findings["RiskScore"] >= 7]),
        "accounts_affected": all_findings["AccountId"].nunique(),
        "top_risks": all_findings.groupby("RiskCategory")["RiskScore"].sum().sort_values(ascending=False).head(5)
    }
    return summary

def create_action_plan(all_findings):
    """Create prioritized action plan"""
    # Group by risk score and category
    critical = all_findings[all_findings["RiskScore"] >= 9].copy()
    high = all_findings[all_findings["RiskScore"] >= 7].copy()
    
    actions = []
    
    # Critical actions (immediate)
    if not critical.empty:
        for category in critical["RiskCategory"].unique():
            cat_findings = critical[critical["RiskCategory"] == category]
            actions.append({
                "Priority": "CRITICAL",
                "Category": category,
                "Count": len(cat_findings),
                "Timeline": "Immediate (0-7 days)",
                "Action": f"Address {len(cat_findings)} critical {category.lower()} findings",
                "Accounts": list(cat_findings["AccountId"].unique())
            })
    
    # High priority actions (30 days)
    if not high.empty:
        for category in high["RiskCategory"].unique():
            if category not in critical["RiskCategory"].unique():  # Don't duplicate
                cat_findings = high[high["RiskCategory"] == category]
                actions.append({
                    "Priority": "HIGH",
                    "Category": category,
                    "Count": len(cat_findings),
                    "Timeline": "Short-term (7-30 days)",
                    "Action": f"Remediate {len(cat_findings)} high-risk {category.lower()} issues",
                    "Accounts": list(cat_findings["AccountId"].unique())
                })
    
    return pd.DataFrame(actions)

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
    
    print(f"[INFO] Found {sum(len(files) for files in csv_files.values())} CSV files")
    
    # Load and combine all data
    all_findings = pd.DataFrame()
    
    for pattern, files in csv_files.items():
        config = RISK_SCORES[pattern]
        print(f"[INFO] Processing {len(files)} {pattern} files...")
        
        for file_path in files:
            df = load_and_tag_data(file_path, config["category"], config["weight"])
            if not df.empty:
                all_findings = pd.concat([all_findings, df], ignore_index=True)
    
    if all_findings.empty:
        print("[ERROR] No data loaded from CSV files")
        return
    
    # Calculate risk scores
    all_findings["RiskScore"] = all_findings.apply(calculate_risk_score, axis=1)
    
    # Sort by risk score
    all_findings = all_findings.sort_values("RiskScore", ascending=False)
    
    # Generate outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Master findings file
    master_file = f"{args.output}_master_{timestamp}.csv"
    all_findings.to_csv(master_file, index=False)
    print(f"[INFO] Master findings saved to: {master_file}")
    
    # 2. Executive summary
    summary = generate_executive_summary(all_findings)
    
    # 3. Action plan
    action_plan = create_action_plan(all_findings)
    action_file = f"{args.output}_action_plan_{timestamp}.csv"
    action_plan.to_csv(action_file, index=False)
    print(f"[INFO] Action plan saved to: {action_file}")
    
    # 4. Top 20 critical findings
    top_critical = all_findings.head(20)
    critical_file = f"{args.output}_top_critical_{timestamp}.csv"
    top_critical.to_csv(critical_file, index=False)
    print(f"[INFO] Top critical findings saved to: {critical_file}")
    
    # Print summary
    print("\n=== EXECUTIVE SUMMARY ===")
    print(f"Total Findings: {summary['total_findings']}")
    print(f"Critical Findings: {summary['critical_findings']}")
    print(f"High Risk Findings: {summary['high_findings']}")
    print(f"Accounts Affected: {summary['accounts_affected']}")
    
    print("\n=== TOP RISK CATEGORIES ===")
    for category, score in summary['top_risks'].items():
        print(f"{category}: {score:.1f} total risk points")
    
    print("\n=== IMMEDIATE ACTIONS REQUIRED ===")
    critical_actions = action_plan[action_plan["Priority"] == "CRITICAL"]
    for _, action in critical_actions.iterrows():
        print(f"• {action['Action']} across {len(action['Accounts'])} accounts")

if __name__ == "__main__":
    main()