import subprocess
import json
import csv
import sys
import argparse

def run_aws_cli(cmd, profile=None):
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running AWS CLI: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def get_failed_findings(profile=None):
    filters = {
        "ComplianceStatus": [
            {"Value": "FAILED", "Comparison": "EQUALS"}
        ]
    }

    cmd = [
        "aws", "securityhub", "get-findings",
        "--filters", json.dumps(filters),
        "--max-results", "100"
    ]

    findings = []
    response = run_aws_cli(cmd, profile)
    findings.extend(response.get("Findings", []))

    while "NextToken" in response:
        cmd_with_token = cmd + ["--next-token", response["NextToken"]]
        response = run_aws_cli(cmd_with_token, profile)
        findings.extend(response.get("Findings", []))

    return findings

def write_findings_to_csv(findings, output_file, split_resources):
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Region",
            "Title",
            "Severity",
            "Compliance Status",
            "Resource Type",
            "Resource ID",
            "First Observed",
            "Last Updated",
            "Description"
        ])

        for finding in findings:
            region = finding.get("Region", "")
            title = finding.get("Title", "")
            severity = finding.get("Severity", {}).get("Label", "")
            compliance_status = finding.get("Compliance", {}).get("Status", "")
            first_observed = finding.get("FirstObservedAt", "")
            updated_at = finding.get("UpdatedAt", "")
            description = finding.get("Description", "")
            resources = finding.get("Resources", [])

            if split_resources:
                for res in resources:
                    res_type = res.get("Type", "")
                    res_id = res.get("Id", "")
                    writer.writerow([
                        region,
                        title,
                        severity,
                        compliance_status,
                        res_type,
                        res_id,
                        first_observed,
                        updated_at,
                        description
                    ])
            else:
                res_types = " | ".join([r.get("Type", "") for r in resources])
                res_ids = " | ".join([r.get("Id", "") for r in resources])
                writer.writerow([
                    region,
                    title,
                    severity,
                    compliance_status,
                    res_types,
                    res_ids,
                    first_observed,
                    updated_at,
                    description
                ])

def main():
    parser = argparse.ArgumentParser(description="Export AWS Security Hub FAILED findings to CSV.")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--split-resources", action="store_true", help="Output each resource on a separate row.")
    args = parser.parse_args()

    print("Fetching FAILED Security Hub findings...")
    if args.profile:
        print(f"Using AWS profile: {args.profile}")
    findings = get_failed_findings(args.profile)
    print(f"Total findings fetched: {len(findings)}")

    from datetime import datetime

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_file = f"securityhub_failed_findings_{timestamp}.csv"

    write_findings_to_csv(findings, output_file, args.split_resources)
    print(f"Report written to {output_file}")

if __name__ == "__main__":
    main()
