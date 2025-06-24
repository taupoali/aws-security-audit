import subprocess
import json
import csv
import sys

def run_aws_cli(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running AWS CLI: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def get_security_check_ids():
    cmd = [
        "aws", "support", "describe-trusted-advisor-checks",
        "--language", "en"
    ]
    output = run_aws_cli(cmd)
    checks = output.get("checks", [])
    return [check for check in checks if check["category"] == "security"]

def get_check_result(check_id):
    cmd = [
        "aws", "support", "describe-trusted-advisor-check-result",
        "--check-id", check_id,
        "--language", "en"
    ]
    return run_aws_cli(cmd)

def write_results_to_csv(checks_with_results, output_file):
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Check Name", "Resource ID", "Status", "Metadata"])

        for check_name, results in checks_with_results:
            flagged = results.get("result", {}).get("flaggedResources", [])
            for resource in flagged:
                writer.writerow([
                    check_name,
                    resource.get("resourceId", ""),
                    resource.get("status", ""),
                    " | ".join(resource.get("metadata", []))
                ])

def main():
    print("Fetching Trusted Advisor security checks...")
    security_checks = get_security_check_ids()

    results = []
    for check in security_checks:
        check_id = check["id"]
        check_name = check["name"]
        print(f"Processing check: {check_name}")
        result = get_check_result(check_id)
        results.append((check_name, result))

    output_file = "trusted_advisor_security_report.csv"
    write_results_to_csv(results, output_file)
    print(f"Report written to {output_file}")

if __name__ == "__main__":
    main()
