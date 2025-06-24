#!/usr/bin/env python3

import json
import csv
import argparse
import os
from datetime import datetime

# Risk scoring constants
RISK_LEVELS = {
    "Critical": (80, 100),
    "High": (60, 79),
    "Medium": (40, 59),
    "Low": (0, 39)
}

# Service-specific risk factors
SERVICE_RISK_FACTORS = {
    "EC2 Instance": 70,
    "S3 Bucket": 80,
    "RDS Instance": 75,
    "API Gateway": 65,
    "Lambda Function": 60,
    "ALB Load Balancer": 60,
    "NLB Load Balancer": 65,
    "Classic ELB": 70,
    "OpenSearch Domain": 75,
    "Redshift Cluster": 80,
    "EKS Cluster": 75,
    "DocumentDB Cluster": 75,
    "ElastiCache": 70,
    "Neptune Cluster": 70,
    "MemoryDB Cluster": 70
}

# Default risk factor for services not explicitly listed
DEFAULT_RISK_FACTOR = 50

def load_inventory(filename):
    """Load inventory data from CSV file"""
    if not os.path.exists(filename):
        print(f"[ERROR] Inventory file not found: {filename}")
        return []
    
    resources = []
    with open(filename, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Convert string "True"/"False" to boolean
            if "IsPublic" in row:
                row["IsPublic"] = row["IsPublic"].lower() == "true"
            resources.append(row)
    
    print(f"[INFO] Loaded {len(resources)} resources from {filename}")
    return resources

def calculate_risk_score(resource):
    """Calculate risk score for a resource"""
    # Only calculate risk for public resources
    if not resource.get("IsPublic", False):
        return 0
    
    # Base risk score from service type
    resource_type = resource.get("ResourceType", "Unknown")
    base_risk = SERVICE_RISK_FACTORS.get(resource_type, DEFAULT_RISK_FACTOR)
    
    # Adjust risk based on additional factors
    risk_score = base_risk
    
    # Adjust for specific services
    if resource_type == "S3 Bucket":
        # Higher risk if bucket has a public policy
        if resource.get("PublicEndpoint"):
            risk_score += 10
    
    elif resource_type == "EC2 Instance":
        # Higher risk for running instances
        if resource.get("State") == "running":
            risk_score += 10
    
    elif "Load Balancer" in resource_type:
        # Higher risk for load balancers with HTTP (not HTTPS)
        if resource.get("PublicEndpoint") and "http://" in resource.get("PublicEndpoint", ""):
            risk_score += 15
    
    elif resource_type == "RDS Instance":
        # Higher risk for certain database engines
        engine = resource.get("Engine", "").lower()
        if engine in ["mysql", "postgresql", "oracle"]:
            risk_score += 5
    
    # Cap risk score at 100
    return min(100, risk_score)

def determine_risk_level(score):
    """Determine risk level based on score"""
    for level, (min_score, max_score) in RISK_LEVELS.items():
        if min_score <= score <= max_score:
            return level
    return "Unknown"

def generate_mitigation_recommendations(resource, risk_level):
    """Generate mitigation recommendations based on resource type and risk level"""
    resource_type = resource.get("ResourceType", "Unknown")
    recommendations = []
    
    # General recommendation for all public resources
    if risk_level in ["Critical", "High"]:
        recommendations.append("Consider restricting public access if not absolutely necessary")
    
    # Service-specific recommendations
    if resource_type == "S3 Bucket":
        recommendations.append("Enable S3 Block Public Access at the bucket and account level")
        recommendations.append("Use bucket policies that restrict access to specific IP ranges or VPCs")
        recommendations.append("Enable S3 server-side encryption")
        recommendations.append("Enable S3 versioning to protect against accidental deletion")
    
    elif resource_type == "EC2 Instance":
        recommendations.append("Use security groups to restrict access to specific IP ranges")
        recommendations.append("Place instances in private subnets and use a load balancer or bastion host")
        recommendations.append("Implement network ACLs as an additional layer of security")
    
    elif "RDS Instance" in resource_type:
        recommendations.append("Move database to a private subnet and use VPC endpoints")
        recommendations.append("Enable encryption at rest")
        recommendations.append("Use IAM database authentication where possible")
    
    elif "Load Balancer" in resource_type:
        recommendations.append("Use HTTPS listeners with modern TLS configurations")
        recommendations.append("Implement AWS WAF for web application firewalls")
        recommendations.append("Configure security groups to allow only necessary ports")
    
    elif "API Gateway" in resource_type:
        recommendations.append("Implement API keys and usage plans")
        recommendations.append("Use AWS WAF to protect against common web exploits")
        recommendations.append("Implement request throttling")
        recommendations.append("Use AWS Cognito or custom authorizers for authentication")
    
    elif "Lambda Function" in resource_type:
        recommendations.append("Implement proper IAM roles with least privilege")
        recommendations.append("Use API Gateway with authorization for public-facing functions")
        recommendations.append("Implement input validation to prevent injection attacks")
    
    return recommendations

def analyze_public_resources(resources):
    """Analyze public resources and their risk posture"""
    public_resources = [r for r in resources if r.get("IsPublic", False)]
    print(f"[INFO] Analyzing {len(public_resources)} public resources...")
    
    analysis_results = []
    for resource in public_resources:
        # Calculate risk score
        risk_score = calculate_risk_score(resource)
        risk_level = determine_risk_level(risk_score)
        
        # Generate mitigation recommendations
        recommendations = generate_mitigation_recommendations(resource, risk_level)
        
        # Create analysis result
        analysis_results.append({
            "AccountId": resource.get("AccountId", "Unknown"),
            "Region": resource.get("Region", "Unknown"),
            "Service": resource.get("Service", "Unknown"),
            "ResourceType": resource.get("ResourceType", "Unknown"),
            "ResourceId": resource.get("ResourceId", "Unknown"),
            "ResourceName": resource.get("ResourceName", "Unknown"),
            "PublicEndpoint": resource.get("PublicEndpoint", "N/A"),
            "RiskScore": risk_score,
            "RiskLevel": risk_level,
            "Recommendations": "; ".join(recommendations)
        })
    
    # Sort by risk score (descending)
    analysis_results.sort(key=lambda x: x["RiskScore"], reverse=True)
    return analysis_results

def export_to_csv(results, filename):
    """Export analysis results to CSV file"""
    if not results:
        print(f"[WARNING] No results to export to {filename}")
        return
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    
    print(f"[INFO] Exported {len(results)} results to {filename}")

def generate_html_report(results, filename):
    """Generate HTML report with analysis results"""
    if not results:
        print(f"[WARNING] No results to include in HTML report {filename}")
        return
    
    # Count resources by risk level
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for result in results:
        risk_level = result.get("RiskLevel")
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1
    
    # Generate HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Public Resource Risk Analysis</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #232F3E; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #232F3E; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .critical {{ background-color: #ff9999; }}
            .high {{ background-color: #ffcc99; }}
            .medium {{ background-color: #ffffcc; }}
            .low {{ background-color: #ccffcc; }}
            .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .summary-box {{ padding: 10px; border-radius: 5px; width: 20%; text-align: center; }}
        </style>
    </head>
    <body>
        <h1>AWS Public Resource Risk Analysis</h1>
        <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <div class="summary-box critical">
                <h3>Critical</h3>
                <p>{risk_counts["Critical"]}</p>
            </div>
            <div class="summary-box high">
                <h3>High</h3>
                <p>{risk_counts["High"]}</p>
            </div>
            <div class="summary-box medium">
                <h3>Medium</h3>
                <p>{risk_counts["Medium"]}</p>
            </div>
            <div class="summary-box low">
                <h3>Low</h3>
                <p>{risk_counts["Low"]}</p>
            </div>
        </div>
        
        <h2>Public Resources by Risk Level</h2>
        <table>
            <tr>
                <th>Account</th>
                <th>Region</th>
                <th>Resource Type</th>
                <th>Resource Name</th>
                <th>Public Endpoint</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
            </tr>
    """
    
    # Add rows for each result
    for result in results:
        risk_class = result.get("RiskLevel", "").lower()
        html += f"""
            <tr class="{risk_class}">
                <td>{result.get("AccountId", "")}</td>
                <td>{result.get("Region", "")}</td>
                <td>{result.get("ResourceType", "")}</td>
                <td>{result.get("ResourceName", "")}</td>
                <td>{result.get("PublicEndpoint", "")}</td>
                <td>{result.get("RiskScore", "")}</td>
                <td>{result.get("RiskLevel", "")}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <h2>Mitigation Recommendations</h2>
        <table>
            <tr>
                <th>Resource Type</th>
                <th>Resource Name</th>
                <th>Risk Level</th>
                <th>Recommendations</th>
            </tr>
    """
    
    # Add rows for recommendations
    for result in results:
        risk_class = result.get("RiskLevel", "").lower()
        html += f"""
            <tr class="{risk_class}">
                <td>{result.get("ResourceType", "")}</td>
                <td>{result.get("ResourceName", "")}</td>
                <td>{result.get("RiskLevel", "")}</td>
                <td>{result.get("Recommendations", "").replace("; ", "<br>")}</td>
            </tr>
        """
    
    html += """
        </table>
    </body>
    </html>
    """
    
    with open(filename, 'w') as f:
        f.write(html)
    
    print(f"[INFO] Generated HTML report: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Analyze public AWS resources and their risk posture")
    parser.add_argument("--inventory", required=True, help="Path to inventory CSV file")
    parser.add_argument("--csv", default="public_resources_analysis.csv", help="Output CSV file (set to 'none' to disable)")
    parser.add_argument("--html", default="public_resources_report.html", help="Output HTML report (set to 'none' to disable)")
    parser.add_argument("--output-all", action="store_true", help="Generate both CSV and HTML outputs")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting public resource analysis...")
    
    # Load inventory
    resources = load_inventory(args.inventory)
    if not resources:
        return
    
    # Analyze public resources
    analysis_results = analyze_public_resources(resources)
    
    # Export results
    if args.csv.lower() != "none":
        export_to_csv(analysis_results, args.csv)
    
    if args.html.lower() != "none":
        generate_html_report(analysis_results, args.html)
    
    # If output-all is specified, ensure both outputs are generated
    if args.output_all:
        if args.csv.lower() == "none":
            export_to_csv(analysis_results, "public_resources_analysis.csv")
        if args.html.lower() == "none":
            generate_html_report(analysis_results, "public_resources_report.html")
    
    # Print summary
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for result in analysis_results:
        risk_level = result.get("RiskLevel")
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1
    
    print("\n=== Risk Analysis Summary ===")
    print(f"Total public resources: {len(analysis_results)}")
    for level, count in risk_counts.items():
        print(f"{level} risk: {count}")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Analysis completed. Duration: {duration}")

if __name__ == "__main__":
    main()