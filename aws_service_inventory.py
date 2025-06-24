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

def run_aws_command(cmd, account=None, profile=None, region=None, retries=3):
    """Run AWS CLI command with retries and caching"""
    # Modify command for specific account/profile
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    # Add region if specified
    if region and "--region" not in cmd:
        cmd.insert(1, "--region")
        cmd.insert(2, region)
    
    cmd_key = ' '.join(cmd)
    if cmd_key in API_CACHE:
        API_STATS["cached"] += 1
        return API_CACHE[cmd_key]
    
    API_STATS["calls"] += 1
    
    # Backoff parameters
    base_delay = 2.0  # Start with 2 seconds
    max_delay = 30.0  # Maximum delay of 30 seconds
    
    # Track previous errors to avoid repeating the same command with the same error
    last_error = None
    
    # Special case for S3 bucket policy - don't retry NoSuchBucketPolicy errors
    is_get_bucket_policy = "s3api" in cmd and "get-bucket-policy" in cmd
    
    for attempt in range(retries + 1):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            API_CACHE[cmd_key] = result.stdout
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip()
            
            # Special handling for NoSuchBucketPolicy - this is normal for buckets without policies
            if is_get_bucket_policy and "NoSuchBucketPolicy" in error_msg:
                API_STATS["calls"] += 1  # Count as a successful call
                return None  # Just return None without retrying
            
            # Don't retry the same error multiple times
            if last_error == error_msg:
                API_STATS["errors"] += 1
                return None
                
            last_error = error_msg
            
            if "AccessDenied" in error_msg or "UnauthorizedOperation" in error_msg:
                print(f"Access denied: {error_msg}")
                return None
                
            if attempt < retries:
                # True exponential backoff with jitter
                delay = min(max_delay, base_delay * (2 ** attempt))
                # Add jitter (±20%)
                jitter = delay * 0.2 * ((time.time() % 1) - 0.5)
                actual_delay = delay + jitter
                
                # Create a more informative command summary
                service = cmd[1] if len(cmd) > 1 else "unknown"
                operation = cmd[2] if len(cmd) > 2 else "unknown"
                
                print(f"[RETRY {attempt+1}/{retries}] {service} {operation} after {actual_delay:.1f}s: {error_msg}")
                time.sleep(actual_delay)
            else:
                API_STATS["errors"] += 1
                return None
        except subprocess.TimeoutExpired:
            API_STATS["timeouts"] += 1
            if attempt < retries:
                # Use same exponential backoff for timeouts
                delay = min(max_delay, base_delay * (2 ** attempt))
                # Add jitter (±20%)
                jitter = delay * 0.2 * ((time.time() % 1) - 0.5)
                actual_delay = delay + jitter
                
                print(f"[TIMEOUT {attempt+1}/{retries}] Retrying after {actual_delay:.1f}s")
                time.sleep(actual_delay)
            else:
                return None
    return None

def get_account_id(profile=None):
    """Get AWS account ID"""
    cmd = ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"]
    if profile:
        cmd = ["aws", "--profile", profile, "sts", "get-caller-identity", "--query", "Account", "--output", "text"]
    
    result = run_aws_command(cmd)
    return result.strip() if result else "unknown"

def get_regions(profile=None):
    """Get list of all AWS regions"""
    cmd = ["aws", "ec2", "describe-regions", "--query", "Regions[].RegionName", "--output", "json"]
    if profile:
        cmd = ["aws", "--profile", profile, "ec2", "describe-regions", "--query", "Regions[].RegionName", "--output", "json"]
    
    result = run_aws_command(cmd)
    if result:
        return json.loads(result)
    return ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1"]

def inventory_service(service_name, detect_fn, account, profile, regions):
    """Inventory a specific AWS service"""
    print(f"[INFO] Inventorying {service_name} in account {account}...")
    results = []
    
    for region in regions:
        try:
            region_results = detect_fn(region, profile)
            if region_results:
                for resource in region_results:
                    resource["AccountId"] = account
                    resource["Region"] = region
                    resource["Service"] = service_name
                results.extend(region_results)
                print(f"[INFO] Found {len(region_results)} {service_name} resources in {region}")
        except Exception as e:
            print(f"[ERROR] Failed to inventory {service_name} in {region}: {e}")
    
    return results

def detect_ec2_instances(region, profile=None):
    """Detect EC2 instances"""
    cmd = ["aws", "ec2", "describe-instances", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile=profile, region=region)
    if not result:
        return []
    
    instances = []
    reservations = json.loads(result).get("Reservations", [])
    
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            # Get name tag
            name = "Unnamed"
            for tag in instance.get("Tags", []):
                if tag.get("Key") == "Name":
                    name = tag.get("Value")
                    break
            
            # Check if public
            public_ip = instance.get("PublicIpAddress")
            is_public = bool(public_ip)
            
            instances.append({
                "ResourceId": instance.get("InstanceId"),
                "ResourceName": name,
                "ResourceType": "EC2 Instance",
                "IsPublic": is_public,
                "PublicEndpoint": public_ip,
                "State": instance.get("State", {}).get("Name")
            })
    
    return instances

def detect_s3_buckets(region, profile=None):
    """Detect S3 buckets"""
    # S3 is global but we'll only run this in one region
    if region != "us-east-1":
        return []
    
    cmd = ["aws", "s3api", "list-buckets", "--output", "json"]
    result = run_aws_command(cmd, profile=profile)
    if not result:
        return []
    
    buckets = []
    bucket_list = json.loads(result).get("Buckets", [])
    
    for bucket in bucket_list:
        bucket_name = bucket.get("Name")
        is_public = False
        public_reason = None
        
        # Check if bucket is public via ACL
        try:
            acl_cmd = ["aws", "s3api", "get-bucket-acl", "--bucket", bucket_name, "--output", "json"]
            acl_result = run_aws_command(acl_cmd, profile=profile)
            
            if acl_result:
                acl = json.loads(acl_result)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        is_public = True
                        public_reason = "Public ACL"
                        break
        except Exception as e:
            print(f"[WARN] Error checking ACL for bucket {bucket_name}: {str(e)[:100]}")
        
        # Check bucket policy for public access - with direct subprocess call to avoid retries
        if not is_public:
            try:
                policy_cmd = ["aws", "s3api", "get-bucket-policy", "--bucket", bucket_name, "--output", "json"]
                if profile:
                    policy_cmd = ["aws", "--profile", profile, "s3api", "get-bucket-policy", "--bucket", bucket_name, "--output", "json"]
                
                # Run directly with subprocess, no retries
                result = subprocess.run(policy_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    policy_str = json.loads(result.stdout).get("Policy", "{}")
                    if '"Principal": "*"' in policy_str or '"Principal":{"AWS":"*"}' in policy_str:
                        is_public = True
                        public_reason = "Public Policy"
            except Exception:
                # Silently ignore errors for bucket policy - this is expected for many buckets
                pass
        
        buckets.append({
            "ResourceId": bucket_name,
            "ResourceName": bucket_name,
            "ResourceType": "S3 Bucket",
            "IsPublic": is_public,
            "PublicReason": public_reason,
            "PublicEndpoint": f"https://{bucket_name}.s3.amazonaws.com" if is_public else None,
            "State": "Available"
        })
    
    return buckets
    
    return buckets

def detect_rds_instances(region, profile=None):
    """Detect RDS instances"""
    cmd = ["aws", "rds", "describe-db-instances", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile=profile, region=region)
    if not result:
        return []
    
    instances = []
    db_instances = json.loads(result).get("DBInstances", [])
    
    for instance in db_instances:
        is_public = instance.get("PubliclyAccessible", False)
        endpoint = instance.get("Endpoint", {})
        
        instances.append({
            "ResourceId": instance.get("DBInstanceIdentifier"),
            "ResourceName": instance.get("DBName", instance.get("DBInstanceIdentifier")),
            "ResourceType": "RDS Instance",
            "IsPublic": is_public,
            "PublicEndpoint": f"{endpoint.get('Address')}:{endpoint.get('Port')}" if is_public and endpoint else None,
            "State": instance.get("DBInstanceStatus")
        })
    
    return instances

def detect_load_balancers(region, profile=None):
    """Detect load balancers (ALB, NLB, CLB)"""
    results = []
    
    # Check ALB and NLB
    cmd = ["aws", "elbv2", "describe-load-balancers", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile=profile, region=region)
    if result:
        lbs = json.loads(result).get("LoadBalancers", [])
        for lb in lbs:
            is_public = lb.get("Scheme") == "internet-facing"
            
            results.append({
                "ResourceId": lb.get("LoadBalancerName"),
                "ResourceName": lb.get("LoadBalancerName"),
                "ResourceType": f"{lb.get('Type')} Load Balancer",
                "IsPublic": is_public,
                "PublicEndpoint": lb.get("DNSName") if is_public else None,
                "State": lb.get("State", {}).get("Code")
            })
    
    # Check Classic ELB
    cmd = ["aws", "elb", "describe-load-balancers", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile=profile, region=region)
    if result:
        lbs = json.loads(result).get("LoadBalancerDescriptions", [])
        for lb in lbs:
            is_public = lb.get("Scheme") == "internet-facing"
            
            results.append({
                "ResourceId": lb.get("LoadBalancerName"),
                "ResourceName": lb.get("LoadBalancerName"),
                "ResourceType": "Classic ELB",
                "IsPublic": is_public,
                "PublicEndpoint": lb.get("DNSName") if is_public else None,
                "State": "Active"  # Classic ELBs don't have a state field
            })
    
    return results

def detect_api_gateways(region, profile=None):
    """Detect API Gateway endpoints"""
    cmd = ["aws", "apigateway", "get-rest-apis", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile=profile, region=region)
    if not result:
        return []
    
    apis = []
    api_list = json.loads(result).get("items", [])
    
    for api in api_list:
        # API Gateway REST APIs are public by default
        apis.append({
            "ResourceId": api.get("id"),
            "ResourceName": api.get("name"),
            "ResourceType": "API Gateway",
            "IsPublic": True,
            "PublicEndpoint": f"https://{api.get('id')}.execute-api.{region}.amazonaws.com",
            "State": api.get("endpointConfiguration", {}).get("types", ["EDGE"])[0]
        })
    
    return apis

def detect_lambda_functions(region, profile=None):
    """Detect Lambda functions"""
    cmd = ["aws", "lambda", "list-functions", "--region", region, "--output", "json"]
    result = run_aws_command(cmd, profile=profile, region=region)
    if not result:
        return []
    
    functions = []
    function_list = json.loads(result).get("Functions", [])
    
    for function in function_list:
        # Check if function has a public policy
        is_public = False
        public_endpoint = None
        
        policy_cmd = ["aws", "lambda", "get-policy", "--function-name", function.get("FunctionName"), "--region", region, "--output", "json"]
        try:
            policy_result = run_aws_command(policy_cmd, profile=profile, region=region)
            if policy_result:
                policy = json.loads(policy_result).get("Policy", "{}")
                if isinstance(policy, str):
                    policy = json.loads(policy)
                
                for statement in policy.get("Statement", []):
                    principal = statement.get("Principal", {})
                    if principal == "*" or principal.get("AWS") == "*" or principal.get("Service") == "apigateway.amazonaws.com":
                        is_public = True
                        break
        except:
            pass
        
        functions.append({
            "ResourceId": function.get("FunctionName"),
            "ResourceName": function.get("FunctionName"),
            "ResourceType": "Lambda Function",
            "IsPublic": is_public,
            "PublicEndpoint": public_endpoint,
            "State": function.get("State")
        })
    
    return functions

def inventory_account(account_name, profile, regions=None):
    """Inventory all services in an AWS account"""
    print(f"[INFO] Starting inventory for account: {account_name} (profile: {profile})")
    
    # Get account ID
    account_id = get_account_id(profile)
    if account_id == "unknown":
        print(f"[ERROR] Failed to get account ID for profile {profile}")
        return []
    
    # Get regions if not provided
    if not regions:
        regions = get_regions(profile)
    
    print(f"[INFO] Account ID: {account_id}")
    print(f"[INFO] Scanning {len(regions)} regions: {', '.join(regions)}")
    
    # Define services to inventory
    services = [
        ("EC2", detect_ec2_instances),
        ("S3", detect_s3_buckets),
        ("RDS", detect_rds_instances),
        ("LoadBalancer", detect_load_balancers),
        ("APIGateway", detect_api_gateways),
        ("Lambda", detect_lambda_functions)
    ]
    
    # Inventory all services
    all_resources = []
    for service_name, detect_fn in services:
        service_resources = inventory_service(service_name, detect_fn, account_id, profile, regions)
        all_resources.extend(service_resources)
    
    print(f"[INFO] Found {len(all_resources)} resources in account {account_name}")
    return all_resources

def export_to_csv(resources, filename):
    """Export resources to CSV file"""
    if not resources:
        print(f"[WARNING] No resources to export to {filename}")
        return
    
    # Get all fields from resources
    fields = set()
    for resource in resources:
        fields.update(resource.keys())
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=sorted(fields))
        writer.writeheader()
        writer.writerows(resources)
    
    print(f"[INFO] Exported {len(resources)} resources to {filename}")

def main():
    parser = argparse.ArgumentParser(description="AWS Service Inventory Tool")
    parser.add_argument("--accounts", nargs="+", help="List of account names to inventory")
    parser.add_argument("--profiles", nargs="+", help="List of AWS profiles to use (must match accounts)")
    parser.add_argument("--regions", nargs="+", help="List of regions to scan (default: all regions)")
    parser.add_argument("--output", default="aws_inventory.csv", help="Output CSV file")
    args = parser.parse_args()
    
    start_time = datetime.now()
    print(f"[{start_time}] Starting AWS service inventory...")
    
    # Validate arguments
    if not args.accounts or not args.profiles:
        print("[ERROR] Both --accounts and --profiles are required")
        return
    
    if len(args.accounts) != len(args.profiles):
        print("[ERROR] Number of accounts must match number of profiles")
        return
    
    # Inventory all accounts
    all_resources = []
    for account_name, profile in zip(args.accounts, args.profiles):
        account_resources = inventory_account(account_name, profile, args.regions)
        all_resources.extend(account_resources)
    
    # Export results
    export_to_csv(all_resources, args.output)
    
    # Print summary
    public_resources = [r for r in all_resources if r.get("IsPublic")]
    print("\n=== Inventory Summary ===")
    print(f"Total resources: {len(all_resources)}")
    print(f"Public resources: {len(public_resources)}")
    
    # Group by service
    services = {}
    for resource in all_resources:
        service = resource.get("Service")
        if service not in services:
            services[service] = {"total": 0, "public": 0}
        services[service]["total"] += 1
        if resource.get("IsPublic"):
            services[service]["public"] += 1
    
    print("\nResources by service:")
    for service, counts in services.items():
        print(f"  {service}: {counts['total']} total, {counts['public']} public")
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[{end_time}] Inventory completed. Duration: {duration}")

if __name__ == "__main__":
    main()