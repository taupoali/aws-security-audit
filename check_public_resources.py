#!/usr/bin/env python3

import subprocess
import json
import sys
import os
import csv
import time
import threading
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


def run_command(command, profile=None):
    """Execute a shell command and return the output"""
    # Add profile to AWS commands if specified
    if profile and command.startswith("aws "):
        command = command.replace("aws ", f"aws --profile {profile} ", 1)
    
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        # Common AWS CLI errors to suppress
        common_errors = [
            "NoSuchEntity", "NoSuchBucket", "NoSuchKey", "AccessDenied", 
            "UnauthorizedOperation", "ValidationError", "InvalidParameterValue",
            "ResourceNotFoundException", "OperationNotPermitted", "ServiceUnavailable"
        ]
        
        # Check if error contains any of the common errors
        if any(error in e.stderr for error in common_errors):
            return None
            
        # For debugging, uncomment this line
        # print(f"Error executing command: {command}\nError message: {e.stderr}")
        return None


def get_regions():
    """Get list of all AWS regions"""
    try:
        # Get only enabled regions
        cmd = "aws account list-regions --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            # Extract only enabled regions
            enabled_regions = []
            for region in data.get('Regions', []):
                if region.get('RegionOptStatus') == 'ENABLED' or region.get('RegionOptStatus') == 'ENABLED_BY_DEFAULT':
                    enabled_regions.append(region.get('RegionName'))
            
            if enabled_regions:
                print(f"Found {len(enabled_regions)} enabled regions")
                return enabled_regions
        
        # Fallback to EC2 describe-regions if account list-regions fails
        cmd = "aws ec2 describe-regions --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            # Extract region names from the response
            if 'Regions' in data:
                regions = [region['RegionName'] for region in data['Regions']]
                print("Warning: Could not determine which regions are enabled. Checking all available regions.")
                return regions
            
        # Fallback to hardcoded list of common regions if API calls fail
        print("Warning: Could not retrieve regions via API, using default region list")
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
            "ap-south-1", "sa-east-1", "ca-central-1"
        ]
    except Exception as e:
        print(f"Error getting regions: {e}")
        return ["us-east-1"]  # Default to us-east-1 if we can't get regions

# Service check functions
def check_ec2_instances_with_public_ips(region):
    """Find EC2 instances with public IPs"""
    results = []
    try:
        # Get all EC2 instances and filter in Python instead of using query
        cmd = f"aws ec2 describe-instances --region {region} --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            reservations = data.get('Reservations', [])
            
            for reservation in reservations:
                instances = reservation.get('Instances', [])
                for instance in instances:
                    # Check if instance has a public IP and is running
                    if instance.get('PublicIpAddress') and instance.get('State', {}).get('Name') == 'running':
                        instance_id = instance.get('InstanceId', 'Unknown')
                        public_ip = instance.get('PublicIpAddress', 'N/A')
                        
                        # Extract Name tag if it exists
                        name = "No Name"
                        for tag in instance.get('Tags', []):
                            if tag.get('Key') == 'Name' and tag.get('Value'):
                                name = tag.get('Value')
                                break
                        
                        results.append({
                            "ResourceType": "EC2 Instance",
                            "Region": region,
                            "ResourceId": instance_id,
                            "Name": name,
                            "PublicIP": public_ip
                        })
    except Exception as e:
        print(f"Error checking EC2 instances in {region}: {e}")
    return results


def check_security_groups_with_open_ingress(region):
    """Find security groups with open ingress rules (0.0.0.0/0)"""
    results = []
    try:
        cmd = f"aws ec2 describe-security-groups --region {region} --query \"SecurityGroups[*].{{ID:GroupId,Name:GroupName,VPC:VpcId,Rules:IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0')]}}\" --output json"
        output = run_command(cmd)
        if output:
            sgs = json.loads(output)
            for sg in sgs:
                if sg["Rules"]:
                    for rule in sg["Rules"]:
                        protocol = rule.get("IpProtocol", "All")
                        from_port = rule.get("FromPort", "All")
                        to_port = rule.get("ToPort", "All")
                        
                        # Format port range
                        if protocol == "-1":
                            protocol = "All"
                            port_range = "All"
                        elif from_port == to_port:
                            port_range = str(from_port)
                        else:
                            port_range = f"{from_port}-{to_port}"
                            
                        results.append({
                            "ResourceType": "Security Group",
                            "Region": region,
                            "ResourceId": sg["ID"],
                            "Name": sg["Name"],
                            "VPC": sg["VPC"],
                            "Protocol": protocol,
                            "Ports": port_range,
                            "Source": "0.0.0.0/0"
                        })
    except Exception as e:
        print(f"Error checking security groups in {region}: {e}")
    return results


def check_public_s3_buckets():
    """Find S3 buckets with public access"""
    results = []
    try:
        # Get list of buckets
        buckets_output = run_command("aws s3api list-buckets --query 'Buckets[*].Name' --output json")
        if not buckets_output:
            return results
            
        buckets = json.loads(buckets_output)
        
        for bucket in buckets:
            # Check bucket public access block settings
            block_cmd = f"aws s3api get-public-access-block --bucket {bucket} --output json 2>/dev/null"
            try:
                block_result = subprocess.run(block_cmd, shell=True, text=True, capture_output=True)
                if block_result.returncode == 0 and block_result.stdout:
                    block_config = json.loads(block_result.stdout).get('PublicAccessBlockConfiguration', {})
                    # If all block settings are True, skip further checks
                    if (block_config.get('BlockPublicAcls', False) and 
                        block_config.get('BlockPublicPolicy', False) and
                        block_config.get('IgnorePublicAcls', False) and
                        block_config.get('RestrictPublicBuckets', False)):
                        continue
            except Exception:
                pass  # No block config or error reading it
            
            # Check bucket policy
            policy_cmd = f"aws s3api get-bucket-policy --bucket {bucket} --output json 2>/dev/null"
            try:
                result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                if result.returncode == 0 and result.stdout:
                    policy = json.loads(result.stdout)
                    if '"Principal": "*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                        results.append({
                            "ResourceType": "S3 Bucket",
                            "ResourceId": bucket,
                            "Issue": "Public access in bucket policy"
                        })
                        continue
            except Exception:
                pass  # No policy or error reading policy
                
            # Check ACL
            acl_cmd = f"aws s3api get-bucket-acl --bucket {bucket} --output json 2>/dev/null"
            try:
                acl_result = subprocess.run(acl_cmd, shell=True, text=True, capture_output=True)
                if acl_result.returncode == 0 and acl_result.stdout:
                    acl = json.loads(acl_result.stdout)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            results.append({
                                "ResourceType": "S3 Bucket",
                                "ResourceId": bucket,
                                "Issue": "Public access in ACL"
                            })
                            break
            except Exception:
                pass  # Error reading ACL
    except Exception as e:
        print(f"Error checking S3 buckets: {e}")
    return results


def check_public_rds_instances(region):
    """Find RDS instances that are publicly accessible"""
    results = []
    try:
        # Get all RDS instances and filter in Python instead of using query
        cmd = f"aws rds describe-db-instances --region {region} --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            instances = data.get('DBInstances', [])
            
            for instance in instances:
                if instance.get('PubliclyAccessible', False):
                    instance_id = instance.get('DBInstanceIdentifier', 'Unknown')
                    endpoint = instance.get('Endpoint', {}).get('Address', 'N/A')
                    engine = instance.get('Engine', 'N/A')
                    
                    results.append({
                        "ResourceType": "RDS Instance",
                        "Region": region,
                        "ResourceId": instance_id,
                        "Endpoint": endpoint,
                        "Engine": engine
                    })
    except Exception as e:
        print(f"Error checking RDS instances in {region}: {e}")
    return results

def check_internet_facing_load_balancers(region):
    """Find internet-facing load balancers"""
    results = []
    try:
        # Check ALBs and NLBs without using query parameter
        cmd = f"aws elbv2 describe-load-balancers --region {region} --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            load_balancers = data.get('LoadBalancers', [])
            
            for lb in load_balancers:
                if lb.get('Scheme') == 'internet-facing':
                    results.append({
                        "ResourceType": f"{lb.get('Type', 'Unknown')} Load Balancer",
                        "Region": region,
                        "ResourceId": lb.get('LoadBalancerName', 'Unknown'),
                        "DNSName": lb.get('DNSName', 'N/A')
                    })
                
        # Check Classic ELBs without using query parameter
        cmd = f"aws elb describe-load-balancers --region {region} --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            classic_lbs = data.get('LoadBalancerDescriptions', [])
            
            for lb in classic_lbs:
                if lb.get('Scheme') == 'internet-facing':
                    results.append({
                        "ResourceType": "Classic ELB",
                        "Region": region,
                        "ResourceId": lb.get('LoadBalancerName', 'Unknown'),
                        "DNSName": lb.get('DNSName', 'N/A')
                    })
    except Exception as e:
        print(f"Error checking load balancers in {region}: {e}")
    return results


def check_api_gateway_endpoints(region):
    """Find API Gateway endpoints"""
    results = []
    try:
        # Get list of APIs
        cmd = f"aws apigateway get-rest-apis --region {region} --output json"
        output = run_command(cmd)
        if output:
            apis = json.loads(output).get('items', [])
            for api in apis:
                # Get stages for each API
                stages_cmd = f"aws apigateway get-stages --region {region} --rest-api-id {api['id']} --output json"
                stages_output = run_command(stages_cmd)
                if stages_output:
                    stages = json.loads(stages_output).get('item', [])
                    for stage in stages:
                        results.append({
                            "ResourceType": "API Gateway",
                            "Region": region,
                            "ResourceId": api['id'],
                            "Name": api['name'],
                            "Stage": stage['stageName'],
                            "URL": f"https://{api['id']}.execute-api.{region}.amazonaws.com/{stage['stageName']}"
                        })
    except Exception as e:
        print(f"Error checking API Gateway in {region}: {e}")
    return results


def check_sns_topics_public_access(region):
    """Find SNS topics with public access policies"""
    results = []
    try:
        # List all SNS topics
        cmd = f"aws sns list-topics --region {region} --output json"
        output = run_command(cmd)
        if output:
            topics = json.loads(output).get('Topics', [])
            if not topics:  # Handle empty topics list
                return []
                
            for topic in topics:
                topic_arn = topic['TopicArn']
                
                # Get topic attributes including policy
                attr_cmd = f"aws sns get-topic-attributes --topic-arn {topic_arn} --region {region} --output json"
                attr_output = run_command(attr_cmd)
                if attr_output:
                    attributes = json.loads(attr_output).get('Attributes', {})
                    if 'Policy' in attributes:
                        policy = attributes['Policy']
                        
                        # Check for public access
                        if '"Principal": "*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                            results.append({
                                "ResourceType": "SNS Topic",
                                "Region": region,
                                "ResourceId": topic_arn.split(':')[-1],
                                "ARN": topic_arn,
                                "Issue": "Public access in policy"
                            })
    except Exception as e:
        print(f"Error checking SNS topics in {region}: {e}")
    return results


def check_sqs_queues_public_access(region):
    """Find SQS queues with public access policies"""
    results = []
    try:
        # List all SQS queues
        cmd = f"aws sqs list-queues --region {region} --output json"
        output = run_command(cmd)
        if output and 'QueueUrls' in json.loads(output):
            queues = json.loads(output)['QueueUrls']
            for queue_url in queues:
                # Get queue attributes including policy
                attr_cmd = f"aws sqs get-queue-attributes --queue-url {queue_url} --attribute-names Policy --region {region} --output json"
                attr_output = run_command(attr_cmd)
                if attr_output:
                    attributes = json.loads(attr_output).get('Attributes', {})
                    if 'Policy' in attributes:
                        policy = attributes['Policy']
                        
                        # Check for public access
                        if '"Principal": "*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                            queue_name = queue_url.split('/')[-1]
                            results.append({
                                "ResourceType": "SQS Queue",
                                "Region": region,
                                "ResourceId": queue_name,
                                "URL": queue_url,
                                "Issue": "Public access in policy"
                            })
    except Exception as e:
        print(f"Error checking SQS queues in {region}: {e}")
    return results


# Additional service checks
def check_opensearch_domains(region):
    """Find OpenSearch domains with public access"""
    results = []
    try:
        # List all OpenSearch domains
        cmd = f"aws opensearch list-domain-names --region {region} --output json"
        output = run_command(cmd)
        if output:
            domains = json.loads(output).get('DomainNames', [])
            for domain in domains:
                domain_name = domain['DomainName']
                
                # Get domain config
                config_cmd = f"aws opensearch describe-domain --domain-name {domain_name} --region {region} --output json"
                config_output = run_command(config_cmd)
                if config_output:
                    domain_config = json.loads(config_output).get('DomainStatus', {})
                    
                    # Check if publicly accessible
                    if domain_config.get('AccessPolicies'):
                        policies = domain_config['AccessPolicies']
                        if '"Principal": "*"' in policies or '"Principal":{"AWS":"*"}' in policies:
                            results.append({
                                "ResourceType": "OpenSearch Domain",
                                "Region": region,
                                "ResourceId": domain_name,
                                "Endpoint": domain_config.get('Endpoint', 'N/A'),
                                "Issue": "Public access in policy"
                            })
    except Exception as e:
        print(f"Error checking OpenSearch domains in {region}: {e}")
    return results

def check_rds_snapshots_public(region):
    """Find publicly shared RDS snapshots"""
    results = []
    try:
        # Check DB snapshots without using query parameter
        cmd = f"aws rds describe-db-snapshots --region {region} --include-shared --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            snapshots = data.get('DBSnapshots', [])
            
            for snapshot in snapshots:
                if snapshot.get('SnapshotType') == 'public':
                    results.append({
                        "ResourceType": "RDS Snapshot",
                        "Region": region,
                        "ResourceId": snapshot.get('DBSnapshotIdentifier', 'Unknown'),
                        "DBInstance": snapshot.get('DBInstanceIdentifier', 'N/A'),
                        "Engine": snapshot.get('Engine', 'N/A'),
                        "Issue": "Publicly shared snapshot"
                    })
                
        # Check cluster snapshots without using query parameter
        cmd = f"aws rds describe-db-cluster-snapshots --region {region} --include-shared --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            cluster_snapshots = data.get('DBClusterSnapshots', [])
            
            for snapshot in cluster_snapshots:
                if snapshot.get('SnapshotType') == 'public':
                    results.append({
                        "ResourceType": "RDS Cluster Snapshot",
                        "Region": region,
                        "ResourceId": snapshot.get('DBClusterSnapshotIdentifier', 'Unknown'),
                        "DBCluster": snapshot.get('DBClusterIdentifier', 'N/A'),
                        "Engine": snapshot.get('Engine', 'N/A'),
                        "Issue": "Publicly shared snapshot"
                    })
    except Exception as e:
        print(f"Error checking RDS snapshots in {region}: {e}")
    return results


def check_public_lambda_functions(region):
    """Find Lambda functions with public access"""
    results = []
    try:
        # Get list of Lambda functions
        cmd = f"aws lambda list-functions --region {region} --output json"
        output = run_command(cmd)
        if output:
            functions = json.loads(output).get('Functions', [])
            for function in functions:
                # Check if function has a public policy - don't use run_command for this since we expect errors
                policy_cmd = f"aws lambda get-policy --function-name {function['FunctionName']} --region {region} --output json 2>/dev/null"
                try:
                    result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                    if result.returncode == 0 and result.stdout:
                        policy = json.loads(result.stdout).get('Policy', '{}')
                        if '"Principal": "*"' in policy or '"AWS": "*"' in policy:
                            results.append({
                                "ResourceType": "Lambda Function",
                                "Region": region,
                                "ResourceId": function['FunctionName'],
                                "ARN": function['FunctionArn'],
                                "Issue": "Public access policy"
                            })
                except Exception:
                    pass  # No policy or error reading policy
    except Exception as e:
        print(f"Error checking Lambda functions in {region}: {e}")
    return results

def check_public_ecr_repositories():
    """Find ECR repositories with public access"""
    results = []
    try:
        # Get list of ECR repositories
        cmd = "aws ecr describe-repositories --output json"
        output = run_command(cmd)
        if output:
            repos = json.loads(output).get('repositories', [])
            for repo in repos:
                # Check repository policy - don't use run_command for this since we expect errors
                policy_cmd = f"aws ecr get-repository-policy --repository-name {repo['repositoryName']} --output json 2>/dev/null"
                try:
                    result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                    if result.returncode == 0 and result.stdout:
                        policy_output = result.stdout
                        policy = json.loads(policy_output).get('policyText', '{}')
                        if isinstance(policy, str):
                            policy = json.loads(policy)
                        
                        # Check for public access in policy
                        for statement in policy.get('Statement', []):
                            principal = statement.get('Principal', {})
                            if principal == "*" or principal.get('AWS') == "*":
                                results.append({
                                    "ResourceType": "ECR Repository",
                                    "ResourceId": repo['repositoryName'],
                                    "ARN": repo['repositoryArn'],
                                    "Issue": "Public access in policy"
                                })
                                break
                except Exception:
                    pass  # No policy or error reading policy
    except Exception as e:
        print(f"Error checking ECR repositories: {e}")
    return results

def check_public_eks_clusters(region):
    """Find EKS clusters with public endpoint access"""
    results = []
    try:
        # Get list of EKS clusters
        cmd = f"aws eks list-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('clusters', [])
            for cluster_name in clusters:
                # Get cluster details
                details_cmd = f"aws eks describe-cluster --name {cluster_name} --region {region} --output json"
                details_output = run_command(details_cmd)
                if details_output:
                    cluster = json.loads(details_output).get('cluster', {})
                    if cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False):
                        results.append({
                            "ResourceType": "EKS Cluster",
                            "Region": region,
                            "ResourceId": cluster_name,
                            "Endpoint": cluster.get('endpoint', 'N/A'),
                            "Issue": "Public endpoint access enabled"
                        })
    except Exception as e:
        print(f"Error checking EKS clusters in {region}: {e}")
    return results

def check_public_opensearch_domains(region):
    """Find OpenSearch domains with public access"""
    results = []
    try:
        # Get list of OpenSearch domains
        cmd = f"aws opensearch list-domain-names --region {region} --output json"
        output = run_command(cmd)
        if output:
            domains = json.loads(output).get('DomainNames', [])
            for domain in domains:
                domain_name = domain.get('DomainName')
                # Get domain config
                config_cmd = f"aws opensearch describe-domain-config --domain-name {domain_name} --region {region} --output json"
                config_output = run_command(config_cmd)
                if config_output:
                    config = json.loads(config_output).get('DomainConfig', {})
                    access_policies = config.get('AccessPolicies', {}).get('Options', '{}')
                    if isinstance(access_policies, str):
                        try:
                            access_policies = json.loads(access_policies)
                        except:
                            access_policies = {}
                    
                    # Check for public access in policy
                    for statement in access_policies.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if principal == "*" or principal.get('AWS') == "*":
                            # Get domain details for endpoint
                            details_cmd = f"aws opensearch describe-domain --domain-name {domain_name} --region {region} --output json"
                            details_output = run_command(details_cmd)
                            endpoint = "N/A"
                            if details_output:
                                details = json.loads(details_output).get('DomainStatus', {})
                                endpoint = details.get('Endpoint', 'N/A')
                            
                            results.append({
                                "ResourceType": "OpenSearch Domain",
                                "Region": region,
                                "ResourceId": domain_name,
                                "Endpoint": endpoint,
                                "Issue": "Public access in policy"
                            })
                            break
    except Exception as e:
        print(f"Error checking OpenSearch domains in {region}: {e}")
    return results

def check_cloudfront_distributions():
    """Find CloudFront distributions"""
    results = []
    try:
        # CloudFront is a global service, so no region is needed
        cmd = "aws cloudfront list-distributions --output json"
        output = run_command(cmd)
        if output:
            distributions_data = json.loads(output)
            # Check if there are any distributions
            if 'DistributionList' not in distributions_data or 'Items' not in distributions_data['DistributionList']:
                return results
                
            distributions = distributions_data['DistributionList']['Items']
            for dist in distributions:
                if dist.get('Enabled', False):  # Only include enabled distributions
                    # Safely extract origin domain
                    origin_domain = "N/A"
                    if 'Origins' in dist and 'Items' in dist['Origins'] and len(dist['Origins']['Items']) > 0:
                        origin_domain = dist['Origins']['Items'][0].get('DomainName', 'N/A')
                        
                    results.append({
                        "ResourceType": "CloudFront Distribution",
                        "Region": "global",
                        "ResourceId": dist.get('Id', 'Unknown'),
                        "DomainName": dist.get('DomainName', 'N/A'),
                        "OriginDomain": origin_domain
                    })
    except Exception as e:
        print(f"Error checking CloudFront distributions: {e}")
    return results

def check_public_redshift_clusters(region):
    """Find publicly accessible Redshift clusters"""
    results = []
    try:
        # Get all Redshift clusters and filter in Python instead of using query
        cmd = f"aws redshift describe-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            clusters = data.get('Clusters', [])
            
            for cluster in clusters:
                if cluster.get('PubliclyAccessible', False):
                    cluster_id = cluster.get('ClusterIdentifier', 'Unknown')
                    endpoint = cluster.get('Endpoint', {})
                    address = endpoint.get('Address', 'N/A')
                    port = endpoint.get('Port', 'N/A')
                    
                    results.append({
                        "ResourceType": "Redshift Cluster",
                        "Region": region,
                        "ResourceId": cluster_id,
                        "Endpoint": f"{address}:{port}" if address != 'N/A' else 'N/A',
                        "Issue": "Publicly accessible"
                    })
    except Exception as e:
        print(f"Error checking Redshift clusters in {region}: {e}")
    return results

def check_unassociated_elastic_ips(region):
    """Find unassociated Elastic IPs"""
    results = []
    try:
        # Get all Elastic IPs and filter in Python instead of using query
        cmd = f"aws ec2 describe-addresses --region {region} --output json"
        output = run_command(cmd)
        if output:
            data = json.loads(output)
            addresses = data.get('Addresses', [])
            
            for eip in addresses:
                if not eip.get('AssociationId'):
                    results.append({
                        "ResourceType": "Elastic IP",
                        "Region": region,
                        "ResourceId": eip.get('AllocationId', 'Unknown'),
                        "PublicIP": eip.get('PublicIp', 'N/A'),
                        "Issue": "Unassociated Elastic IP"
                    })
    except Exception as e:
        print(f"Error checking Elastic IPs in {region}: {e}")
    return results

def check_api_gateway_v2_endpoints(region):
    """Find API Gateway v2 (HTTP APIs) endpoints"""
    results = []
    try:
        cmd = f"aws apigatewayv2 get-apis --region {region} --output json"
        output = run_command(cmd)
        if output:
            apis = json.loads(output).get('Items', [])
            for api in apis:
                api_id = api.get('ApiId')
                api_name = api.get('Name')
                api_endpoint = api.get('ApiEndpoint')
                
                # Get stages for each API
                stages_cmd = f"aws apigatewayv2 get-stages --api-id {api_id} --region {region} --output json"
                stages_output = run_command(stages_cmd)
                if stages_output:
                    stages = json.loads(stages_output).get('Items', [])
                    for stage in stages:
                        stage_name = stage.get('StageName')
                        results.append({
                            "ResourceType": "API Gateway v2",
                            "Region": region,
                            "ResourceId": api_id,
                            "Name": api_name,
                            "Stage": stage_name,
                            "URL": f"{api_endpoint}/{stage_name}"
                        })
    except Exception as e:
        print(f"Error checking API Gateway v2 in {region}: {e}")
    return results

def check_elastic_beanstalk_environments(region):
    """Find Elastic Beanstalk environments with public endpoints"""
    results = []
    try:
        cmd = f"aws elasticbeanstalk describe-environments --region {region} --output json"
        output = run_command(cmd)
        if output:
            environments = json.loads(output).get('Environments', [])
            for env in environments:
                if env.get('Status') == 'Ready' and env.get('Health') in ['Green', 'Yellow']:
                    results.append({
                        "ResourceType": "Elastic Beanstalk",
                        "Region": region,
                        "ResourceId": env.get('EnvironmentId'),
                        "Name": env.get('EnvironmentName'),
                        "URL": env.get('CNAME', 'N/A'),
                        "Health": env.get('Health', 'N/A')
                    })
    except Exception as e:
        print(f"Error checking Elastic Beanstalk environments in {region}: {e}")
    return results

def check_public_neptune_clusters(region):
    """Find publicly accessible Neptune clusters"""
    results = []
    try:
        cmd = f"aws neptune describe-db-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('DBClusters', [])
            for cluster in clusters:
                if not cluster.get('StorageEncrypted', False) or cluster.get('PubliclyAccessible', False):
                    endpoint = cluster.get('Endpoint', 'N/A')
                    issues = []
                    
                    if not cluster.get('StorageEncrypted', False):
                        issues.append("Unencrypted storage")
                    
                    if cluster.get('PubliclyAccessible', False):
                        issues.append("Publicly accessible")
                    
                    results.append({
                        "ResourceType": "Neptune Cluster",
                        "Region": region,
                        "ResourceId": cluster.get('DBClusterIdentifier'),
                        "Endpoint": endpoint,
                        "Issue": ", ".join(issues)
                    })
    except Exception as e:
        print(f"Error checking Neptune clusters in {region}: {e}")
    return results

def check_public_dynamodb_tables(region):
    """Find DynamoDB tables with public access"""
    results = []
    try:
        # Get list of DynamoDB tables
        cmd = f"aws dynamodb list-tables --region {region} --output json"
        output = run_command(cmd)
        if output:
            tables_data = json.loads(output)
            tables = tables_data.get('TableNames', [])
            
            for table_name in tables:
                # Check for resource-based policies
                policy_cmd = f"aws dynamodb describe-table --table-name {table_name} --region {region} --output json"
                policy_output = run_command(policy_cmd)
                
                if policy_output:
                    table_data = json.loads(policy_output).get('Table', {})
                    
                    # Check for public access through IAM policy
                    # Note: DynamoDB doesn't support resource policies directly like S3
                    # We'll check for tables with stream enabled as they might be exposed
                    if table_data.get('StreamSpecification', {}).get('StreamEnabled', False):
                        stream_arn = table_data.get('LatestStreamArn', 'N/A')
                        
                        results.append({
                            "ResourceType": "DynamoDB Table",
                            "Region": region,
                            "ResourceId": table_name,
                            "ARN": table_data.get('TableArn', 'N/A'),
                            "StreamARN": stream_arn,
                            "Issue": "Stream enabled - check IAM policies for public access"
                        })
                        
                    # Check for Global Tables (replicated across regions)
                    if table_data.get('Replicas', []):
                        results.append({
                            "ResourceType": "DynamoDB Global Table",
                            "Region": region,
                            "ResourceId": table_name,
                            "ARN": table_data.get('TableArn', 'N/A'),
                            "Replicas": ", ".join([r.get('RegionName', 'unknown') for r in table_data.get('Replicas', [])]),
                            "Issue": "Global table - check IAM policies across all regions"
                        })
    except Exception as e:
        print(f"Error checking DynamoDB tables in {region}: {e}")
    return results

def check_public_efs_filesystems(region):
    """Find EFS file systems with public access"""
    results = []
    try:
        # Get list of EFS file systems
        cmd = f"aws efs describe-file-systems --region {region} --output json"
        output = run_command(cmd)
        if output:
            filesystems = json.loads(output).get('FileSystems', [])
            
            for fs in filesystems:
                fs_id = fs.get('FileSystemId')
                
                # Check mount targets for the file system
                mt_cmd = f"aws efs describe-mount-targets --file-system-id {fs_id} --region {region} --output json"
                mt_output = run_command(mt_cmd)
                
                if mt_output:
                    mount_targets = json.loads(mt_output).get('MountTargets', [])
                    
                    for mt in mount_targets:
                        mt_id = mt.get('MountTargetId')
                        subnet_id = mt.get('SubnetId')
                        
                        # Check security groups for the mount target
                        sg_cmd = f"aws efs describe-mount-target-security-groups --mount-target-id {mt_id} --region {region} --output json"
                        sg_output = run_command(sg_cmd)
                        
                        if sg_output:
                            security_groups = json.loads(sg_output).get('SecurityGroups', [])
                            
                            # For each security group, check if it allows public access
                            for sg_id in security_groups:
                                sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                                sg_details = run_command(sg_cmd)
                                
                                if sg_details and sg_details != "[]":
                                    results.append({
                                        "ResourceType": "EFS File System",
                                        "Region": region,
                                        "ResourceId": fs_id,
                                        "MountTarget": mt_id,
                                        "SecurityGroup": sg_id,
                                        "SubnetId": subnet_id,
                                        "Issue": "Mount target security group allows public access"
                                    })
                                    break  # Found a public SG, no need to check others
    except Exception as e:
        print(f"Error checking EFS file systems in {region}: {e}")
    return results

def check_public_fsx_windows(region):
    """Find FSx for Windows file systems with public access"""
    results = []
    try:
        # Get list of FSx file systems
        cmd = f"aws fsx describe-file-systems --region {region} --output json"
        output = run_command(cmd)
        if output:
            filesystems = json.loads(output).get('FileSystems', [])
            
            for fs in filesystems:
                # Only check Windows file systems
                if fs.get('FileSystemType') == 'WINDOWS':
                    fs_id = fs.get('FileSystemId')
                    dns_name = fs.get('DNSName', 'N/A')
                    
                    # Check network interfaces associated with the file system
                    network_interfaces = fs.get('NetworkInterfaceIds', [])
                    
                    for nic_id in network_interfaces:
                        # Get security groups associated with the network interface
                        nic_cmd = f"aws ec2 describe-network-interfaces --network-interface-ids {nic_id} --region {region} --output json"
                        nic_output = run_command(nic_cmd)
                        
                        if nic_output:
                            nic_data = json.loads(nic_output).get('NetworkInterfaces', [])
                            if nic_data:
                                nic = nic_data[0]  # Should only be one result
                                subnet_id = nic.get('SubnetId', 'N/A')
                                
                                # Check security groups for public access
                                for sg in nic.get('Groups', []):
                                    sg_id = sg.get('GroupId')
                                    if sg_id:
                                        sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                                        sg_details = run_command(sg_cmd)
                                        
                                        if sg_details and sg_details != "[]":
                                            results.append({
                                                "ResourceType": "FSx Windows File System",
                                                "Region": region,
                                                "ResourceId": fs_id,
                                                "DNSName": dns_name,
                                                "NetworkInterface": nic_id,
                                                "SecurityGroup": sg_id,
                                                "SubnetId": subnet_id,
                                                "Issue": "Security group allows public access"
                                            })
                                            break  # Found a public SG, no need to check others
    except Exception as e:
        print(f"Error checking FSx Windows file systems in {region}: {e}")
    return results

def check_public_emr_clusters(region):
    """Find EMR clusters with public access"""
    results = []
    try:
        # Get list of active EMR clusters
        cmd = f"aws emr list-clusters --active --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('Clusters', [])
            
            for cluster in clusters:
                cluster_id = cluster.get('Id')
                cluster_name = cluster.get('Name', 'N/A')
                
                # Get detailed cluster information
                details_cmd = f"aws emr describe-cluster --cluster-id {cluster_id} --region {region} --output json"
                details_output = run_command(details_cmd)
                
                if details_output:
                    details = json.loads(details_output).get('Cluster', {})
                    
                    # Check if the cluster has public access enabled
                    ec2_config = details.get('Ec2InstanceAttributes', {})
                    
                    # Check if EMR block public access is disabled
                    bpa_cmd = f"aws emr get-block-public-access-configuration --region {region} --output json"
                    bpa_output = run_command(bpa_cmd)
                    block_public_access = True
                    
                    if bpa_output:
                        bpa_config = json.loads(bpa_output).get('BlockPublicAccessConfiguration', {})
                        block_public_access = bpa_config.get('BlockPublicSecurityGroupRules', True)
                    
                    # Check master node security group
                    master_sg = ec2_config.get('EmrManagedMasterSecurityGroup')
                    if master_sg:
                        sg_cmd = f"aws ec2 describe-security-groups --group-ids {master_sg} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                        sg_details = run_command(sg_cmd)
                        
                        if sg_details and sg_details != "[]":
                            results.append({
                                "ResourceType": "EMR Cluster",
                                "Region": region,
                                "ResourceId": cluster_id,
                                "Name": cluster_name,
                                "SecurityGroup": master_sg,
                                "BlockPublicAccess": str(block_public_access),
                                "Issue": "Master node security group allows public access"
                            })
                            continue  # Found public access, no need to check slave SG
                    
                    # Check slave node security group
                    slave_sg = ec2_config.get('EmrManagedSlaveSecurityGroup')
                    if slave_sg:
                        sg_details = run_command(sg_cmd)
                        
                        if sg_details and sg_details != "[]":
                            results.append({
                                "ResourceType": "EMR Cluster",
                                "Region": region,
                                "ResourceId": cluster_id,
                                "Name": cluster_name,
                                "SecurityGroup": slave_sg,
                                "BlockPublicAccess": str(block_public_access),
                                "Issue": "Slave node security group allows public access"
                            })
    except Exception as e:
        print(f"Error checking EMR clusters in {region}: {e}")
    return results

def check_public_elasticache_clusters(region):
    """Find ElastiCache clusters with public access"""
    results = []
    try:
        # Get list of ElastiCache clusters
        cmd = f"aws elasticache describe-cache-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('CacheClusters', [])
            
            for cluster in clusters:
                cluster_id = cluster.get('CacheClusterId', 'Unknown')
                engine = cluster.get('Engine', 'N/A')
                
                # Check if the cluster is in a public subnet
                subnet_group_name = cluster.get('CacheSubnetGroupName')
                if subnet_group_name:
                    # Get subnet group details
                    sg_cmd = f"aws elasticache describe-cache-subnet-groups --cache-subnet-group-name {subnet_group_name} --region {region} --output json"
                    sg_output = run_command(sg_cmd)
                    
                    if sg_output:
                        subnet_groups = json.loads(sg_output).get('CacheSubnetGroups', [])
                        if subnet_groups:
                            subnet_group = subnet_groups[0]
                            vpc_id = subnet_group.get('VpcId', 'N/A')
                            
                            # Check security groups
                            security_groups = cluster.get('SecurityGroups', [])
                            for sg in security_groups:
                                sg_id = sg.get('SecurityGroupId')
                                if sg_id:
                                    sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                                    sg_details = run_command(sg_cmd)
                                    
                                    if sg_details and sg_details != "[]":
                                        results.append({
                                            "ResourceType": f"ElastiCache {engine}",
                                            "Region": region,
                                            "ResourceId": cluster_id,
                                            "SecurityGroup": sg_id,
                                            "VPC": vpc_id,
                                            "Issue": "Security group allows public access"
                                        })
                                        break  # Found public access, no need to check other SGs
    except Exception as e:
        print(f"Error checking ElastiCache clusters in {region}: {e}")
    return results

def check_public_kinesis_streams(region):
    """Find Kinesis streams with public access"""
    results = []
    try:
        # Get list of Kinesis streams
        cmd = f"aws kinesis list-streams --region {region} --output json"
        output = run_command(cmd)
        if output:
            streams = json.loads(output).get('StreamNames', [])
            
            for stream_name in streams:
                # Check stream details
                details_cmd = f"aws kinesis describe-stream --stream-name {stream_name} --region {region} --output json"
                details_output = run_command(details_cmd)
                
                if details_output:
                    stream_details = json.loads(details_output).get('StreamDescription', {})
                    stream_arn = stream_details.get('StreamARN', 'N/A')
                    
                    # Check for resource-based policy
                    policy_cmd = f"aws kinesis describe-stream-consumer --stream-arn {stream_arn} --consumer-name default --region {region} --output json 2>/dev/null"
                    try:
                        result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                        if result.returncode == 0 and result.stdout:
                            # Check if there's a public policy
                            # Note: Kinesis doesn't directly support resource policies like S3
                            # This is a placeholder for checking consumer configurations
                            pass
                    except Exception:
                        pass
                    
                    # Check for enhanced monitoring which might expose metrics publicly
                    if stream_details.get('EnhancedMonitoring', []):
                        results.append({
                            "ResourceType": "Kinesis Stream",
                            "Region": region,
                            "ResourceId": stream_name,
                            "ARN": stream_arn,
                            "Issue": "Enhanced monitoring enabled - check CloudWatch permissions"
                        })
    except Exception as e:
        print(f"Error checking Kinesis streams in {region}: {e}")
    return results

def check_public_msk_clusters(region):
    """Find MSK (Managed Streaming for Kafka) clusters with public access"""
    results = []
    try:
        # Get list of MSK clusters
        cmd = f"aws kafka list-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('ClusterInfoList', [])
            
            for cluster in clusters:
                cluster_arn = cluster.get('ClusterArn', 'N/A')
                cluster_name = cluster.get('ClusterName', 'Unknown')
                
                # Check if the cluster has public access
                if cluster.get('ClientAuthentication', {}).get('Unauthenticated', {}).get('Enabled', False):
                    results.append({
                        "ResourceType": "MSK Cluster",
                        "Region": region,
                        "ResourceId": cluster_name,
                        "ARN": cluster_arn,
                        "Issue": "Unauthenticated access enabled"
                    })
                    continue
                
                # Check security groups
                broker_nodes = cluster.get('BrokerNodeGroupInfo', {})
                security_groups = broker_nodes.get('SecurityGroups', [])
                
                for sg_id in security_groups:
                    sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                    sg_details = run_command(sg_cmd)
                    
                    if sg_details and sg_details != "[]":
                        results.append({
                            "ResourceType": "MSK Cluster",
                            "Region": region,
                            "ResourceId": cluster_name,
                            "ARN": cluster_arn,
                            "SecurityGroup": sg_id,
                            "Issue": "Security group allows public access"
                        })
                        break  # Found public access, no need to check other SGs
    except Exception as e:
        print(f"Error checking MSK clusters in {region}: {e}")
    return results

def check_public_opensearch_serverless(region):
    """Find OpenSearch Serverless collections with public access"""
    results = []
    try:
        # Get list of OpenSearch Serverless collections
        cmd = f"aws opensearchserverless list-collections --region {region} --output json"
        output = run_command(cmd)
        if output:
            collections = json.loads(output).get('collectionSummaries', [])
            
            for collection in collections:
                collection_id = collection.get('id', 'Unknown')
                collection_name = collection.get('name', 'N/A')
                
                # Check network policy
                policy_cmd = f"aws opensearchserverless list-access-policies --type network --region {region} --output json"
                policy_output = run_command(policy_cmd)
                
                if policy_output:
                    policies = json.loads(policy_output).get('accessPolicySummaries', [])
                    for policy in policies:
                        if collection_name in policy.get('name', ''):
                            # Check if policy allows public access
                            if '0.0.0.0/0' in str(policy):
                                results.append({
                                    "ResourceType": "OpenSearch Serverless",
                                    "Region": region,
                                    "ResourceId": collection_id,
                                    "Name": collection_name,
                                    "Issue": "Network policy allows public access"
                                })
                                break
    except Exception as e:
        print(f"Error checking OpenSearch Serverless collections in {region}: {e}")
    return results

def check_public_documentdb_clusters(region):
    """Find DocumentDB clusters with public access"""
    results = []
    try:
        # Get list of DocumentDB clusters
        cmd = f"aws docdb describe-db-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('DBClusters', [])
            
            for cluster in clusters:
                cluster_id = cluster.get('DBClusterIdentifier', 'Unknown')
                endpoint = cluster.get('Endpoint', 'N/A')
                
                # Check if publicly accessible
                if cluster.get('PubliclyAccessible', False):
                    results.append({
                        "ResourceType": "DocumentDB Cluster",
                        "Region": region,
                        "ResourceId": cluster_id,
                        "Endpoint": endpoint,
                        "Issue": "Publicly accessible"
                    })
                    continue
                
                # Check security groups
                vpc_security_groups = cluster.get('VpcSecurityGroups', [])
                for sg in vpc_security_groups:
                    sg_id = sg.get('VpcSecurityGroupId')
                    if sg_id:
                        sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                        sg_details = run_command(sg_cmd)
                        
                        if sg_details and sg_details != "[]":
                            results.append({
                                "ResourceType": "DocumentDB Cluster",
                                "Region": region,
                                "ResourceId": cluster_id,
                                "Endpoint": endpoint,
                                "SecurityGroup": sg_id,
                                "Issue": "Security group allows public access"
                            })
                            break  # Found public access, no need to check other SGs
    except Exception as e:
        print(f"Error checking DocumentDB clusters in {region}: {e}")
    return results

def check_public_codebuild_projects(region):
    """Find CodeBuild projects with public access"""
    results = []
    try:
        # Get list of CodeBuild projects
        cmd = f"aws codebuild list-projects --region {region} --output json"
        output = run_command(cmd)
        if output:
            project_names = json.loads(output).get('projects', [])
            
            # Batch projects in groups of 100 (AWS API limit)
            for i in range(0, len(project_names), 100):
                batch = project_names[i:i+100]
                if not batch:
                    continue
                    
                # Get project details
                batch_cmd = f"aws codebuild batch-get-projects --names {' '.join(batch)} --region {region} --output json"
                batch_output = run_command(batch_cmd)
                
                if batch_output:
                    projects = json.loads(batch_output).get('projects', [])
                    
                    for project in projects:
                        project_name = project.get('name', 'Unknown')
                        project_arn = project.get('arn', 'N/A')
                        
                        # Check if project has public build results
                        if project.get('projectVisibility') == 'PUBLIC':
                            results.append({
                                "ResourceType": "CodeBuild Project",
                                "Region": region,
                                "ResourceId": project_name,
                                "ARN": project_arn,
                                "Issue": "Project has public visibility"
                            })
                            continue
                            
                        # Check if project has public access enabled via resource policy
                        policy_cmd = f"aws codebuild get-resource-policy --resource-arn {project_arn} --region {region} --output json"
                        try:
                            policy_result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                            if policy_result.returncode == 0 and policy_result.stdout:
                                policy = json.loads(policy_result.stdout).get('policy', '{}')
                                # Check for public access in policy
                                if '"Principal": "*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                                    results.append({
                                        "ResourceType": "CodeBuild Project",
                                        "Region": region,
                                        "ResourceId": project_name,
                                        "ARN": project_arn,
                                        "Issue": "Resource policy allows public access"
                                    })
                        except Exception:
                            pass  # No policy or error reading policy
                        
                        # Check if project has public webhook
                        if project.get('webhook', {}).get('url'):
                            filter_groups = project.get('webhook', {}).get('filterGroups', [])
                            if filter_groups and not project.get('webhook', {}).get('buildType') == 'BUILD_BATCH':
                                results.append({
                                    "ResourceType": "CodeBuild Project",
                                    "Region": region,
                                    "ResourceId": project_name,
                                    "ARN": project_arn,
                                    "Issue": "Project has public webhook configured"
                                })
    except Exception as e:
        print(f"Error checking CodeBuild projects in {region}: {e}")
    return results

def check_public_appsync_apis(region):
    """Find AppSync APIs with public access"""
    results = []
    try:
        # Get list of AppSync APIs
        cmd = f"aws appsync list-graphql-apis --region {region} --output json"
        output = run_command(cmd)
        if output:
            apis = json.loads(output).get('graphqlApis', [])
            
            for api in apis:
                api_id = api.get('apiId', 'Unknown')
                api_name = api.get('name', 'N/A')
                api_arn = api.get('arn', 'N/A')
                
                # Check authentication type
                auth_type = api.get('authenticationType', '')
                
                # Check if API is publicly accessible (API_KEY or AWS_IAM with public policy)
                if auth_type == 'API_KEY':
                    # Get API keys to check expiration
                    keys_cmd = f"aws appsync list-api-keys --api-id {api_id} --region {region} --output json"
                    keys_output = run_command(keys_cmd)
                    
                    if keys_output:
                        api_keys = json.loads(keys_output).get('apiKeys', [])
                        for key in api_keys:
                            if key.get('expires') > 0:  # Key is not expired
                                results.append({
                                    "ResourceType": "AppSync API",
                                    "Region": region,
                                    "ResourceId": api_id,
                                    "Name": api_name,
                                    "AuthType": auth_type,
                                    "Issue": "API uses API key authentication (potentially public)"
                                })
                                break  # Found at least one valid key
                
                # Check if API is using AWS_IAM but has a public policy
                elif auth_type == 'AWS_IAM':
                    # No direct way to check IAM policies via CLI, but we can note it for review
                    results.append({
                        "ResourceType": "AppSync API",
                        "Region": region,
                        "ResourceId": api_id,
                        "Name": api_name,
                        "AuthType": auth_type,
                        "Issue": "API uses IAM authentication - check IAM policies for public access"
                    })
                
                # Check if API is completely open
                elif auth_type == 'NONE':
                    results.append({
                        "ResourceType": "AppSync API",
                        "Region": region,
                        "ResourceId": api_id,
                        "Name": api_name,
                        "AuthType": auth_type,
                        "Issue": "API has no authentication (public)"
                    })
    except Exception as e:
        print(f"Error checking AppSync APIs in {region}: {e}")
    return results

def check_public_amplify_apps(region):
    """Find Amplify apps with public access"""
    results = []
    try:
        # Get list of Amplify apps
        cmd = f"aws amplify list-apps --region {region} --output json"
        output = run_command(cmd)
        if output:
            apps = json.loads(output).get('apps', [])
            
            for app in apps:
                app_id = app.get('appId', 'Unknown')
                app_name = app.get('name', 'N/A')
                default_domain = app.get('defaultDomain', 'N/A')
                
                # Check if app is publicly accessible
                # Amplify apps are public by default unless access control is enabled
                if not app.get('enableBasicAuth', False) and not app.get('enableBranchAutoBuild', False):
                    results.append({
                        "ResourceType": "Amplify App",
                        "Region": region,
                        "ResourceId": app_id,
                        "Name": app_name,
                        "Domain": default_domain,
                        "Issue": "App is publicly accessible (no basic auth)"
                    })
                    continue
                
                # Check branches for public access
                branches_cmd = f"aws amplify list-branches --app-id {app_id} --region {region} --output json"
                branches_output = run_command(branches_cmd)
                
                if branches_output:
                    branches = json.loads(branches_output).get('branches', [])
                    for branch in branches:
                        branch_name = branch.get('branchName', 'N/A')
                        # Check if branch has basic auth disabled but is active
                        if branch.get('enableBasicAuth', False) == False and branch.get('displayName'):
                            results.append({
                                "ResourceType": "Amplify Branch",
                                "Region": region,
                                "ResourceId": f"{app_id}/{branch_name}",
                                "Name": f"{app_name}/{branch_name}",
                                "Domain": f"{branch_name}.{default_domain}",
                                "Issue": "Branch is publicly accessible (no basic auth)"
                            })
    except Exception as e:
        print(f"Error checking Amplify apps in {region}: {e}")
    return results

def check_public_ecr_public_repositories():
    """Find ECR Public repositories"""
    results = []
    try:
        # ECR Public is only available in us-east-1
        region = "us-east-1"
        
        # Get list of ECR Public repositories
        cmd = f"aws ecr-public describe-repositories --region {region} --output json"
        output = run_command(cmd)
        if output:
            repos = json.loads(output).get('repositories', [])
            
            for repo in repos:
                repo_name = repo.get('repositoryName', 'Unknown')
                repo_uri = repo.get('repositoryUri', 'N/A')
                
                results.append({
                    "ResourceType": "ECR Public Repository",
                    "Region": region,
                    "ResourceId": repo_name,
                    "URI": repo_uri,
                    "Issue": "Repository is publicly accessible by design"
                })
    except Exception as e:
        print(f"Error checking ECR Public repositories: {e}")
    return results

def check_memorydb_clusters(region):
    """Find MemoryDB clusters with public access"""
    results = []
    try:
        # Get list of MemoryDB clusters
        cmd = f"aws memorydb describe-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('Clusters', [])
            
            for cluster in clusters:
                cluster_name = cluster.get('Name', 'Unknown')
                cluster_endpoint = cluster.get('ClusterEndpoint', {}).get('Address', 'N/A')
                
                # Check security groups
                security_groups = cluster.get('SecurityGroups', [])
                for sg in security_groups:
                    sg_id = sg.get('SecurityGroupId')
                    if sg_id:
                        sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                        sg_details = run_command(sg_cmd)
                        
                        if sg_details and sg_details != "[]":
                            results.append({
                                "ResourceType": "MemoryDB Cluster",
                                "Region": region,
                                "ResourceId": cluster_name,
                                "Endpoint": cluster_endpoint,
                                "SecurityGroup": sg_id,
                                "Issue": "Security group allows public access"
                            })
                            break  # Found public access, no need to check other SGs
    except Exception as e:
        print(f"Error checking MemoryDB clusters in {region}: {e}")
    return results

def check_public_transfer_servers(region):
    """Find AWS Transfer Family servers with public access"""
    results = []
    try:
        # Get list of Transfer servers
        cmd = f"aws transfer list-servers --region {region} --output json"
        output = run_command(cmd)
        if output:
            servers = json.loads(output).get('Servers', [])
            
            for server in servers:
                server_id = server.get('ServerId', 'Unknown')
                endpoint_type = server.get('EndpointType', 'N/A')
                
                # Check if server has public endpoint
                if endpoint_type == 'PUBLIC':
                    # Get server details
                    details_cmd = f"aws transfer describe-server --server-id {server_id} --region {region} --output json"
                    details_output = run_command(details_cmd)
                    
                    if details_output:
                        details = json.loads(details_output).get('Server', {})
                        endpoint = details.get('Endpoint', 'N/A')
                        domain = details.get('Domain', 'N/A')
                        protocols = details.get('Protocols', [])
                        
                        results.append({
                            "ResourceType": "Transfer Family Server",
                            "Region": region,
                            "ResourceId": server_id,
                            "Endpoint": endpoint,
                            "Domain": domain,
                            "Protocols": ", ".join(protocols),
                            "Issue": "Server has public endpoint"
                        })
    except Exception as e:
        print(f"Error checking Transfer Family servers in {region}: {e}")
    return results

def check_public_apprunner_services(region):
    """Find AWS AppRunner services with public access"""
    results = []
    try:
        # Get list of AppRunner services
        cmd = f"aws apprunner list-services --region {region} --output json"
        output = run_command(cmd)
        if output:
            services = json.loads(output).get('ServiceSummaryList', [])
            
            for service in services:
                service_name = service.get('ServiceName', 'Unknown')
                service_id = service.get('ServiceId', 'Unknown')
                service_arn = service.get('ServiceArn', 'N/A')
                status = service.get('Status', 'N/A')
                
                # Get service details
                details_cmd = f"aws apprunner describe-service --service-arn {service_arn} --region {region} --output json"
                details_output = run_command(details_cmd)
                
                if details_output:
                    details = json.loads(details_output).get('Service', {})
                    service_url = details.get('ServiceUrl', 'N/A')
                    
                    # Check if service is active and has a public URL
                    if status in ['RUNNING', 'ACTIVE'] and service_url:
                        results.append({
                            "ResourceType": "AppRunner Service",
                            "Region": region,
                            "ResourceId": service_id,
                            "Name": service_name,
                            "URL": f"https://{service_url}",
                            "Issue": "Service has public endpoint"
                        })
    except Exception as e:
        print(f"Error checking AppRunner services in {region}: {e}")
    return results

def check_public_sagemaker_endpoints(region):
    """Find AWS SageMaker endpoints with public access"""
    results = []
    try:
        # Get list of SageMaker endpoints
        cmd = f"aws sagemaker list-endpoints --region {region} --output json"
        output = run_command(cmd)
        if output:
            endpoints = json.loads(output).get('Endpoints', [])
            
            for endpoint in endpoints:
                endpoint_name = endpoint.get('EndpointName', 'Unknown')
                endpoint_status = endpoint.get('EndpointStatus', 'N/A')
                
                # Only check active endpoints
                if endpoint_status == 'InService':
                    # Get endpoint config
                    config_cmd = f"aws sagemaker describe-endpoint-config --endpoint-config-name {endpoint_name} --region {region} --output json"
                    config_output = run_command(config_cmd)
                    
                    if config_output:
                        config = json.loads(config_output)
                        
                        # Check for VPC config - endpoints without VPC config are potentially public
                        if not config.get('VpcConfig'):
                            results.append({
                                "ResourceType": "SageMaker Endpoint",
                                "Region": region,
                                "ResourceId": endpoint_name,
                                "Status": endpoint_status,
                                "Issue": "Endpoint has no VPC configuration (potentially public)"
                            })
                            continue
                        
                        # Check if endpoint has a resource policy
                        policy_cmd = f"aws sagemaker describe-endpoint --endpoint-name {endpoint_name} --region {region} --output json"
                        policy_output = run_command(policy_cmd)
                        
                        if policy_output:
                            endpoint_details = json.loads(policy_output)
                            
                            # Check for public network access
                            if endpoint_details.get('EndpointConfigName'):
                                network_cmd = f"aws sagemaker describe-endpoint-config --endpoint-config-name {endpoint_details.get('EndpointConfigName')} --region {region} --output json"
                                network_output = run_command(network_cmd)
                                
                                if network_output:
                                    network_config = json.loads(network_output)
                                    if network_config.get('NetworkIsolationEnabled') is False:
                                        results.append({
                                            "ResourceType": "SageMaker Endpoint",
                                            "Region": region,
                                            "ResourceId": endpoint_name,
                                            "Status": endpoint_status,
                                            "Issue": "Network isolation disabled (potentially public)"
                                        })
    except Exception as e:
        print(f"Error checking SageMaker endpoints in {region}: {e}")
    return results

def check_public_cognito_user_pools(region):
    """Find Cognito User Pools with public access"""
    results = []
    try:
        # Get list of Cognito User Pools
        cmd = f"aws cognito-idp list-user-pools --max-results 60 --region {region} --output json"
        output = run_command(cmd)
        if output:
            user_pools = json.loads(output).get('UserPools', [])
            
            for pool in user_pools:
                pool_id = pool.get('Id', 'Unknown')
                pool_name = pool.get('Name', 'N/A')
                
                # Get user pool details
                details_cmd = f"aws cognito-idp describe-user-pool --user-pool-id {pool_id} --region {region} --output json"
                details_output = run_command(details_cmd)
                
                if details_output:
                    details = json.loads(details_output).get('UserPool', {})
                    
                    # Check if user pool allows unauthenticated identities
                    if details.get('AllowUnauthenticatedIdentities', False):
                        results.append({
                            "ResourceType": "Cognito User Pool",
                            "Region": region,
                            "ResourceId": pool_id,
                            "Name": pool_name,
                            "Issue": "Allows unauthenticated identities"
                        })
                        continue
                    
                    # Check for public client apps
                    clients_cmd = f"aws cognito-idp list-user-pool-clients --user-pool-id {pool_id} --region {region} --output json"
                    clients_output = run_command(clients_cmd)
                    
                    if clients_output:
                        clients = json.loads(clients_output).get('UserPoolClients', [])
                        for client in clients:
                            client_id = client.get('ClientId', 'Unknown')
                            client_name = client.get('ClientName', 'N/A')
                            
                            # Get client details
                            client_cmd = f"aws cognito-idp describe-user-pool-client --user-pool-id {pool_id} --client-id {client_id} --region {region} --output json"
                            client_output = run_command(client_cmd)
                            
                            if client_output:
                                client_details = json.loads(client_output).get('UserPoolClient', {})
                                
                                # Check for public client settings
                                if not client_details.get('PreventUserExistenceErrors', 'LEGACY') == 'ENABLED':
                                    results.append({
                                        "ResourceType": "Cognito User Pool Client",
                                        "Region": region,
                                        "ResourceId": f"{pool_id}/{client_id}",
                                        "Name": f"{pool_name}/{client_name}",
                                        "Issue": "User existence errors not prevented (information disclosure)"
                                    })
                                
                                # Check for no auth flows
                                if not client_details.get('ExplicitAuthFlows'):
                                    results.append({
                                        "ResourceType": "Cognito User Pool Client",
                                        "Region": region,
                                        "ResourceId": f"{pool_id}/{client_id}",
                                        "Name": f"{pool_name}/{client_name}",
                                        "Issue": "No explicit auth flows configured"
                                    })
                                
                                # Check for public client with no secret
                                if client_details.get('ClientSecret') is None:
                                    results.append({
                                        "ResourceType": "Cognito User Pool Client",
                                        "Region": region,
                                        "ResourceId": f"{pool_id}/{client_id}",
                                        "Name": f"{pool_name}/{client_name}",
                                        "Issue": "Public client (no client secret)"
                                    })
    except Exception as e:
        print(f"Error checking Cognito User Pools in {region}: {e}")
    return results

def check_public_athena_workgroups(region):
    """Find Athena workgroups with public access"""
    results = []
    try:
        # Get list of Athena workgroups
        cmd = f"aws athena list-work-groups --region {region} --output json"
        output = run_command(cmd)
        if output:
            workgroups = json.loads(output).get('WorkGroups', [])
            
            for workgroup in workgroups:
                workgroup_name = workgroup.get('Name', 'Unknown')
                
                # Get workgroup details
                details_cmd = f"aws athena get-work-group --work-group {workgroup_name} --region {region} --output json"
                details_output = run_command(details_cmd)
                
                if details_output:
                    details = json.loads(details_output).get('WorkGroup', {})
                    configuration = details.get('Configuration', {})
                    
                    # Check if results are publicly accessible in S3
                    output_location = configuration.get('ResultConfiguration', {}).get('OutputLocation', '')
                    if output_location.startswith('s3://'):
                        bucket_name = output_location.split('/')[2]
                        
                        # Check if the S3 bucket is public
                        acl_cmd = f"aws s3api get-bucket-acl --bucket {bucket_name} --output json 2>/dev/null"
                        try:
                            acl_result = subprocess.run(acl_cmd, shell=True, text=True, capture_output=True)
                            if acl_result.returncode == 0 and acl_result.stdout:
                                acl = json.loads(acl_result.stdout)
                                for grant in acl.get('Grants', []):
                                    grantee = grant.get('Grantee', {})
                                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                        results.append({
                                            "ResourceType": "Athena Workgroup",
                                            "Region": region,
                                            "ResourceId": workgroup_name,
                                            "OutputLocation": output_location,
                                            "Issue": "Results stored in public S3 bucket"
                                        })
                                        break
                        except Exception:
                            pass  # Error reading ACL
                        
                        # Check bucket policy
                        policy_cmd = f"aws s3api get-bucket-policy --bucket {bucket_name} --output json 2>/dev/null"
                        try:
                            policy_result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                            if policy_result.returncode == 0 and policy_result.stdout:
                                policy = json.loads(policy_result.stdout)
                                if '"Principal": "*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                                    results.append({
                                        "ResourceType": "Athena Workgroup",
                                        "Region": region,
                                        "ResourceId": workgroup_name,
                                        "OutputLocation": output_location,
                                        "Issue": "Results stored in S3 bucket with public policy"
                                    })
                        except Exception:
                            pass  # No policy or error reading policy
    except Exception as e:
        print(f"Error checking Athena workgroups in {region}: {e}")
    return results

def check_public_fargate_services(region):
    """Find ECS Fargate services with public access"""
    results = []
    try:
        # Get list of ECS clusters
        cmd = f"aws ecs list-clusters --region {region} --output json"
        output = run_command(cmd)
        if output:
            clusters = json.loads(output).get('clusterArns', [])
            
            for cluster_arn in clusters:
                cluster_name = cluster_arn.split('/')[-1]
                
                # Get services in the cluster
                services_cmd = f"aws ecs list-services --cluster {cluster_name} --region {region} --output json"
                services_output = run_command(services_cmd)
                
                if services_output:
                    services = json.loads(services_output).get('serviceArns', [])
                    
                    if services:
                        # Batch describe services (max 10 at a time)
                        for i in range(0, len(services), 10):
                            batch = services[i:i+10]
                            batch_services = ' '.join([f'"{s}"' for s in batch])
                            
                            details_cmd = f"aws ecs describe-services --cluster {cluster_name} --services {batch_services} --region {region} --output json"
                            details_output = run_command(details_cmd)
                            
                            if details_output:
                                service_details = json.loads(details_output).get('services', [])
                                
                                for service in service_details:
                                    service_name = service.get('serviceName', 'Unknown')
                                    launch_type = service.get('launchType', 'N/A')
                                    
                                    # Only check Fargate services
                                    if launch_type == 'FARGATE':
                                        # Check if service has public IP assignment
                                        network_config = service.get('networkConfiguration', {}).get('awsvpcConfiguration', {})
                                        if network_config.get('assignPublicIp') == 'ENABLED':
                                            # Check if security groups allow public access
                                            security_groups = network_config.get('securityGroups', [])
                                            for sg_id in security_groups:
                                                sg_cmd = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region} --query 'SecurityGroups[*].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]' --output json"
                                                sg_details = run_command(sg_cmd)
                                                
                                                if sg_details and sg_details != "[]":
                                                    results.append({
                                                        "ResourceType": "ECS Fargate Service",
                                                        "Region": region,
                                                        "ResourceId": service_name,
                                                        "Cluster": cluster_name,
                                                        "SecurityGroup": sg_id,
                                                        "Issue": "Public IP assigned with open security group"
                                                    })
                                                    break  # Found public access, no need to check other SGs
    except Exception as e:
        print(f"Error checking ECS Fargate services in {region}: {e}")
    return results


def scan_region(region, result_queue):
    """Scan a single region for public resources"""
    region_results = []
    thread_name = threading.current_thread().name
    print(f"[{thread_name}] Scanning region: {region}")
    
    # Define all checks to run in this region
    checks = [
        ("EC2 instances", check_ec2_instances_with_public_ips),
        ("security groups", check_security_groups_with_open_ingress),
        ("RDS instances", check_public_rds_instances),
        ("load balancers", check_internet_facing_load_balancers),
        ("API Gateway endpoints", check_api_gateway_endpoints),
        ("API Gateway v2 endpoints", check_api_gateway_v2_endpoints),
        ("Lambda functions", check_public_lambda_functions),
        ("EKS clusters", check_public_eks_clusters),
        ("OpenSearch domains", check_public_opensearch_domains),
        ("SNS topics", check_sns_topics_public_access),
        ("SQS queues", check_sqs_queues_public_access),
        ("RDS snapshots", check_rds_snapshots_public),
        ("Redshift clusters", check_public_redshift_clusters),
        ("Elastic IPs", check_unassociated_elastic_ips),
        ("Elastic Beanstalk environments", check_elastic_beanstalk_environments),
        ("Neptune clusters", check_public_neptune_clusters),
        ("DynamoDB tables", check_public_dynamodb_tables),
        ("EFS file systems", check_public_efs_filesystems),
        ("FSx for Windows file systems", check_public_fsx_windows),
        ("EMR clusters", check_public_emr_clusters),
        ("ElastiCache clusters", check_public_elasticache_clusters),
        ("Kinesis streams", check_public_kinesis_streams),
        ("MSK clusters", check_public_msk_clusters),
        ("OpenSearch Serverless collections", check_public_opensearch_serverless),
        ("DocumentDB clusters", check_public_documentdb_clusters),
        ("CodeBuild projects", check_public_codebuild_projects),
        ("AppSync APIs", check_public_appsync_apis),
        ("Amplify apps", check_public_amplify_apps),
        ("MemoryDB clusters", check_memorydb_clusters),
        ("Transfer Family servers", check_public_transfer_servers),
        ("AppRunner services", check_public_apprunner_services),
        ("SageMaker endpoints", check_public_sagemaker_endpoints),
        ("Cognito User Pools", check_public_cognito_user_pools),
        ("Athena workgroups", check_public_athena_workgroups),
        ("ECS Fargate services", check_public_fargate_services)
    ]
    
    # Run all checks
    for check_name, check_func in checks:
        try:
            print(f"[{thread_name}] Checking {check_name} in {region}...")
            check_results = check_func(region)
            # Make sure check_results is a list before extending
            if check_results:
                if isinstance(check_results, list):
                    region_results.extend(check_results)
                    print(f"[{thread_name}] Found {len(check_results)} public {check_name} in {region}")
                else:
                    print(f"[{thread_name}] Warning: {check_name} check returned non-list result: {type(check_results)}")
        except Exception as e:
            print(f"[{thread_name}] Error checking {check_name} in {region}: {e}")
    
    print(f"[{thread_name}] Completed scan of region: {region}")
    result_queue.put(region_results)

def main():
    """Main function to check all public resources"""
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Check for public AWS resources")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    args = parser.parse_args()
    
    all_results = []
    profile = args.profile
    
    # Check AWS CLI is installed and configured
    try:
        version = run_command("aws --version")
        if not version:
            print("Error: AWS CLI not found. Please install and configure the AWS CLI.")
            return
        
        # Check if credentials are configured
        caller_identity = run_command("aws sts get-caller-identity --output json", profile)
        if not caller_identity:
            print("Error: AWS credentials not configured or insufficient permissions.")
            print("Please run 'aws configure' to set up your credentials.")
            return
            
        print(f"AWS CLI detected: {version}")
        identity = json.loads(caller_identity)
        print(f"Running as: {identity.get('Arn')}")
        if profile:
            print(f"Using AWS profile: {profile}")
    except Exception as e:
        print(f"Error checking AWS configuration: {e}")
        return
    
    # Check AWS CLI version for account list-regions support
    cli_version = version.split('/')[1].split(' ')[0] if '/' in version else "0.0.0"
    has_account_api = False
    
    # Simple version check without using packaging module
    try:
        # Parse version components
        version_parts = cli_version.split('.')
        major = int(version_parts[0]) if version_parts and version_parts[0].isdigit() else 0
        minor = int(version_parts[1]) if len(version_parts) > 1 and version_parts[1].isdigit() else 0
        
        # Check if version is at least 2.9.0
        has_account_api = (major > 2) or (major == 2 and minor >= 9)
    except Exception:
        # If any error occurs during version parsing, assume API is not available
        has_account_api = False
    
    if not has_account_api:
        print("Note: AWS CLI version 2.9.0+ required for checking enabled regions. Will check all available regions.")
    
    # Update get_regions to use profile
    def get_regions_with_profile():
        """Get list of all AWS regions with profile support"""
        try:
            # Get only enabled regions
            cmd = "aws account list-regions --output json"
            output = run_command(cmd, profile)
            if output:
                data = json.loads(output)
                # Extract only enabled regions
                enabled_regions = []
                for region in data.get('Regions', []):
                    if region.get('RegionOptStatus') == 'ENABLED' or region.get('RegionOptStatus') == 'ENABLED_BY_DEFAULT':
                        enabled_regions.append(region.get('RegionName'))
                
                if enabled_regions:
                    print(f"Found {len(enabled_regions)} enabled regions")
                    return enabled_regions
            
            # Fallback to EC2 describe-regions if account list-regions fails
            cmd = "aws ec2 describe-regions --output json"
            output = run_command(cmd, profile)
            if output:
                data = json.loads(output)
                # Extract region names from the response
                if 'Regions' in data:
                    regions = [region['RegionName'] for region in data['Regions']]
                    print("Warning: Could not determine which regions are enabled. Checking all available regions.")
                    return regions
                
            # Fallback to hardcoded list of common regions if API calls fail
            print("Warning: Could not retrieve regions via API, using default region list")
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
                "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
                "ap-south-1", "sa-east-1", "ca-central-1"
            ]
        except Exception as e:
            print(f"Error getting regions: {e}")
            return ["us-east-1"]  # Default to us-east-1 if we can't get regions
    
    regions = get_regions_with_profile()
    if not regions:
        print("Error: Could not retrieve AWS regions. Check your permissions.")
        return
        
    print(f"Scanning {len(regions)} AWS regions for public resources...")
    
    # Ask user about parallel execution
    max_workers = 1
    try:
        response = input("Run scans in parallel to speed up execution? (y/n) [default: n]: ").strip().lower()
        if response == 'y':
            suggested_workers = min(10, len(regions))
            workers_input = input(f"Enter maximum number of parallel scans (1-{len(regions)}) [default: {suggested_workers}]: ").strip()
            if workers_input and workers_input.isdigit():
                max_workers = max(1, min(len(regions), int(workers_input)))
            else:
                max_workers = suggested_workers
            print(f"Using {max_workers} parallel workers")
        else:
            print("Using sequential execution")
    except Exception:
        print("Using sequential execution")
        max_workers = 1
    
    # Check global resources first
    print("Checking global resources...")
    
    # Update global resource checks to use profile
    def check_global_resources_with_profile():
        global_results = []
        
        # Check S3 buckets (global resource)
        print("Checking S3 buckets...")
        # Update check_public_s3_buckets to use profile
        def check_s3_buckets_with_profile():
            results = []
            try:
                # Get list of buckets
                buckets_output = run_command("aws s3api list-buckets --query 'Buckets[*].Name' --output json", profile)
                if not buckets_output:
                    return results
                    
                buckets = json.loads(buckets_output)
                
                for bucket in buckets:
                    # Check bucket public access block settings
                    block_cmd = f"aws s3api get-public-access-block --bucket {bucket} --output json 2>/dev/null"
                    try:
                        block_result = subprocess.run(block_cmd, shell=True, text=True, capture_output=True)
                        if block_result.returncode == 0 and block_result.stdout:
                            block_config = json.loads(block_result.stdout).get('PublicAccessBlockConfiguration', {})
                            # If all block settings are True, skip further checks
                            if (block_config.get('BlockPublicAcls', False) and 
                                block_config.get('BlockPublicPolicy', False) and
                                block_config.get('IgnorePublicAcls', False) and
                                block_config.get('RestrictPublicBuckets', False)):
                                continue
                    except Exception:
                        pass  # No block config or error reading it
                    
                    # Check bucket policy
                    policy_cmd = f"aws s3api get-bucket-policy --bucket {bucket} --output json 2>/dev/null"
                    if profile:
                        policy_cmd = f"aws --profile {profile} s3api get-bucket-policy --bucket {bucket} --output json 2>/dev/null"
                    try:
                        result = subprocess.run(policy_cmd, shell=True, text=True, capture_output=True)
                        if result.returncode == 0 and result.stdout:
                            policy = json.loads(result.stdout)
                            if '"Principal": "*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                                results.append({
                                    "ResourceType": "S3 Bucket",
                                    "ResourceId": bucket,
                                    "Issue": "Public access in bucket policy"
                                })
                                continue
                    except Exception:
                        pass  # No policy or error reading policy
                        
                    # Check ACL
                    acl_cmd = f"aws s3api get-bucket-acl --bucket {bucket} --output json 2>/dev/null"
                    if profile:
                        acl_cmd = f"aws --profile {profile} s3api get-bucket-acl --bucket {bucket} --output json 2>/dev/null"
                    try:
                        acl_result = subprocess.run(acl_cmd, shell=True, text=True, capture_output=True)
                        if acl_result.returncode == 0 and acl_result.stdout:
                            acl = json.loads(acl_result.stdout)
                            for grant in acl.get('Grants', []):
                                grantee = grant.get('Grantee', {})
                                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                    results.append({
                                        "ResourceType": "S3 Bucket",
                                        "ResourceId": bucket,
                                        "Issue": "Public access in ACL"
                                    })
                                    break
                    except Exception:
                        pass  # Error reading ACL
            except Exception as e:
                print(f"Error checking S3 buckets: {e}")
            return results
        
        global_results.extend(check_s3_buckets_with_profile())
        
        # Check ECR repositories (global resource)
        print("Checking ECR repositories...")
        ecr_results = []
        try:
            cmd = "aws ecr describe-repositories --output json"
            output = run_command(cmd, profile)
            if output:
                repos = json.loads(output).get('repositories', [])
                for repo in repos:
                    policy_cmd = f"aws ecr get-repository-policy --repository-name {repo['repositoryName']} --output json 2>/dev/null"
                    try:
                        policy_result = run_command(policy_cmd, profile)
                        if policy_result:
                            policy = json.loads(policy_result).get('policyText', '{}')
                            if '"Principal": "*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                                ecr_results.append({
                                    "ResourceType": "ECR Repository",
                                    "ResourceId": repo['repositoryName'],
                                    "ARN": repo['repositoryArn'],
                                    "Issue": "Public access in policy"
                                })
                    except Exception:
                        pass  # No policy or error reading policy
        except Exception as e:
            print(f"Error checking ECR repositories: {e}")
        global_results.extend(ecr_results)
        
        # Check CloudFront distributions (global resource)
        print("Checking CloudFront distributions...")
        cf_results = []
        try:
            cmd = "aws cloudfront list-distributions --output json"
            output = run_command(cmd, profile)
            if output:
                distributions_data = json.loads(output)
                if 'DistributionList' in distributions_data and 'Items' in distributions_data['DistributionList']:
                    distributions = distributions_data['DistributionList']['Items']
                    for dist in distributions:
                        if dist.get('Enabled', False):  # Only include enabled distributions
                            origin_domain = "N/A"
                            if 'Origins' in dist and 'Items' in dist['Origins'] and len(dist['Origins']['Items']) > 0:
                                origin_domain = dist['Origins']['Items'][0].get('DomainName', 'N/A')
                                
                            cf_results.append({
                                "ResourceType": "CloudFront Distribution",
                                "Region": "global",
                                "ResourceId": dist.get('Id', 'Unknown'),
                                "DomainName": dist.get('DomainName', 'N/A'),
                                "OriginDomain": origin_domain
                            })
        except Exception as e:
            print(f"Error checking CloudFront distributions: {e}")
        global_results.extend(cf_results)
        
        # Check ECR Public repositories (global resource in us-east-1)
        print("Checking ECR Public repositories...")
        ecr_public_results = []
        try:
            region = "us-east-1"
            cmd = f"aws ecr-public describe-repositories --region {region} --output json"
            output = run_command(cmd, profile)
            if output:
                repos = json.loads(output).get('repositories', [])
                for repo in repos:
                    repo_name = repo.get('repositoryName', 'Unknown')
                    repo_uri = repo.get('repositoryUri', 'N/A')
                    
                    ecr_public_results.append({
                        "ResourceType": "ECR Public Repository",
                        "Region": region,
                        "ResourceId": repo_name,
                        "URI": repo_uri,
                        "Issue": "Repository is publicly accessible by design"
                    })
        except Exception as e:
            print(f"Error checking ECR Public repositories: {e}")
        global_results.extend(ecr_public_results)
        
        return global_results
    
    all_results.extend(check_global_resources_with_profile())
    
    # Update scan_region to use profile
    def scan_region_with_profile(region, result_queue, profile=None):
        """Scan a single region for public resources with profile support"""
        region_results = []
        thread_name = threading.current_thread().name
        print(f"[{thread_name}] Scanning region: {region}")
        
        # Define all checks to run in this region
        # We'll modify each check function to use the profile parameter
        # For brevity, we'll just modify how scan_region calls the check functions
        
        # Define all checks to run in this region
        checks = [
            ("EC2 instances", check_ec2_instances_with_public_ips),
            ("security groups", check_security_groups_with_open_ingress),
            ("RDS instances", check_public_rds_instances),
            ("load balancers", check_internet_facing_load_balancers),
            ("API Gateway endpoints", check_api_gateway_endpoints),
            ("API Gateway v2 endpoints", check_api_gateway_v2_endpoints),
            ("Lambda functions", check_public_lambda_functions),
            ("EKS clusters", check_public_eks_clusters),
            ("OpenSearch domains", check_public_opensearch_domains),
            ("SNS topics", check_sns_topics_public_access),
            ("SQS queues", check_sqs_queues_public_access),
            ("RDS snapshots", check_rds_snapshots_public),
            ("Redshift clusters", check_public_redshift_clusters),
            ("Elastic IPs", check_unassociated_elastic_ips),
            ("Elastic Beanstalk environments", check_elastic_beanstalk_environments),
            ("Neptune clusters", check_public_neptune_clusters),
            ("DynamoDB tables", check_public_dynamodb_tables),
            ("EFS file systems", check_public_efs_filesystems),
            ("FSx for Windows file systems", check_public_fsx_windows),
            ("EMR clusters", check_public_emr_clusters),
            ("ElastiCache clusters", check_public_elasticache_clusters),
            ("Kinesis streams", check_public_kinesis_streams),
            ("MSK clusters", check_public_msk_clusters),
            ("OpenSearch Serverless collections", check_public_opensearch_serverless),
            ("DocumentDB clusters", check_public_documentdb_clusters),
            ("CodeBuild projects", check_public_codebuild_projects),
            ("AppSync APIs", check_public_appsync_apis),
            ("Amplify apps", check_public_amplify_apps),
            ("MemoryDB clusters", check_memorydb_clusters),
            ("Transfer Family servers", check_public_transfer_servers),
            ("AppRunner services", check_public_apprunner_services),
            ("SageMaker endpoints", check_public_sagemaker_endpoints),
            ("Cognito User Pools", check_public_cognito_user_pools),
            ("Athena workgroups", check_public_athena_workgroups),
            ("ECS Fargate services", check_public_fargate_services)
        ]
        
        # Run all checks
        for check_name, check_func in checks:
            try:
                print(f"[{thread_name}] Checking {check_name} in {region}...")
                # Modify each check function to use the profile parameter
                # This is a wrapper approach that avoids modifying all check functions
                def run_check_with_profile():
                    # Temporarily modify run_command to include profile
                    global run_command
                    original_run_command = run_command
                    
                    def patched_run_command(cmd, *args, **kwargs):
                        return original_run_command(cmd, profile)
                    
                    # Swap the function
                    temp = run_command
                    run_command = patched_run_command
                    
                    try:
                        # Run the check with the patched run_command
                        result = check_func(region)
                        return result
                    finally:
                        # Restore original function
                        run_command = temp
                
                check_results = run_check_with_profile()
                
                # Make sure check_results is a list before extending
                if check_results:
                    if isinstance(check_results, list):
                        region_results.extend(check_results)
                        print(f"[{thread_name}] Found {len(check_results)} public {check_name} in {region}")
                    else:
                        print(f"[{thread_name}] Warning: {check_name} check returned non-list result: {type(check_results)}")
            except Exception as e:
                print(f"[{thread_name}] Error checking {check_name} in {region}: {e}")
        
        print(f"[{thread_name}] Completed scan of region: {region}")
        result_queue.put(region_results)
    
    # Check resources in each region using parallel execution if requested
    if max_workers > 1:
        # Use thread pool for parallel execution
        result_queue = queue.Queue()
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all region scans to the thread pool
            for region in regions:
                executor.submit(scan_region_with_profile, region, result_queue, profile)
        
        # Collect results from the queue
        region_results_count = 0
        while region_results_count < len(regions):
            try:
                region_results = result_queue.get(timeout=1)
                all_results.extend(region_results)
                region_results_count += 1
                print(f"Progress: {region_results_count}/{len(regions)} regions processed")
            except queue.Empty:
                if time.time() - start_time > 600:  # 10 minute timeout
                    print("Warning: Timeout waiting for region scans to complete")
                    break
                continue
    else:
        # Sequential execution
        for region in regions:
            result_queue = queue.Queue()
            scan_region_with_profile(region, result_queue, profile)
            try:
                region_results = result_queue.get(timeout=1)
                all_results.extend(region_results)
            except queue.Empty:
                print(f"Warning: No results received from {region}")
                continue
    
    # Generate report
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"public_resources_report_{timestamp}.csv"
    
    print(f"\nFound {len(all_results)} public resources.")
    print(f"Writing report to {report_file}")
    
    # Get all possible field names from all results
    fieldnames = set()
    for result in all_results:
        fieldnames.update(result.keys())
    fieldnames = sorted(list(fieldnames))
    
    # Write CSV report
    with open(report_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)
    
    print("Report complete.")
    
    # Print summary
    resource_types = {}
    for result in all_results:
        resource_type = result.get("ResourceType", "Unknown")
        if resource_type not in resource_types:
            resource_types[resource_type] = 0
        resource_types[resource_type] += 1
    
    print("\nSummary:")
    for resource_type, count in resource_types.items():
        print(f"  {resource_type}: {count}")

if __name__ == "__main__":
    main()