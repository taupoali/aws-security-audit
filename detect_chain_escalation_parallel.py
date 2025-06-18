from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import subprocess
import json
import argparse
import os
import csv
import time
import sys
from collections import defaultdict

# Expanded list of sensitive actions that can lead to privilege escalation
SENSITIVE_ACTIONS = {
    # IAM admin actions
    "iam:*", "iam:Create*", "iam:PassRole", "iam:PutRolePolicy", "iam:AttachRolePolicy",
    # S3 admin actions
    "s3:*", 
    # Lambda actions that can lead to privilege escalation
    "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction",
    # EC2 actions that can lead to privilege escalation
    "ec2:RunInstances", "ec2:CreateInstance*", "ec2:StartInstances",
    # CloudFormation actions that can lead to privilege escalation
    "cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:ExecuteChangeSet",
    # Glue actions that can lead to privilege escalation
    "glue:CreateDevEndpoint", "glue:UpdateDevEndpoint", "glue:CreateJob", "glue:UpdateJob",
    # CodeBuild actions that can lead to privilege escalation
    "codebuild:CreateProject", "codebuild:UpdateProject", "codebuild:StartBuild",
    # SageMaker actions that can lead to privilege escalation
    "sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob",
    # ECS/Fargate actions that can lead to privilege escalation
    "ecs:RunTask", "ecs:StartTask",
    # Data pipeline actions
    "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition",
    # SSM actions that can lead to privilege escalation
    "ssm:SendCommand", "ssm:StartSession",
    # EventBridge actions
    "events:PutRule", "events:PutTargets",
    # Wildcard permissions
    "*"
}

# Service principals that can be used for privilege escalation
RISKY_SERVICE_PRINCIPALS = {
    "lambda.amazonaws.com",
    "glue.amazonaws.com",
    "codebuild.amazonaws.com",
    "sagemaker.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "ec2.amazonaws.com",
    "ssm.amazonaws.com",
    "events.amazonaws.com",
    "cloudformation.amazonaws.com"
}


# Cache for AWS CLI results to avoid duplicate calls
AWS_CLI_CACHE = {}
# Track API call statistics
API_STATS = {"calls": 0, "timeouts": 0, "errors": 0, "cached": 0}
# Backoff settings
BACKOFF_BASE = 0.5  # Start with 0.5s delay
BACKOFF_MAX = 5     # Maximum 5s delay
BACKOFF_FACTOR = 1.5  # Increase by 50% each retry
MAX_RETRIES = 3     # Maximum 3 retries

def run_aws_cli(cmd, profile=None, retries=0):
    # Add profile if specified
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    # Convert command list to tuple for hashing
    cmd_key = tuple(cmd)
    
    # Return cached result if available
    if cmd_key in AWS_CLI_CACHE:
        API_STATS["cached"] += 1
        return AWS_CLI_CACHE[cmd_key]
    
    # Track API calls
    API_STATS["calls"] += 1
    
    try:
        # Increase timeout for policy-related operations which are often slow
        timeout = 20 if any(x in str(cmd) for x in ["policy", "Policy"]) else 10
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if result.returncode != 0:
            # Check for throttling errors
            if "Throttling" in result.stderr or "Rate exceeded" in result.stderr:
                if retries < MAX_RETRIES:
                    # Exponential backoff
                    delay = min(BACKOFF_MAX, BACKOFF_BASE * (BACKOFF_FACTOR ** retries))
                    print(f"[WARN] AWS API throttling detected, retrying in {delay:.1f}s ({retries+1}/{MAX_RETRIES})")
                    time.sleep(delay)
                    # Pass the profile parameter in the recursive call
                    return run_aws_cli(cmd, profile=None, retries=retries + 1)
                else:
                    print(f"[ERROR] AWS API throttling limit reached after {MAX_RETRIES} retries")
            
            API_STATS["errors"] += 1
            AWS_CLI_CACHE[cmd_key] = None
            return None
            
        parsed_result = json.loads(result.stdout)
        AWS_CLI_CACHE[cmd_key] = parsed_result
        return parsed_result
    except subprocess.TimeoutExpired:
        API_STATS["timeouts"] += 1
        print(f"[WARN] AWS CLI command timed out: {' '.join(str(x) for x in cmd)}")
        
        # Retry with backoff for timeouts
        if retries < MAX_RETRIES:
            delay = min(BACKOFF_MAX, BACKOFF_BASE * (BACKOFF_FACTOR ** retries))
            print(f"[INFO] Retrying after timeout in {delay:.1f}s ({retries+1}/{MAX_RETRIES})")
            time.sleep(delay)
            # Pass the profile parameter in the recursive call
            return run_aws_cli(cmd, profile=None, retries=retries + 1)
            
        AWS_CLI_CACHE[cmd_key] = None
        return None
    except json.JSONDecodeError:
        API_STATS["errors"] += 1
        print(f"[ERROR] Invalid JSON response from AWS CLI: {' '.join(str(x) for x in cmd)}")
        AWS_CLI_CACHE[cmd_key] = None
        return None


def get_account_id(profile=None):
    cmd = ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"]
    if profile:
        cmd = ["aws", "--profile", profile] + cmd[1:]
    
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    return result.stdout.strip()


def get_all_roles(profile=None):
    print("[INFO] Fetching IAM roles...")
    result = run_aws_cli(["aws", "iam", "list-roles"], profile)
    if not result:
        print("[ERROR] Failed to fetch IAM roles.")
        return {}
    roles = {r["RoleName"]: r for r in result["Roles"]}
    print(f"[INFO] Retrieved {len(roles)} IAM roles")
    return roles


def get_trust_policy(role_name, profile=None):
    result = run_aws_cli(["aws", "iam", "get-role", "--role-name", role_name], profile)
    if not result:
        return None
    return result["Role"]["AssumeRolePolicyDocument"]


def get_inline_policies(role_name, profile=None):
    result = run_aws_cli(["aws", "iam", "list-role-policies", "--role-name", role_name], profile)
    if not result:
        return []
    policies = []
    for policy_name in result["PolicyNames"]:
        p = run_aws_cli(["aws", "iam", "get-role-policy", "--role-name", role_name, "--policy-name", policy_name], profile)
        if p:
            policies.append(p["PolicyDocument"])
    return policies


def get_attached_policies(role_name, profile=None):
    result = run_aws_cli(["aws", "iam", "list-attached-role-policies", "--role-name", role_name], profile)
    if not result:
        return []
    
    policies = []
    total = len(result["AttachedPolicies"])
    
    # Use batch processing for AWS managed policies to reduce API calls
    aws_managed = []
    customer_managed = []
    
    # Separate AWS managed policies from customer managed policies
    for attached in result["AttachedPolicies"]:
        arn = attached["PolicyArn"]
        if ":aws:" in arn and ":policy/" in arn:
            aws_managed.append(arn)
        else:
            customer_managed.append(arn)
    
    # For AWS managed policies, use a predefined set of common permissions
    # This significantly reduces API calls for common policies
    common_aws_policies = {
        "arn:aws:iam::aws:policy/AdministratorAccess": {"Effect": "Allow", "Action": "*", "Resource": "*"},
        "arn:aws:iam::aws:policy/PowerUserAccess": {"Effect": "Allow", "Action": "*", "Resource": "*", "NotAction": "iam:*"},
        "arn:aws:iam::aws:policy/ReadOnlyAccess": {"Effect": "Allow", "Action": ["*:Get*", "*:List*", "*:Describe*"], "Resource": "*"}
    }
    
    # Process AWS managed policies
    for arn in aws_managed:
        if arn in common_aws_policies:
            policies.append({"Statement": common_aws_policies[arn]})
            continue
            
        # For other AWS managed policies, fetch them normally
        pv = run_aws_cli(["aws", "iam", "get-policy", "--policy-arn", arn], profile)
        if not pv:
            continue
        ver_id = pv["Policy"]["DefaultVersionId"]
        pd = run_aws_cli(["aws", "iam", "get-policy-version", "--policy-arn", arn, "--version-id", ver_id], profile)
        if pd:
            policies.append(pd["PolicyVersion"]["Document"])
    
    # Process customer managed policies
    for arn in customer_managed:
        pv = run_aws_cli(["aws", "iam", "get-policy", "--policy-arn", arn], profile)
        if not pv:
            continue
        ver_id = pv["Policy"]["DefaultVersionId"]
        pd = run_aws_cli(["aws", "iam", "get-policy-version", "--policy-arn", arn, "--version-id", ver_id], profile)
        if pd:
            policies.append(pd["PolicyVersion"]["Document"])
    
    return policies


def extract_actions(policy_doc):
    actions = set()
    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        act = stmt.get("Action", [])
        if isinstance(act, str):
            actions.add(act)
        elif isinstance(act, list):
            actions.update(act)
    return actions


def can_assume(source, target, account_id, profile=None):
    target_arn = f"arn:aws:iam::{account_id}:role/{target}"
    for policy in get_inline_policies(source, profile) + get_attached_policies(source, profile):
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if "sts:AssumeRole" not in extract_actions({"Statement": [stmt]}):
                continue
            resource = stmt.get("Resource")
            if resource == "*" or resource == target_arn:
                return True
            if isinstance(resource, list) and (target_arn in resource or "*" in resource):
                return True
    return False


def trust_allows(source, target, account_id, profile=None):
    trust = get_trust_policy(target, profile)
    if not trust:
        return False
    for stmt in trust.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
            
        # Check AWS principals (roles/users)
        principal = stmt.get("Principal", {})
        aws_principal = principal.get("AWS")
        source_arn = f"arn:aws:iam::{account_id}:role/{source}"
        
        if isinstance(aws_principal, str):
            if aws_principal == source_arn or aws_principal == "*":
                return True
        elif isinstance(aws_principal, list):
            if source_arn in aws_principal or "*" in aws_principal:
                return True
                
        # Check for service principals that can be exploited
        service_principal = principal.get("Service")
        if service_principal:
            if isinstance(service_principal, str) and service_principal in RISKY_SERVICE_PRINCIPALS:
                return True
            elif isinstance(service_principal, list) and any(sp in RISKY_SERVICE_PRINCIPALS for sp in service_principal):
                return True
    
    return False


def is_privileged(role_name, profile=None):
    findings = set()
    
    # Get policies
    inline_policies = get_inline_policies(role_name, profile)
    attached_policies = get_attached_policies(role_name, profile)
    
    for policy in inline_policies + attached_policies:
        actions = extract_actions(policy)
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
            
        # Check for sensitive actions
        for act in actions:
            for sensitive in SENSITIVE_ACTIONS:
                if act.startswith(sensitive.rstrip("*")):
                    findings.add(act)
        
        # Check for admin access via resource conditions
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
                
            # Check for admin access via resource patterns
            resources = stmt.get("Resource", [])
            if not isinstance(resources, list):
                resources = [resources]
                
            actions_in_stmt = stmt.get("Action", [])
            if not isinstance(actions_in_stmt, list):
                actions_in_stmt = [actions_in_stmt]
                
            # Check for admin access patterns
            if "*" in resources and any(a.endswith("*") for a in actions_in_stmt):
                findings.add("admin-via-wildcard-resource")
    
    is_admin = len(findings) > 0
    return is_admin


def check_cross_account_trust(role_name, account_id=None, profile=None):
    """Check if a role can be assumed by principals in other accounts"""
    cross_account_trusts = []
    trust = get_trust_policy(role_name, profile)
    
    if not trust:
        return []
    
    # Use provided account_id or global ACCOUNT_ID
    if account_id is None:
        account_id = ACCOUNT_ID
        
    for stmt in trust.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
            
        principal = stmt.get("Principal", {})
        
        # Check AWS principals
        aws_principal = principal.get("AWS")
        if aws_principal:
            if isinstance(aws_principal, str):
                if aws_principal == "*" or (aws_principal.startswith("arn:aws:iam::") and not aws_principal.startswith(f"arn:aws:iam::{account_id}:")):
                    cross_account_trusts.append(aws_principal)
            elif isinstance(aws_principal, list):
                for p in aws_principal:
                    if p == "*" or (p.startswith("arn:aws:iam::") and not p.startswith(f"arn:aws:iam::{account_id}:")):
                        cross_account_trusts.append(p)
    
    return cross_account_trusts

def build_graph_parallel(role_names, account_id, profile=None, max_workers=None, batch_size=100):
    # Use command line args if provided, otherwise use defaults
    if max_workers is None:
        max_workers = args.max_workers if 'args' in globals() and hasattr(args, 'max_workers') else 8
    graph = {}
    cross_account_findings = {}
    total_pairs = len(role_names) * len(role_names)
    completed = 0
    found_edges = 0
    last_update = time.time()
    update_interval = 2  # Update progress every 2 seconds

    def check_pair(source, target):
        if source == target:
            return None
        if can_assume(source, target, account_id, profile) and trust_allows(source, target, account_id, profile):
            return (source, target)
        return None
        
    def check_role_cross_account(role_name):
        trusts = check_cross_account_trust(role_name, account_id, profile)
        if trusts:
            return (role_name, trusts)
        return None
    
    # Process roles in batches to avoid overwhelming the AWS API
    def process_batch(role_batch):
        batch_results = []
        for source in role_batch:
            for target in role_names:
                result = check_pair(source, target)
                if result:
                    batch_results.append(result)
        return batch_results

    print(f"[INFO] Running parallel trust/permission checks for {len(role_names)} roles ({total_pairs} potential relationships)...")
    print(f"[INFO] Using {max_workers} workers and batch size of {batch_size}")
    print(f"[INFO] Progress updates will be shown every {update_interval} seconds")
    
    start_time = time.time()
    
    # Process in batches to avoid overwhelming the AWS API
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Process role-to-role relationships in batches
        for i in range(0, len(role_names), batch_size):
            batch = role_names[i:i+batch_size]
            print(f"[INFO] Processing batch {i//batch_size + 1}/{(len(role_names) + batch_size - 1)//batch_size} ({len(batch)} roles)")
            
            # Submit batch for processing
            futures = []
            for source in batch:
                for target in role_names:
                    futures.append(executor.submit(check_pair, source, target))
            
            # Process results from this batch
            batch_completed = 0
            batch_total = len(futures)
            
            for f in as_completed(futures):
                batch_completed += 1
                completed += 1
                current_time = time.time()
                
                # Show progress update at intervals
                if current_time - last_update >= update_interval:
                    elapsed = current_time - start_time
                    percent = (completed / total_pairs) * 100
                    remaining = (elapsed / completed) * (total_pairs - completed) if completed > 0 else 0
                    
                    print(f"[PROGRESS] {completed}/{total_pairs} checks completed ({percent:.1f}%) - Found {found_edges} edges - ETA: {remaining:.1f}s")
                    last_update = current_time
                    
                result = f.result()
                if result:
                    src, tgt = result
                    graph.setdefault(src, []).append(tgt)
                    found_edges += 1
                    print(f"[GRAPH] {src} -> {tgt}")
            
            # Show batch completion
            print(f"[INFO] Batch {i//batch_size + 1} completed: {batch_completed}/{batch_total} checks, found {found_edges} edges so far")
                
        # Also check for cross-account trust relationships
        print("[INFO] Checking for cross-account trust relationships...")
        cross_account_futures = []
        for role in role_names:
            cross_account_futures.append(executor.submit(check_role_cross_account, role))
                
        # Process cross-account findings
        cross_account_count = 0
        for f in as_completed(cross_account_futures):
            result = f.result()
            if result:
                role, trusts = result
                cross_account_findings[role] = trusts
                cross_account_count += 1
                print(f"[CROSS-ACCOUNT] {role} can be assumed by: {', '.join(trusts)}")
        
        if cross_account_futures:
            print(f"[INFO] Found {cross_account_count} roles with cross-account trust relationships")

    # Show final progress for role-to-role checks
    print(f"[INFO] Completed {completed}/{total_pairs} role-to-role checks, found {found_edges} edges")

    # Add cross-account findings to the return value
    return {"graph": graph, "cross_account_findings": cross_account_findings}


def find_chains(graph, profile=None):
    chains = []
    privileged_roles = {}  # Cache for privileged role checks
    total_roles = len(graph)
    processed = 0
    start_time = time.time()
    
    print(f"[INFO] Searching for privilege escalation chains from {total_roles} starting roles...")
    
    def dfs(current, path, visited):
        # Use cached result if available
        if current not in privileged_roles:
            privileged_roles[current] = is_privileged(current, profile)
            
        if privileged_roles[current]:
            chains.append(path + [current])
            return
            
        for neighbor in graph.get(current, []):
            if neighbor not in visited:
                dfs(neighbor, path + [current], visited | {neighbor})

    for i, start in enumerate(graph):
        dfs(start, [], {start})
        processed += 1
        
        # Show progress every 5% or at least every 10 roles
        if processed % max(1, min(10, total_roles // 20)) == 0 or processed == total_roles:
            percent = (processed / total_roles) * 100
            elapsed = time.time() - start_time
            remaining = (elapsed / processed) * (total_roles - processed) if processed > 0 else 0
            
            print(f"[PROGRESS] Analyzed {processed}/{total_roles} starting roles ({percent:.1f}%) - Found {len(chains)} chains - ETA: {remaining:.1f}s")
    
    return chains


# Function to generate visualization of escalation paths
def generate_visualization(chains, graph, cross_account_findings=None, output_file="escalation_paths.html"):
    try:
        # Simple HTML visualization
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AWS IAM Privilege Escalation Analysis</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .chain { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; }
                .node { display: inline-block; padding: 5px 10px; margin: 5px; background-color: #f0f0f0; border-radius: 5px; }
                .arrow { display: inline-block; margin: 0 5px; }
                .privileged { background-color: #ffcccc; }
                .cross-account { background-color: #ffffcc; }
                .section { margin-top: 30px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>AWS IAM Privilege Escalation Analysis</h1>
            <p>Generated on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        """
        
        # Add privilege escalation chains section
        html += '<div class="section">'
        if chains:
            html += f"<h2>Found {len(chains)} privilege escalation chains</h2>"
            for i, chain in enumerate(chains):
                html += f'<div class="chain"><h3>Chain {i+1}</h3>'
                for j, role in enumerate(chain):
                    is_last = j == len(chain) - 1
                    html += f'<span class="node{" privileged" if is_last else ""}">{role}</span>'
                    if not is_last:
                        html += '<span class="arrow">→</span>'
                html += '</div>'
        else:
            html += "<h2>No privilege escalation chains found</h2>"
        html += '</div>'
        
        # Add cross-account findings section
        if cross_account_findings:
            html += '<div class="section">'
            html += f"<h2>Found {len(cross_account_findings)} roles with cross-account trust relationships</h2>"
            html += '<table>'
            html += '<tr><th>Role Name</th><th>External Principals</th></tr>'
            
            for role_name, principals in cross_account_findings.items():
                html += f'<tr><td>{role_name}</td><td>{", ".join(principals)}</td></tr>'
            
            html += '</table>'
            html += '</div>'
            
        html += """
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html)
        return output_file
    except Exception as e:
        print(f"[ERROR] Failed to generate visualization: {e}")
        return None

# Function to export results to CSV
def export_to_csv(chains, output_file="escalation_chains.csv"):
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Chain ID", "Path", "Length", "Target Privileged Role"])
            
            for i, chain in enumerate(chains):
                writer.writerow([
                    i+1,
                    " -> ".join(chain),
                    len(chain),
                    chain[-1]
                ])
        return output_file
    except Exception as e:
        print(f"[ERROR] Failed to export to CSV: {e}")
        return None

# Function to export cross-account findings to CSV
def export_cross_account_to_csv(findings, output_file="cross_account_findings.csv"):
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Role Name", "External Principals"])
            
            for role_name, principals in findings.items():
                writer.writerow([
                    role_name,
                    ", ".join(principals)
                ])
        return output_file
    except Exception as e:
        print(f"[ERROR] Failed to export cross-account findings to CSV: {e}")
        return None

# Progress bar function for console output
def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f"\r{prefix} |{bar}| {percent}% {suffix}")
    sys.stdout.flush()
    if iteration == total:
        print()

# === MAIN ===
parser = argparse.ArgumentParser(description="Detect IAM privilege escalation via role chaining.")
parser.add_argument("--profile", help="AWS CLI profile to use")
parser.add_argument("--filter", help="Only include roles starting with this prefix", default="")
parser.add_argument("--limit", type=int, help="Limit the number of roles to evaluate", default=None)
parser.add_argument("--cross-account", action="store_true", help="Check for cross-account trust relationships")
parser.add_argument("--output", choices=["text", "csv", "html", "all"], default="text", help="Output format")
parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed progress information")
parser.add_argument("--max-workers", type=int, default=8, help="Maximum number of parallel workers")
parser.add_argument("--batch-size", type=int, default=100, help="Batch size for processing roles")
args = parser.parse_args()

start_time = datetime.now()
print(f"[{start_time}] Starting IAM escalation chain analysis...")
print(f"[INFO] AWS Account ID: {get_account_id(args.profile)}")

# Set global verbosity
verbose = args.verbose

# Get account ID and roles with progress reporting
ACCOUNT_ID = get_account_id(args.profile)
roles = get_all_roles(args.profile)

# Filter roles
filtered_roles = [r for r in roles if r.startswith(args.filter)] if args.filter else list(roles.keys())
if args.limit:
    filtered_roles = filtered_roles[:args.limit]

print(f"[INFO] Filtering roles with prefix: '{args.filter}'")
print(f"[INFO] Evaluating {len(filtered_roles)}/{len(roles)} role(s)")
print(f"[INFO] Using {args.max_workers} parallel workers")

# Build graph with progress reporting
graph_start = time.time()
result = build_graph_parallel(filtered_roles, ACCOUNT_ID, args.profile)
graph = result["graph"]
cross_account_findings = result["cross_account_findings"]
graph_duration = time.time() - graph_start
print(f"[INFO] Graph building completed in {graph_duration:.2f} seconds")
print(f"[INFO] Escalation graph contains {len(graph)} roles with assume edges")
print(f"[INFO] Found {len(cross_account_findings)} roles with cross-account trust relationships")

# Find chains with progress reporting
chains_start = time.time()
chains = find_chains(graph, args.profile)
chains_duration = time.time() - chains_start
print(f"[INFO] Chain detection completed in {chains_duration:.2f} seconds")

# Overall completion
end_time = datetime.now()
duration = end_time - start_time
print(f"[{end_time}] Analysis completed. Total duration: {duration}")

# Print API statistics
print("\n=== AWS API Call Statistics ===")
print(f"Total API calls: {API_STATS['calls']}")
print(f"Cached responses: {API_STATS['cached']}")
print(f"Timeouts: {API_STATS['timeouts']}")
print(f"Errors: {API_STATS['errors']}")
print(f"Success rate: {((API_STATS['calls'] - API_STATS['timeouts'] - API_STATS['errors']) / max(1, API_STATS['calls']) * 100):.1f}%")

print(f"\n[SUMMARY] Roles analyzed: {len(filtered_roles)}, Graph nodes: {len(graph)}, Chains found: {len(chains)}, Cross-account findings: {len(cross_account_findings)}")

# Display chain results
if chains:
    print(f"[RESULT] Detected {len(chains)} privilege escalation chain(s):\n")
    for chain in chains:
        print("  " + " -> ".join(chain))

# Display cross-account findings summary if any
if cross_account_findings:
    print(f"\n[RESULT] Detected {len(cross_account_findings)} roles with cross-account trust relationships")

# Generate additional outputs if requested
if args.output in ["csv", "all"]:
    # Export chains if any
    if chains:
        csv_file = export_to_csv(chains)
        if csv_file:
            print(f"\n[INFO] Chain results exported to CSV: {csv_file}")
    
    # Export cross-account findings if any
    if cross_account_findings:
        cross_account_csv = export_cross_account_to_csv(cross_account_findings)
        if cross_account_csv:
            print(f"[INFO] Cross-account findings exported to CSV: {cross_account_csv}")

if args.output in ["html", "all"]:
    html_file = generate_visualization(chains, graph, cross_account_findings)
    if html_file:
        print(f"\n[INFO] Visualization generated: {html_file}")

# Show message if no findings
if not chains and not cross_account_findings:
    print("[RESULT] No privilege escalation chains or cross-account trust relationships found.")
elif not chains:
    print("[RESULT] No privilege escalation chains found.")
elif not cross_account_findings:
    print("[RESULT] No cross-account trust relationships found.")