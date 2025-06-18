# AWS Security Audit Toolkit

This toolkit provides a comprehensive set of scripts for conducting AWS security audits across multiple accounts and regions.

## Scripts Overview

### Account Summary and Statistics

1. **account_summary.py**
   - Provides high-level statistics about AWS accounts
   - Shows IAM Identity Center vs. traditional IAM usage
   - Identifies Control Tower managed accounts
   - Summarizes IAM users, roles, groups, and policies

### IAM Security Analysis

2. **detect_chain_escalation_parallel.py**
   - Detects IAM privilege escalation chains
   - Identifies roles that can assume higher privileges
   - Analyzes cross-account trust relationships

3. **analyze_iam_permissions.py**
   - Reviews IAM policies for cross-account access
   - Assesses role permissions and adherence to least privilege
   - Identifies roles with PassRole permissions

4. **iam_risk_analyzer.py**
   - Identifies accounts and roles with elevated privileges
   - Analyzes trust policy conditions
   - Provides risk scoring for IAM configurations

5. **analyze_scps.py**
   - Assesses Service Control Policies (SCPs) implementation
   - Identifies overly permissive or restrictive SCPs
   - Provides recommendations for SCP improvements

6. **analyze_access_analyzer.py**
   - Leverages IAM Access Analyzer to identify external access
   - Detects resources shared with external entities
   - Provides severity-based findings and recommendations

7. **analyze_identity_center.py**
   - Analyzes AWS IAM Identity Center (SSO) configuration
   - Reviews permission sets and account assignments
   - Evaluates AD integration and security settings

### Organization and Account Management

8. **analyze_control_tower.py**
   - Analyzes AWS Control Tower configuration
   - Checks enabled guardrails and controls
   - Identifies drift and compliance issues
   - Evaluates security of Control Tower managed accounts

### Resource Security Analysis

9. **aws_service_inventory.py**
   - Performs inventory of all services across AWS accounts
   - Identifies resources and their configurations
   - Detects publicly accessible resources

10. **analyze_public_resources.py**
    - Evaluates risk posture of internet-facing services
    - Provides risk scoring for public resources
    - Generates mitigation recommendations

11. **check_public_resources.py**
    - Scans for specific types of public resources
    - Checks security configurations of resources
    - Identifies unintended public access

### Logging and Monitoring Analysis

12. **analyze_logging.py**
    - Reviews current logging practices
    - Checks CloudTrail, CloudWatch Logs, Config, and VPC Flow Logs
    - Ensures comprehensive and reliable data capture

13. **analyze_monitoring.py**
    - Verifies adequacy of CloudWatch alarms
    - Checks GuardDuty and Security Hub configurations
    - Recommends improvements to alerting and response processes

## Usage Instructions

### Step 0: Get Account Summary

Start by getting a high-level overview of your accounts:

```bash
# Get summary for a single account
python account_summary.py

# Get summary for multiple accounts
python account_summary.py --accounts prod dev test --profiles prod-admin dev-admin test-admin
```

### Step 1: IAM and Organization Security Analysis

Next, analyze IAM configurations and organizational controls:

```bash
# Detect privilege escalation chains
python detect_chain_escalation_parallel.py --output csv

# Analyze IAM permissions
python analyze_iam_permissions.py --all

# Analyze IAM risk posture
python iam_risk_analyzer.py --chains-file escalation_chains.csv --html-report

# Analyze Service Control Policies
python analyze_scps.py --profile management-account

# Analyze IAM Access Analyzer findings
python analyze_access_analyzer.py --profile admin

# Analyze IAM Identity Center (SSO)
python analyze_identity_center.py --profile admin

# Analyze Control Tower configuration
python analyze_control_tower.py --profile management-account
```

### Step 2: Service Inventory and Public Resource Analysis

Then, inventory all services and analyze public resources:

```bash
# Inventory services across multiple accounts
python aws_service_inventory.py --accounts prod dev test --profiles prod-admin dev-admin test-admin --output aws_inventory.csv

# Analyze public resources from inventory
python analyze_public_resources.py --inventory aws_inventory.csv

# Check for specific public resources
python check_public_resources.py
```

### Step 3: Logging and Monitoring Analysis

Finally, analyze logging and monitoring configurations:

```bash
# Analyze logging practices
python analyze_logging.py --profile admin --regions us-east-1 us-west-2 eu-west-1

# Analyze monitoring and alerting
python analyze_monitoring.py --profile admin --regions us-east-1 us-west-2 eu-west-1
```