# CL5 — Terraform Plan Analyzer

Audit Terraform plans for security misconfigurations, privilege escalation, and public exposure.

## Overview

This project implements a static analysis tool that:
- Parses Terraform plan JSON output
- Audits security groups for dangerous open ports and CIDR rules
- Detects IAM privilege escalation paths and admin access
- Identifies publicly exposed resources (S3, RDS, ElastiCache, MQ, SQS)
- Checks encryption status, backup configuration, and storage settings

## Features

- **Plan Parsing**: Extract resources from `terraform plan -json` output
- **Security Group Audit**: Detect SSH/RDP exposure, database ports, open CIDRs
- **IAM Analysis**: Find escalation actions, wildcard policies, role chaining
- **Public Exposure Detection**: S3 ACLs, RDS public access, storage encryption
- **Severity Ranking**: CRITICAL through LOW with summary report

## Usage

```bash
# Generate plan JSON
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Analyze the plan
python3 terraform_plan_analyzer.py tfplan.json
```

## Requirements

- Python 3.7+ (standard library only)

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the infrastructure owner before using this tool
- Unauthorized access to cloud infrastructure is illegal under federal and state laws
- This tool should ONLY be used on infrastructure you own or have written authorization to audit

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own infrastructure
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
