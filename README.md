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

# Offline demo (no Terraform/cloud required)
python3 terraform_plan_analyzer.py --demo

# Write a JSON report
python3 terraform_plan_analyzer.py plan.json --output reports/plan-report.json

# CI-friendly exit codes (2 when CRITICAL/HIGH findings exist)
python3 terraform_plan_analyzer.py plan.json --exit-code-on-findings
```

## Exit Codes

- `0` — analysis completed (no CRITICAL/HIGH findings, or `--exit-code-on-findings` not passed)
- `1` — file/missing-fixture/runtime error
- `2` — analysis completed with CRITICAL or HIGH findings (`--exit-code-on-findings`)

## Requirements

- Python 3.7+ (standard library only)

## Live Lab Test Plan

Runs entirely offline against the bundled `fixtures/tfplan.json` — no Terraform binary, no cloud account, no credentials.

1. **Demo**: `python3 terraform_plan_analyzer.py --demo` — expect CRITICAL/HIGH/MEDIUM findings for the open SSH+MySQL SGs, public S3, admin IAM policy, public RDS, unencrypted EBS, HTTP-only Azure storage, and public SQS. Exit code `0`.
2. **JSON report**: `python3 terraform_plan_analyzer.py --demo --output reports/demo.json` — verify `reports/demo.json` has `finding_count > 0`, per-finding `severity/category/address/message/remediation`, and a `summary` map.
3. **CI exit code**: `python3 terraform_plan_analyzer.py --demo --exit-code-on-findings; echo $?` — expect `2`.
4. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (exercises the real parser + all three auditors against the fixture).
5. **Live (optional)**: run `terraform plan -out=tfplan && terraform show -json tfplan > tfplan.json` in *your own* account, then analyze — detections use the same rule engine as the fixtures.

## Metrics

- 3 auditor engines: SecurityGroupAuditor, IAMPrivilegeEscalationAuditor, PublicExposureDetector
- Detection rules exercised offline: Open Firewall Rule, Public Admin Port, Public Database Port, All Protocols Allowed, Empty Security Group, IAM Admin Access / Privilege Escalation / Broad Access / Role Chaining, Public S3 (ACL + policy), S3 Versioning Disabled, S3 Public Access Block disabled, Public RDS, RDS Unencrypted / No Backups, Unencrypted EBS, Azure Storage HTTP, Public SQS
- Every finding carries a remediation string (`findings_to_json`)
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`)
- Zero third-party dependencies; fixture mode exercises the exact same code path as live plan files

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
