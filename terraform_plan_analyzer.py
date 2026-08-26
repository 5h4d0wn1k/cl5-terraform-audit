#!/usr/bin/env python3
"""CL5 — Terraform Plan Analyzer: Audit TF plans for security misconfigurations."""

import json
import re
import sys
import os
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class Finding:
    severity: str
    category: str
    resource: str
    address: str
    message: str

    def __str__(self):
        return f"[{self.severity}] {self.category} | {self.resource} ({self.address}): {self.message}"


class TerraformPlanParser:
    """Parse Terraform plan JSON output."""

    @staticmethod
    def load_plan(filepath: str) -> Dict[str, Any]:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Plan file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data

    @staticmethod
    def extract_resources(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        resources = []
        format_version = plan.get("format_version", "")
        pl = plan.get("planned_values", plan.get("prior_state", {}))

        if isinstance(pl, dict):
            root = pl.get("root_module", {})
            resources.extend(TerraformPlanParser._walk_module(root))

        for change_key in ("resource_changes", "configuration"):
            if change_key in plan:
                items = plan[change_key]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and "address" in item:
                            resources.append(item)
                elif isinstance(items, dict) and "resources" in items:
                    for item in items["resources"]:
                        if isinstance(item, dict):
                            resources.append(item)

        return TerraformPlanParser._deduplicate(resources)

    @staticmethod
    def _walk_module(module: Dict) -> List[Dict]:
        resources = []
        for res in module.get("resources", []):
            if isinstance(res, dict):
                resources.append(res)
        for child in module.get("child_modules", []):
            if isinstance(child, dict):
                resources.extend(TerraformPlanParser._walk_module(child))
        return resources

    @staticmethod
    def _deduplicate(resources: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for r in resources:
            addr = r.get("address", id(r))
            if addr not in seen:
                seen.add(addr)
                unique.append(r)
        return unique


class SecurityGroupAuditor:
    """Audit security groups for dangerous rules."""

    DANGEROUS_PORTS = {
        22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
        27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
        9200: "Elasticsearch", 5601: "Kibana", 2375: "Docker API",
        2376: "Docker TLS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        1433: "MSSQL", 1521: "Oracle", 5984: "CouchDB",
    }

    OPEN_CIDRS = {"0.0.0.0/0", "::/0", "0.0.0.0/0,::/0"}

    def audit(self, resources: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        for res in resources:
            rtype = res.get("type", "")
            if rtype in ("aws_security_group", "aws_security_group_rule",
                         "aws_network_acl_rule", "azurerm_network_security_group",
                         "azurerm_network_security_rule"):
                findings.extend(self._audit_sg(res))
        return findings

    def _audit_sg(self, res: Dict) -> List[Finding]:
        findings: List[Finding] = []
        addr = res.get("address", "unknown")
        rtype = res.get("type", "")
        values = res.get("values", res.get("change", {}).get("after", {}))
        if not isinstance(values, dict):
            return findings

        name = values.get("name", values.get("id", "unnamed"))
        rtype_label = rtype.split("_")[-1] if "_" in rtype else rtype

        ingress_rules = values.get("ingress", [])
        egress_rules = values.get("egress", [])

        if isinstance(values.get("security_group_ingress"), list):
            ingress_rules = values["security_group_ingress"]
        if isinstance(values.get("security_group_egress"), list):
            egress_rules = values["security_group_egress"]

        if isinstance(values.get("rule"), list):
            for rule in values["rule"]:
                if isinstance(rule, dict) and rule.get("type") == "ingress":
                    ingress_rules.append(rule)

        for direction, rules in [("ingress", ingress_rules), ("egress", egress_rules)]:
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                findings.extend(self._check_rule(rule, direction, rtype_label, name, addr))

        if not ingress_rules and not egress_rules:
            findings.append(Finding(
                severity="MEDIUM",
                category="Empty Security Group",
                resource=rtype_label,
                address=addr,
                message=f"Security group '{name}' has no explicit rules",
            ))

        return findings

    def _check_rule(self, rule: Dict, direction: str, rtype: str, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []

        cidrs = set()
        for field in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_block", "source",
                       "source_address_prefix", "destination_address_prefix"):
            val = rule.get(field, [])
            if isinstance(val, str):
                cidrs.add(val)
            elif isinstance(val, list):
                cidrs.update(val)

        from_port = rule.get("from_port", rule.get("destination_port_range", rule.get("port_range", "")))
        to_port = rule.get("to_port", rule.get("destination_port_range", rule.get("port_range", "")))
        protocol = rule.get("protocol", rule.get("protocol", ""))

        is_open = any(c in self.OPEN_CIDRS for c in cidrs)

        if is_open:
            findings.append(Finding(
                severity="HIGH",
                category="Open Firewall Rule",
                resource=rtype,
                address=addr,
                message=f"{direction.capitalize()} rule on '{name}': allows traffic from 0.0.0.0/0",
            ))

            if self._is_ssh_rdp(from_port, to_port, protocol):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Public Admin Port",
                    resource=rtype,
                    address=addr,
                    message=f"SSH/RDP exposed to internet on '{name}' (ports {from_port}-{to_port})",
                ))

            if self._is_sensitive_port(from_port, to_port):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Public Database Port",
                    resource=rtype,
                    address=addr,
                    message=f"Sensitive service exposed to internet on '{name}' (ports {from_port}-{to_port})",
                ))

        if protocol in ("-1", "all", "*"):
            findings.append(Finding(
                severity="MEDIUM",
                category="All Protocols Allowed",
                resource=rtype,
                address=addr,
                message=f"{direction.capitalize()} rule allows all protocols on '{name}'",
            ))

        return findings

    def _is_ssh_rdp(self, from_port, to_port, protocol) -> bool:
        try:
            fp = int(from_port)
            tp = int(to_port)
            return (fp <= 22 <= tp) or (fp <= 3389 <= tp)
        except (ValueError, TypeError):
            return False

    def _is_sensitive_port(self, from_port, to_port) -> bool:
        try:
            fp = int(from_port)
            tp = int(to_port)
            for p in self.DANGEROUS_PORTS:
                if fp <= p <= tp:
                    return True
        except (ValueError, TypeError):
            pass
        return False


class IAMPrivilegeEscalationAuditor:
    """Detect IAM privilege escalation paths."""

    ESCALATION_ACTIONS = {
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:CreatePolicy",
        "iam:PassRole",
        "sts:AssumeRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode",
        "ec2:RunInstances",
        "ec2:CreateInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:CreateInstanceProfile",
        "iam:PassRole",
    }

    ADMIN_ACTIONS = {"*"}
    ADMIN_ACTIONS_PREFIX = {"iam:*", "sts:*", "ec2:*", "s3:*"}

    def audit(self, resources: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        for res in resources:
            rtype = res.get("type", "")
            if rtype in ("aws_iam_policy", "aws_iam_role_policy",
                         "aws_iam_user_policy", "aws_iam_group_policy",
                         "aws_iam_policy_attachment", "aws_iam_role",
                         "aws_iam_user", "aws_iam_user_policy_attachment"):
                findings.extend(self._audit_iam(res))
        return findings

    def _audit_iam(self, res: Dict) -> List[Finding]:
        findings: List[Finding] = []
        addr = res.get("address", "unknown")
        rtype = res.get("type", "")
        values = res.get("values", res.get("change", {}).get("after", {}))
        if not isinstance(values, dict):
            return findings

        name = values.get("name", values.get("id", "unnamed"))
        all_actions = self._extract_actions(values)

        escalation_found = all_actions & self.ESCALATION_ACTIONS
        if escalation_found:
            findings.append(Finding(
                severity="CRITICAL",
                category="IAM Privilege Escalation",
                resource=rtype,
                address=addr,
                message=f"'{name}' grants escalation actions: {sorted(escalation_found)}",
            ))

        if "*" in all_actions:
            findings.append(Finding(
                severity="CRITICAL",
                category="IAM Admin Access",
                resource=rtype,
                address=addr,
                message=f"'{name}' grants wildcard (*) admin access",
            ))

        for prefix in self.ADMIN_ACTIONS_PREFIX:
            if prefix in all_actions and prefix != "*":
                findings.append(Finding(
                    severity="HIGH",
                    category="IAM Broad Access",
                    resource=rtype,
                    address=addr,
                    message=f"'{name}' grants broad access: {prefix}",
                ))

        if "sts:AssumeRole" in all_actions:
            findings.append(Finding(
                severity="HIGH",
                category="Role Chaining",
                resource=rtype,
                address=addr,
                message=f"'{name}' can assume other roles (potential lateral movement)",
            ))

        return findings

    def _extract_actions(self, values: Dict) -> set:
        actions = set()
        for field in ("actions", "Action", "not_actions"):
            val = values.get(field, [])
            if isinstance(val, str):
                actions.add(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        actions.add(item)
                    elif isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, str):
                                actions.add(v)
                            elif isinstance(v, list):
                                actions.update(v)

        policy_doc = values.get("policy", values.get("policy_json", ""))
        if isinstance(policy_doc, str) and policy_doc:
            try:
                parsed = json.loads(policy_doc)
                for stmt in parsed.get("Statement", []):
                    act = stmt.get("Action", [])
                    if isinstance(act, str):
                        actions.add(act)
                    elif isinstance(act, list):
                        actions.update(act)
            except (json.JSONDecodeError, AttributeError):
                pass
        elif isinstance(policy_doc, dict):
            for stmt in policy_doc.get("Statement", []):
                act = stmt.get("Action", [])
                if isinstance(act, str):
                    actions.add(act)
                elif isinstance(act, list):
                    actions.update(act)

        return actions


class PublicExposureDetector:
    """Detect publicly exposed resources."""

    PUBLIC_INDICATORS = {
        "publicly_accessible": True,
        "public": True,
    }

    def detect(self, resources: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        for res in resources:
            findings.extend(self._check_resource(res))
        return findings

    def _check_resource(self, res: Dict) -> List[Finding]:
        findings: List[Finding] = []
        rtype = res.get("type", "")
        addr = res.get("address", "unknown")
        values = res.get("values", res.get("change", {}).get("after", {}))
        if not isinstance(values, dict):
            return findings

        name = values.get("name", values.get("id", "unnamed"))

        if rtype == "aws_s3_bucket":
            findings.extend(self._check_s3(values, name, addr))
        elif rtype == "aws_s3_bucket_public_access_block":
            findings.extend(self._check_s3_public_block(values, name, addr))
        elif rtype == "aws_db_instance":
            findings.extend(self._check_rds(values, name, addr))
        elif rtype in ("aws_elasticache_cluster", "aws_elasticache_replication_group"):
            findings.extend(self._check_elasticache(values, name, addr))
        elif rtype == "aws_ebs_volume":
            findings.extend(self._check_ebs(values, name, addr))
        elif rtype in ("azurerm_storage_account",):
            findings.extend(self._check_azure_storage(values, name, addr))
        elif rtype == "aws_sns_topic":
            pass
        elif rtype == "aws_sqs_queue":
            findings.extend(self._check_sqs(values, name, addr))
        elif rtype in ("aws_mq_broker", "aws_mq_configuration"):
            findings.extend(self._check_mq(values, name, addr, rtype))

        return findings

    def _check_s3(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        acl = values.get("acl", "")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            findings.append(Finding(
                severity="CRITICAL",
                category="Public S3 Bucket",
                resource="aws_s3_bucket",
                address=addr,
                message=f"Bucket '{name}' has public ACL: {acl}",
            ))

        policy = values.get("policy", "")
        if isinstance(policy, str) and policy:
            try:
                parsed = json.loads(policy)
                for stmt in parsed.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    effect = stmt.get("Effect", "")
                    if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                        findings.append(Finding(
                            severity="CRITICAL",
                            category="Public S3 Policy",
                            resource="aws_s3_bucket",
                            address=addr,
                            message=f"Bucket '{name}' policy grants access to everyone",
                        ))
            except (json.JSONDecodeError, AttributeError):
                pass

        versioning = values.get("versioning", [])
        if isinstance(versioning, list):
            for v in versioning:
                if isinstance(v, dict) and not v.get("enabled"):
                    findings.append(Finding(
                        severity="MEDIUM",
                        category="S3 Versioning Disabled",
                        resource="aws_s3_bucket",
                        address=addr,
                        message=f"Bucket '{name}' has versioning disabled",
                    ))
                    break

        return findings

    def _check_s3_public_block(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        blocking = all(not values.get(f) for f in [
            "block_public_acls", "block_public_policy",
            "ignore_public_acls", "restrict_public_buckets",
        ])
        if blocking:
            findings.append(Finding(
                severity="HIGH",
                category="S3 Public Access Not Blocked",
                resource="aws_s3_bucket_public_access_block",
                address=addr,
                message=f"Public access block '{name}' is fully disabled",
            ))
        return findings

    def _check_rds(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        if values.get("publicly_accessible"):
            findings.append(Finding(
                severity="CRITICAL",
                category="Public RDS Instance",
                resource="aws_db_instance",
                address=addr,
                message=f"RDS instance '{name}' is publicly accessible",
            ))
        if values.get("storage_encrypted") is False:
            findings.append(Finding(
                severity="HIGH",
                category="RDS Unencrypted Storage",
                resource="aws_db_instance",
                address=addr,
                message=f"RDS instance '{name}' has unencrypted storage",
            ))
        if values.get("backup_retention_period", 0) == 0:
            findings.append(Finding(
                severity="MEDIUM",
                category="RDS No Backups",
                resource="aws_db_instance",
                address=addr,
                message=f"RDS instance '{name}' has no automated backups",
            ))
        return findings

    def _check_elasticache(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        if values.get("publicly_accessible"):
            findings.append(Finding(
                severity="HIGH",
                category="Public ElastiCache",
                resource="elasticache",
                address=addr,
                message=f"ElastiCache '{name}' is publicly accessible",
            ))
        return findings

    def _check_ebs(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        if not values.get("encrypted"):
            findings.append(Finding(
                severity="MEDIUM",
                category="Unencrypted EBS Volume",
                resource="aws_ebs_volume",
                address=addr,
                message=f"EBS volume '{name}' is not encrypted",
            ))
        return findings

    def _check_azure_storage(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        if values.get("enable_https_traffic_only") is False:
            findings.append(Finding(
                severity="HIGH",
                category="Azure Storage HTTP",
                resource="azurerm_storage_account",
                address=addr,
                message=f"Storage account '{name}' allows HTTP traffic",
            ))
        return findings

    def _check_sqs(self, values: Dict, name: str, addr: str) -> List[Finding]:
        findings: List[Finding] = []
        policy = values.get("policy", "")
        if isinstance(policy, str) and policy:
            try:
                parsed = json.loads(policy)
                for stmt in parsed.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                        findings.append(Finding(
                            severity="HIGH",
                            category="Public SQS Queue",
                            resource="aws_sqs_queue",
                            address=addr,
                            message=f"Queue '{name}' policy grants access to everyone",
                        ))
            except (json.JSONDecodeError, AttributeError):
                pass
        return findings

    def _check_mq(self, values: Dict, name: str, addr: str, rtype: str) -> List[Finding]:
        findings: List[Finding] = []
        if values.get("publicly_accessible"):
            findings.append(Finding(
                severity="CRITICAL",
                category="Public MQ Broker",
                resource=rtype,
                address=addr,
                message=f"MQ broker '{name}' is publicly accessible",
            ))
        return findings


class TerraformPlanAnalyzer:
    """Main analyzer orchestrator."""

    def __init__(self):
        self.parser = TerraformPlanParser()
        self.sg_auditor = SecurityGroupAuditor()
        self.iam_auditor = IAMPrivilegeEscalationAuditor()
        self.exposure_detector = PublicExposureDetector()

    def analyze_file(self, filepath: str) -> List[Finding]:
        plan = self.parser.load_plan(filepath)
        resources = self.parser.extract_resources(plan)
        return self._analyze(resources)

    def analyze_plan(self, plan: Dict[str, Any]) -> List[Finding]:
        resources = self.parser.extract_resources(plan)
        return self._analyze(resources)

    def _analyze(self, resources: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self.sg_auditor.audit(resources))
        findings.extend(self.iam_auditor.audit(resources))
        findings.extend(self.exposure_detector.detect(resources))
        return findings

    def print_report(self, findings: List[Finding]):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

        print("\n" + "=" * 70)
        print("  CL5 — Terraform Plan Analyzer Report")
        print("=" * 70)

        if not sorted_findings:
            print("\n  No security issues found.\n")
            return

        counts = {}
        for f in sorted_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        print("\n  Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                print(f"    {sev}: {counts[sev]}")
        print(f"    TOTAL: {len(sorted_findings)}")
        print()

        for f in sorted_findings:
            print(f"  {f}")

        print("\n" + "=" * 70 + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CL5 — Terraform Plan Analyzer")
    parser.add_argument("plan_file", help="Terraform plan JSON file")
    args = parser.parse_args()

    analyzer = TerraformPlanAnalyzer()

    try:
        findings = analyzer.analyze_file(args.plan_file)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in plan file: {e}", file=sys.stderr)
        sys.exit(1)

    analyzer.print_report(findings)

    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    if critical > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
