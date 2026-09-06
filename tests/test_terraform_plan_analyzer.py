import json
import os
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import terraform_plan_analyzer as tpa

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "fixtures", "tfplan.json")


class TestTerraformPlanAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(FIXTURE) as f:
            cls.plan = json.load(f)
        cls.analyzer = tpa.TerraformPlanAnalyzer()
        cls.findings = cls.analyzer.analyze_plan(cls.plan)

    def test_parses_resources(self):
        resources = tpa.TerraformPlanParser.extract_resources(self.plan)
        self.assertTrue(any(r.get("type") == "aws_security_group" for r in resources))
        self.assertTrue(any(r.get("type") == "aws_s3_bucket" for r in resources))
        self.assertTrue(any(r.get("type") == "aws_iam_policy" for r in resources))

    def test_detects_public_admin_port(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Public Admin Port", cats)

    def test_detects_open_firewall(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Open Firewall Rule", cats)

    def test_detects_public_database_port(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Public Database Port", cats)

    def test_detects_iAM_admin_access(self):
        cats = [f.category for f in self.findings]
        self.assertIn("IAM Admin Access", cats)

    def test_detects_public_s3(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Public S3 Bucket", cats)
        self.assertIn("Public S3 Policy", cats)

    def test_detects_public_rds(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Public RDS Instance", cats)

    def test_detects_unencrypted_ebs(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Unencrypted EBS Volume", cats)

    def test_detects_azure_http(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Azure Storage HTTP", cats)

    def test_detects_public_sqs(self):
        cats = [f.category for f in self.findings]
        self.assertIn("Public SQS Queue", cats)

    def test_findings_have_remediation(self):
        report = tpa.findings_to_json(self.findings)
        for f in report["findings"]:
            self.assertTrue(f["remediation"])

    def test_severity_counts_present(self):
        report = tpa.findings_to_json(self.findings)
        self.assertGreaterEqual(report["summary"].get("CRITICAL", 0), 1)

    def test_clean_analysis_no_findings_for_secure_sg(self):
        secure_values = {
            "name": "secure",
            "ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp",
                         "cidr_blocks": ["10.0.0.0/8"]}],
            "egress": []
        }
        resources = [{"type": "aws_security_group", "address": "a.s",
                      "values": secure_values}]
        findings = self.analyzer._analyze(resources)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
