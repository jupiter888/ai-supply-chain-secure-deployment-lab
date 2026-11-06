"""
Project 8 — Risk Acceptance Integration Security Tests

P8-H06: Machine-Verifiable Risk Acceptance

Adversarial end-to-end validation of:
- Cross-release acceptance substitution
- Cross-manifest acceptance substitution
- Cross-component acceptance substitution
- Finding identifier substitution
- Missing required risk acceptance
- Additional unauthorized risk acceptance
- Duplicate risk acceptance
- Policy/finding namespace collision
- Critical vulnerability denial
- Valid exact risk acceptance

All components, vulnerabilities, identities, releases,
and approval records are synthetic.

No external deployment occurs.
"""

import copy
import sys
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_deployment_controller as deployment_fixtures

from src.deployment.controller import (
    DeploymentSecurityError,
)


class TestRiskAcceptanceIntegration(unittest.TestCase):

    def setUp(self):
        self.fixture = (
            deployment_fixtures.TestControlledDeployment(
                methodName="test_001_authorized_deployment"
            )
        )

        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

        self.controller = self.fixture.controller
        self.component_id = self.fixture.component_id

    def review_request(self):
        """
        Configure an incomplete synthetic scan and
        construct exact, authorized risk acceptance.
        """

        self.fixture.scan["scan_status"] = "incomplete"

        request = self.fixture.request()

        return self.fixture.accept_current_risks(
            request
        )

    def add_finding(
        self,
        finding_id,
        severity="medium",
        applicability="affected",
    ):
        self.fixture.scan["findings"].append({
            "finding_id": finding_id,
            "component_id": self.component_id,
            "severity": severity,
            "applicability": applicability,
            "evidence": (
                "Synthetic adversarial test finding."
            ),
        })

    def assert_deployment_blocked(self, request):
        """
        A rejected deployment must not activate a
        release or create a successful audit entry.
        """

        with self.assertRaises(
            DeploymentSecurityError
        ):
            self.fixture.deploy(request)

        self.assertIsNone(
            self.controller.active_release_id
        )

        self.assertEqual(
            len(self.controller.audit_history),
            0,
        )

    # --------------------------------------------------
    # P8-H06-INT-001
    # Cross-release acceptance substitution
    # --------------------------------------------------

    def test_001_cross_release_acceptance_blocked(self):
        request = self.review_request()

        request["risk_acceptance"][
            "release_id"
        ] = "ari-release-002"

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-002
    # Cross-manifest acceptance substitution
    # --------------------------------------------------

    def test_002_cross_manifest_acceptance_blocked(self):
        request = self.review_request()

        request["risk_acceptance"][
            "manifest_digest"
        ] = "a" * 64

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-003
    # Cross-component risk substitution
    # --------------------------------------------------

    def test_003_cross_component_acceptance_blocked(self):
        request = self.review_request()

        request["risk_acceptance"][
            "accepted_risks"
        ][0]["component_id"] = "attacker-component-v1"

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-004
    # Finding identifier substitution
    # --------------------------------------------------

    def test_004_finding_substitution_blocked(self):
        self.add_finding(
            "CVE-2099-0001",
            severity="medium",
        )

        request = self.review_request()

        accepted = request["risk_acceptance"][
            "accepted_risks"
        ]

        finding_entries = [
            entry for entry in accepted
            if entry["risk_id"].startswith("FINDING:")
        ]

        self.assertEqual(
            len(finding_entries),
            1,
        )

        finding_entries[0]["risk_id"] = (
            "FINDING:CVE-2099-9999"
        )

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-005
    # Missing required risk acceptance
    # --------------------------------------------------

    def test_005_missing_required_risk_blocked(self):
        self.add_finding(
            "CVE-2099-0002",
            severity="medium",
        )

        request = self.review_request()

        accepted = request["risk_acceptance"][
            "accepted_risks"
        ]

        self.assertGreaterEqual(
            len(accepted),
            2,
        )

        accepted.pop()

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-006
    # Additional unrelated risk acceptance
    # --------------------------------------------------

    def test_006_extra_risk_acceptance_blocked(self):
        request = self.review_request()

        request["risk_acceptance"][
            "accepted_risks"
        ].append({
            "component_id": self.component_id,
            "risk_id": "FINDING:CVE-2099-9999",
        })

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-007
    # Duplicate risk acceptance
    # --------------------------------------------------

    def test_007_duplicate_risk_acceptance_blocked(self):
        request = self.review_request()

        accepted = request["risk_acceptance"][
            "accepted_risks"
        ]

        accepted.append(
            copy.deepcopy(accepted[0])
        )

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-008
    # Policy/finding namespace collision
    # --------------------------------------------------

    def test_008_policy_finding_collision_blocked(self):
        """
        A finding named SCAN_INCOMPLETE must not be
        accepted merely by accepting the policy
        condition POLICY:SCAN_INCOMPLETE.
        """

        self.add_finding(
            "SCAN_INCOMPLETE",
            severity="medium",
        )

        request = self.review_request()

        accepted = request["risk_acceptance"][
            "accepted_risks"
        ]

        risk_ids = {
            entry["risk_id"]
            for entry in accepted
        }

        self.assertIn(
            "FINDING:SCAN_INCOMPLETE",
            risk_ids,
        )

        self.assertIn(
            "POLICY:SCAN_INCOMPLETE",
            risk_ids,
        )

        request["risk_acceptance"][
            "accepted_risks"
        ] = [
            entry for entry in accepted
            if entry["risk_id"] != (
                "FINDING:SCAN_INCOMPLETE"
            )
        ]

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-009
    # Critical vulnerability cannot be overridden
    # --------------------------------------------------

    def test_009_critical_vulnerability_cannot_be_accepted(self):
        request = self.review_request()

        self.add_finding(
            "CVE-2099-CRITICAL",
            severity="critical",
        )

        request["risk_acceptance"][
            "accepted_risks"
        ].append({
            "component_id": self.component_id,
            "risk_id": "FINDING:CVE-2099-CRITICAL",
        })

        self.assert_deployment_blocked(request)

    # --------------------------------------------------
    # P8-H06-INT-010
    # Valid exact risk acceptance
    # --------------------------------------------------

    def test_010_valid_exact_risk_acceptance(self):
        self.add_finding(
            "CVE-2099-0003",
            severity="medium",
        )

        request = self.review_request()

        accepted_ids = {
            entry["risk_id"]
            for entry in request["risk_acceptance"][
                "accepted_risks"
            ]
        }

        self.assertEqual(
            accepted_ids,
            {
                "POLICY:SCAN_INCOMPLETE",
                "FINDING:CVE-2099-0003",
            },
        )

        record = self.fixture.deploy(request)

        self.assertEqual(
            record.operation,
            "DEPLOY",
        )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-001",
        )

        self.assertEqual(
            len(self.controller.audit_history),
            1,
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)