"""
Project 8 — Governance Decision Security Tests

P8-H06: Machine-Verifiable Risk Acceptance
P8-H06: Technical Result Consistency Fixture Hardening

Tests:
- Authorized governance decisions
- Separation of duties
- Release and manifest binding
- Component-specific risk acceptance
- Finding-specific risk acceptance
- Exact risk coverage
- Expiration enforcement
- Fail-closed technical decisions
- Consistent release/component technical evidence

All identities, releases, and findings are synthetic.
"""

import copy
import hashlib
import sys
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.policy.governance import (
    GovernanceDecisionEngine,
    GovernanceValidationError,
)

from src.policy.release_gate import (
    ComponentGateResult,
    ReleaseGateResult,
    ReviewRisk,
)


COMPONENT_ID = "model-research-assistant-v1"

FINDING_RISK = "FINDING:CVE-2099-0001"
SECOND_FINDING_RISK = "FINDING:CVE-2099-0002"

SCAN_RISK = "POLICY:SCAN_INCOMPLETE"
COVERAGE_RISK = "POLICY:COVERAGE_INCOMPLETE"


class TestGovernanceDecisionEngine(unittest.TestCase):

    def setUp(self):
        self.now = datetime(
            2026, 11, 4, 12, 0,
            tzinfo=timezone.utc,
        )

        self.release_id = "ari-release-001"

        self.manifest_digest = hashlib.sha256(
            b"synthetic-release-manifest"
        ).hexdigest()

        self.engine = GovernanceDecisionEngine(
            authorized_approvers=frozenset({
                "ari-security-approver",
            }),
            authorized_risk_owners=frozenset({
                "ari-risk-owner",
            }),
        )

        self.review_risks = (
            ReviewRisk(
                component_id=COMPONENT_ID,
                risk_id=FINDING_RISK,
            ),
        )

        self.request = {
            "schema_version": "1.0.0",
            "release_id": self.release_id,
            "manifest_digest": self.manifest_digest,
            "requester_id": "ari-release-engineer",
            "approver_id": "ari-security-approver",
            "decision": "approve",
            "justification": (
                "Synthetic release security review."
            ),
            "expires_at": (
                self.now + timedelta(days=7)
            ).isoformat(),
            "risk_acceptance": {
                "accepted": False,
                "risk_owner_id": None,
                "release_id": None,
                "manifest_digest": None,
                "accepted_risks": [],
                "justification": None,
                "expires_at": None,
            },
        }

    def technical(
        self,
        decision="ELIGIBLE",
        risks=None,
    ):
        """
        Construct internally consistent synthetic
        technical gate evidence.

        Deliberately malformed risk collections are
        preserved for adversarial test cases.
        """

        if risks is None:
            risks = (
                self.review_risks
                if decision == "REVIEW"
                else ()
            )

        risks = tuple(risks)

        component = ComponentGateResult(
            component_id=COMPONENT_ID,
            decision=decision,
            reasons=(
                "Synthetic technical gate evaluation.",
            ),
            review_risks=risks,
        )

        return ReleaseGateResult(
            decision=decision,
            component_results=(component,),
            evaluated_components=1,
            review_risks=risks,
        )

    def evaluate(
        self,
        decision="ELIGIBLE",
        risks=None,
    ):
        return self.engine.evaluate(
            request=self.request,
            technical_result=self.technical(
                decision,
                risks,
            ),
            expected_release_id=self.release_id,
            expected_manifest_digest=(
                self.manifest_digest
            ),
            now=self.now,
        )

    def enable_risk_acceptance(self):
        self.request["risk_acceptance"] = {
            "accepted": True,
            "risk_owner_id": "ari-risk-owner",
            "release_id": self.release_id,
            "manifest_digest": self.manifest_digest,
            "accepted_risks": [
                {
                    "component_id": COMPONENT_ID,
                    "risk_id": FINDING_RISK,
                },
            ],
            "justification": (
                "Compensating controls and monitored "
                "limited-duration exception."
            ),
            "expires_at": (
                self.now + timedelta(days=3)
            ).isoformat(),
        }

    def assert_invalid_review(self):
        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("REVIEW")

    # --------------------------------------------------
    # Existing governance scenarios — 001 through 030
    # --------------------------------------------------

    def test_001_valid_approval(self):
        self.assertEqual(
            self.evaluate().decision,
            "APPROVED",
        )

    def test_002_unauthorized_approver(self):
        self.request["approver_id"] = "attacker"

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_003_self_approval_rejected(self):
        self.request["requester_id"] = (
            "ari-security-approver"
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_004_wrong_release_id(self):
        self.request["release_id"] = (
            "ari-release-002"
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_005_wrong_manifest_digest(self):
        self.request["manifest_digest"] = "a" * 64

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_006_expired_approval(self):
        self.request["expires_at"] = (
            self.now - timedelta(seconds=1)
        ).isoformat()

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_007_blocked_gate_cannot_be_approved(self):
        self.assertEqual(
            self.evaluate("BLOCKED").decision,
            "REJECTED",
        )

    def test_008_review_without_risk_acceptance(self):
        self.assertEqual(
            self.evaluate("REVIEW").decision,
            "REVIEW_REQUIRED",
        )

    def test_009_valid_risk_acceptance(self):
        self.enable_risk_acceptance()

        result = self.evaluate("REVIEW")

        self.assertEqual(result.decision, "APPROVED")
        self.assertEqual(
            result.risk_owner_id,
            "ari-risk-owner",
        )

    def test_010_unauthorized_risk_owner(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "risk_owner_id"
        ] = "attacker"

        self.assert_invalid_review()

    def test_011_requester_cannot_accept_risk(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "risk_owner_id"
        ] = "ari-release-engineer"

        self.assert_invalid_review()

    def test_012_approver_cannot_accept_risk(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "risk_owner_id"
        ] = "ari-security-approver"

        self.assert_invalid_review()

    def test_013_expired_risk_acceptance(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "expires_at"
        ] = (
            self.now - timedelta(seconds=1)
        ).isoformat()

        self.assert_invalid_review()

    def test_014_risk_acceptance_outlives_approval(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "expires_at"
        ] = (
            self.now + timedelta(days=10)
        ).isoformat()

        self.assert_invalid_review()

    def test_015_missing_risk_scope(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "accepted_risks"
        ] = []

        self.assert_invalid_review()

    def test_016_missing_risk_justification(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "justification"
        ] = None

        self.assert_invalid_review()

    def test_017_unnecessary_risk_acceptance(self):
        self.enable_risk_acceptance()

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("ELIGIBLE")

    def test_018_authorized_rejection(self):
        self.request["decision"] = "reject"

        self.assertEqual(
            self.evaluate().decision,
            "REJECTED",
        )

    def test_019_unknown_governance_decision(self):
        self.request["decision"] = "override"

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_020_unknown_technical_decision(self):
        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("UNKNOWN")

    def test_021_extra_request_field(self):
        self.request["override"] = True

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_022_missing_request_field(self):
        del self.request["approver_id"]

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_023_naive_timestamp(self):
        self.request["expires_at"] = (
            "2026-11-10T12:00:00"
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_024_record_digest_is_deterministic(self):
        first = self.evaluate()
        second = self.evaluate()

        self.assertEqual(
            first.record_digest,
            second.record_digest,
        )

    def test_025_changed_justification_changes_digest(self):
        first = self.evaluate()

        self.request["justification"] = (
            "Updated synthetic governance review."
        )

        second = self.evaluate()

        self.assertNotEqual(
            first.record_digest,
            second.record_digest,
        )

    def test_026_risk_acceptance_must_be_boolean(self):
        self.request["risk_acceptance"][
            "accepted"
        ] = "true"

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_027_invalid_schema_version(self):
        self.request["schema_version"] = "2.0.0"

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_028_rejected_technical_gate_precedence(self):
        result = self.evaluate("BLOCKED")

        self.assertNotEqual(
            result.decision,
            "APPROVED",
        )

    def test_029_invalid_manifest_digest_format(self):
        self.request["manifest_digest"] = (
            "not-a-digest"
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate()

    def test_030_risk_owner_not_recorded_without_exception(self):
        self.assertIsNone(
            self.evaluate().risk_owner_id
        )

    # --------------------------------------------------
    # P8-H06 adversarial scope-binding tests
    # --------------------------------------------------

    def test_031_cross_release_acceptance_rejected(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "release_id"
        ] = "ari-release-002"

        self.assert_invalid_review()

    def test_032_cross_manifest_acceptance_rejected(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "manifest_digest"
        ] = "b" * 64

        self.assert_invalid_review()

    def test_033_cross_component_acceptance_rejected(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "accepted_risks"
        ][0]["component_id"] = "package-attacker-v1"

        self.assert_invalid_review()

    def test_034_missing_finding_acceptance_rejected(self):
        self.enable_risk_acceptance()

        risks = (
            ReviewRisk(COMPONENT_ID, FINDING_RISK),
            ReviewRisk(COMPONENT_ID, SECOND_FINDING_RISK),
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("REVIEW", risks)

    def test_035_unrelated_finding_acceptance_rejected(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "accepted_risks"
        ].append({
            "component_id": COMPONENT_ID,
            "risk_id": SECOND_FINDING_RISK,
        })

        self.assert_invalid_review()

    def test_036_duplicate_accepted_risk_rejected(self):
        self.enable_risk_acceptance()

        first = copy.deepcopy(
            self.request["risk_acceptance"][
                "accepted_risks"
            ][0]
        )

        self.request["risk_acceptance"][
            "accepted_risks"
        ].append(first)

        self.assert_invalid_review()

    def test_037_expired_exception_rejected(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "expires_at"
        ] = (
            self.now - timedelta(days=1)
        ).isoformat()

        self.assert_invalid_review()

    def test_038_blocked_gate_cannot_be_overridden(self):
        self.enable_risk_acceptance()

        result = self.evaluate("BLOCKED")

        self.assertEqual(
            result.decision,
            "REJECTED",
        )

    def test_039_missing_policy_risk_rejected(self):
        self.enable_risk_acceptance()

        risks = (
            ReviewRisk(COMPONENT_ID, FINDING_RISK),
            ReviewRisk(COMPONENT_ID, SCAN_RISK),
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("REVIEW", risks)

    def test_040_exact_multiple_risks_approved(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "accepted_risks"
        ].append({
            "component_id": COMPONENT_ID,
            "risk_id": SCAN_RISK,
        })

        risks = (
            ReviewRisk(COMPONENT_ID, FINDING_RISK),
            ReviewRisk(COMPONENT_ID, SCAN_RISK),
        )

        result = self.evaluate("REVIEW", risks)

        self.assertEqual(
            result.decision,
            "APPROVED",
        )

    def test_041_empty_review_risks_fail_closed(self):
        self.enable_risk_acceptance()

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("REVIEW", ())

    def test_042_duplicate_technical_risks_rejected(self):
        self.enable_risk_acceptance()

        risks = (
            ReviewRisk(COMPONENT_ID, FINDING_RISK),
            ReviewRisk(COMPONENT_ID, FINDING_RISK),
        )

        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate("REVIEW", risks)

    def test_043_unknown_policy_risk_rejected(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "accepted_risks"
        ][0]["risk_id"] = "POLICY:UNRECOGNIZED"

        self.assert_invalid_review()

    def test_044_namespaced_collision_is_distinct(self):
        self.enable_risk_acceptance()

        self.request["risk_acceptance"][
            "accepted_risks"
        ] = [
            {
                "component_id": COMPONENT_ID,
                "risk_id": "FINDING:SCAN_INCOMPLETE",
            },
            {
                "component_id": COMPONENT_ID,
                "risk_id": SCAN_RISK,
            },
        ]

        risks = (
            ReviewRisk(
                COMPONENT_ID,
                "FINDING:SCAN_INCOMPLETE",
            ),
            ReviewRisk(
                COMPONENT_ID,
                SCAN_RISK,
            ),
        )

        result = self.evaluate("REVIEW", risks)

        self.assertEqual(
            result.decision,
            "APPROVED",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)