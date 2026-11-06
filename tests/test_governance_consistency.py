"""
Project 8 — Adversarial Governance Consistency Tests

P8-H06: Technical Result Consistency Hardening

Tests malformed and contradictory technical gate
results and inactive risk acceptance records.

All evidence, identities, and releases are synthetic.
"""

import copy
import hashlib
import sys
import unittest

from dataclasses import replace
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
OTHER_COMPONENT_ID = "model-secondary-v1"
FINDING_RISK = "FINDING:CVE-2099-0001"
SCAN_RISK = "POLICY:SCAN_INCOMPLETE"


class TestGovernanceConsistency(unittest.TestCase):

    def setUp(self):
        self.now = datetime(
            2026, 11, 6, 12, 0,
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

        self.request = {
            "schema_version": "1.0.0",
            "release_id": self.release_id,
            "manifest_digest": self.manifest_digest,
            "requester_id": "ari-release-engineer",
            "approver_id": "ari-security-approver",
            "decision": "approve",
            "justification": "Synthetic security review.",
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

        self.finding = ReviewRisk(
            COMPONENT_ID,
            FINDING_RISK,
        )

    def technical(
        self,
        decision="ELIGIBLE",
        risks=None,
    ):
        if risks is None:
            risks = (
                (self.finding,)
                if decision == "REVIEW"
                else ()
            )

        risks = tuple(risks)

        component = ComponentGateResult(
            component_id=COMPONENT_ID,
            decision=decision,
            reasons=("Synthetic technical evaluation.",),
            review_risks=risks,
        )

        return ReleaseGateResult(
            decision=decision,
            component_results=(component,),
            evaluated_components=1,
            review_risks=risks,
        )

    def evaluate(self, technical_result):
        return self.engine.evaluate(
            request=self.request,
            technical_result=technical_result,
            expected_release_id=self.release_id,
            expected_manifest_digest=self.manifest_digest,
            now=self.now,
        )

    def assert_rejected(self, technical_result):
        with self.assertRaises(
            GovernanceValidationError
        ):
            self.evaluate(technical_result)

    def test_001_valid_eligible_result_approved(self):
        self.assertEqual(
            self.evaluate(self.technical()).decision,
            "APPROVED",
        )

    def test_002_component_count_mismatch_rejected(self):
        technical = replace(
            self.technical(),
            evaluated_components=2,
        )
        self.assert_rejected(technical)

    def test_003_missing_component_results_rejected(self):
        technical = replace(
            self.technical(),
            component_results=(),
        )
        self.assert_rejected(technical)

    def test_004_duplicate_components_rejected(self):
        technical = self.technical()
        component = technical.component_results[0]

        technical = replace(
            technical,
            component_results=(component, component),
            evaluated_components=2,
        )
        self.assert_rejected(technical)

    def test_005_eligible_release_with_review_component(self):
        technical = self.technical("REVIEW")

        technical = replace(
            technical,
            decision="ELIGIBLE",
        )
        self.assert_rejected(technical)

    def test_006_review_release_with_eligible_component(self):
        technical = replace(
            self.technical(),
            decision="REVIEW",
        )
        self.assert_rejected(technical)

    def test_007_blocked_component_must_block_release(self):
        technical = self.technical("BLOCKED")

        technical = replace(
            technical,
            decision="ELIGIBLE",
        )
        self.assert_rejected(technical)

    def test_008_missing_aggregate_review_risk(self):
        technical = replace(
            self.technical("REVIEW"),
            review_risks=(),
        )
        self.assert_rejected(technical)

    def test_009_extra_aggregate_review_risk(self):
        technical = self.technical("REVIEW")

        technical = replace(
            technical,
            review_risks=(
                self.finding,
                ReviewRisk(
                    COMPONENT_ID,
                    SCAN_RISK,
                ),
            ),
        )
        self.assert_rejected(technical)

    def test_010_duplicate_aggregate_review_risk(self):
        technical = replace(
            self.technical("REVIEW"),
            review_risks=(
                self.finding,
                self.finding,
            ),
        )
        self.assert_rejected(technical)

    def test_011_cross_component_risk_substitution(self):
        technical = self.technical("REVIEW")
        component = technical.component_results[0]

        substituted = ReviewRisk(
            OTHER_COMPONENT_ID,
            FINDING_RISK,
        )

        technical = replace(
            technical,
            component_results=(
                replace(
                    component,
                    review_risks=(substituted,),
                ),
            ),
            review_risks=(substituted,),
        )
        self.assert_rejected(technical)

    def test_012_eligible_component_with_review_risk(self):
        technical = self.technical()

        technical = replace(
            technical,
            component_results=(
                replace(
                    technical.component_results[0],
                    review_risks=(self.finding,),
                ),
            ),
            review_risks=(self.finding,),
        )
        self.assert_rejected(technical)

    def test_013_review_component_without_risks(self):
        technical = self.technical("REVIEW")

        technical = replace(
            technical,
            component_results=(
                replace(
                    technical.component_results[0],
                    review_risks=(),
                ),
            ),
        )
        self.assert_rejected(technical)

    def test_014_inactive_acceptance_with_risk_owner(self):
        self.request["risk_acceptance"][
            "risk_owner_id"
        ] = "ari-risk-owner"

        self.assert_rejected(self.technical())

    def test_015_inactive_acceptance_with_scope(self):
        self.request["risk_acceptance"][
            "accepted_risks"
        ] = [{
            "component_id": COMPONENT_ID,
            "risk_id": FINDING_RISK,
        }]

        self.assert_rejected(self.technical())

    def test_016_inactive_acceptance_with_expiry(self):
        self.request["risk_acceptance"][
            "expires_at"
        ] = (
            self.now + timedelta(days=2)
        ).isoformat()

        self.assert_rejected(self.technical())

    def test_017_valid_review_without_acceptance(self):
        result = self.evaluate(
            self.technical("REVIEW")
        )
        self.assertEqual(
            result.decision,
            "REVIEW_REQUIRED",
        )

    def test_018_valid_blocked_result_rejected(self):
        result = self.evaluate(
            self.technical("BLOCKED")
        )
        self.assertEqual(
            result.decision,
            "REJECTED",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)