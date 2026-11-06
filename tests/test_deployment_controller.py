"""
Project 8 — Controlled Deployment Security Tests

P8-H06: Machine-Verifiable Risk Acceptance

All identities, artifacts, release records, and trust
authority credentials are synthetic.

No external deployment occurs.

The fixture simulates an independently controlled trust
authority. Production deployment callers must not possess
the trust authority's signing key.
"""

import copy
import hashlib
import json
import sys
import tempfile
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.trust.registry import (
    TrustedReleaseRegistry,
    sign_synthetic_trust_record,
)

from src.deployment.controller import (
    ControlledDeploymentController,
    DeploymentSecurityError,
)

from src.policy.release_gate import ReleaseSecurityGate
from src.policy.governance import GovernanceDecisionEngine

from src.provenance.verifier import (
    ProvenanceTrustPolicy,
    sign_synthetic_attestation,
)


class TestControlledDeployment(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.directory = Path(self.temp.name)

        self.now = datetime(
            2026, 11, 4, 12, 0,
            tzinfo=timezone.utc,
        )

        self.secret = (
            b"synthetic-deployment-key-" + b"x" * 32
        )

        self.key_id = "ari-builder-key"
        self.builder = "ari-trusted-builder"
        self.source = "synthetic://ari/source/research"
        self.revision = "revision-001"

        trust_policy = ProvenanceTrustPolicy(
            trusted_keys={self.key_id: self.secret},
            allowed_builders=frozenset({self.builder}),
            allowed_sources=frozenset({self.source}),
            allowed_revisions=frozenset({self.revision}),
        )

        self.gate = ReleaseSecurityGate(trust_policy)

        self.governance = GovernanceDecisionEngine(
            authorized_approvers=frozenset({
                "ari-security-approver",
            }),
            authorized_risk_owners=frozenset({
                "ari-risk-owner",
            }),
        )

        self.trust_key = (
            b"ari-independent-deployment-trust-"
            + b"x" * 32
        )

        self.trust_issuer = "ari-security-authority"

        self.trust_registry = TrustedReleaseRegistry({
            self.trust_issuer: self.trust_key,
        })

        self.controller = ControlledDeploymentController(
            release_gate=self.gate,
            governance_engine=self.governance,
            storage_directory=self.directory / "snapshots",
            trust_registry=self.trust_registry,
        )

        baseline = json.loads(
            (
                ROOT
                / "data"
                / "synthetic"
                / "model-manifest.json"
            ).read_text(encoding="utf-8")
        )

        self.records = [copy.deepcopy(baseline)]
        self.component_id = self.records[0]["component_id"]

        self.artifact_bytes = (
            b"PROJECT8-DEPLOYMENT-MODEL-V1"
        )

        self.artifact_path = (
            self.directory / "research-assistant.bin"
        )

        self.artifact_path.write_bytes(self.artifact_bytes)

        self.digest = hashlib.sha256(
            self.artifact_bytes
        ).hexdigest()

        self.records[0]["artifact"][
            "expected_digest"
        ] = self.digest

        self.records[0]["artifact"][
            "size_bytes"
        ] = len(self.artifact_bytes)

        self.trusted_digests = {
            self.component_id: self.digest,
        }

        self._update_attestation()

        self.scan = {
            "schema_version": "1.0.0",
            "component_id": self.component_id,
            "scan_status": "completed",
            "coverage": {
                "dependencies": True,
                "artifact": True,
            },
            "findings": [],
        }

        self.evidence = {
            self.component_id: {
                "artifact_path": self.artifact_path,
                "attestation": self.attestation,
                "vulnerability_report": self.scan,
            },
        }

    def _update_attestation(self):
        claims = {
            "schema_version": "1.0.0",
            "subject_id": self.component_id,
            "subject_digest": self.digest,
            "builder_id": self.builder,
            "source_uri": self.source,
            "source_revision": self.revision,
            "key_id": self.key_id,
        }

        self.attestation = sign_synthetic_attestation(
            claims,
            self.secret,
        )

    def register_trusted_release(self, release_id):
        """
        Simulate independent trust-authority registration.

        This helper exists only in the test fixture.
        """

        claims = {
            "schema_version": "1.0.0",
            "release_id": release_id,
            "manifest_digest": (
                self.controller.manifest_digest(
                    self.records
                )
            ),
            "component_digests": dict(
                self.trusted_digests
            ),
            "issuer_id": self.trust_issuer,
        }

        signed = sign_synthetic_trust_record(
            claims,
            self.trust_key,
        )

        self.trust_registry.verify_and_register(signed)

    def request(self, release_id="ari-release-001"):
        digest = self.controller.manifest_digest(
            self.records
        )

        return {
            "schema_version": "1.0.0",
            "release_id": release_id,
            "manifest_digest": digest,
            "requester_id": "ari-release-engineer",
            "approver_id": "ari-security-approver",
            "decision": "approve",
            "justification": (
                "Synthetic deployment approval."
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

    def accept_current_risks(
        self,
        request,
        expires_after=timedelta(days=2),
    ):
        """
        Build risk acceptance from actual technical risks.

        This helper is test-only. It does not simulate
        authenticated approval by a real risk owner.
        """

        technical = self.gate.evaluate(
            records=self.records,
            evidence_by_component=self.evidence,
            trusted_digests=self.trusted_digests,
        )

        if technical.decision != "REVIEW":
            raise AssertionError(
                "Expected a REVIEW technical result."
            )

        if not technical.review_risks:
            raise AssertionError(
                "Technical review risks are missing."
            )

        request["risk_acceptance"] = {
            "accepted": True,
            "risk_owner_id": "ari-risk-owner",
            "release_id": request["release_id"],
            "manifest_digest": request["manifest_digest"],
            "accepted_risks": [
                {
                    "component_id": risk.component_id,
                    "risk_id": risk.risk_id,
                }
                for risk in technical.review_risks
            ],
            "justification": (
                "Time-limited synthetic exception."
            ),
            "expires_at": (
                self.now + expires_after
            ).isoformat(),
        }

        return request

    def rollback_request(self, release_id):
        request = self.request(release_id)
        request["operation"] = "rollback"
        return request

    def deploy(self, request=None):
        """
        Register authenticated release trust before
        invoking the deployment controller.
        """

        selected = (
            request if request is not None
            else self.request()
        )

        self.register_trusted_release(
            selected["release_id"]
        )

        return self.controller.deploy(
            records=self.records,
            evidence_by_component=self.evidence,
            trusted_digests=self.trusted_digests,
            governance_request=selected,
            now=self.now,
        )

    def second_release(self):
        self.artifact_bytes = (
            b"PROJECT8-DEPLOYMENT-MODEL-V2"
        )

        self.artifact_path.write_bytes(
            self.artifact_bytes
        )

        self.digest = hashlib.sha256(
            self.artifact_bytes
        ).hexdigest()

        self.records[0]["version"] = "2.0.0"

        self.records[0]["artifact"][
            "expected_digest"
        ] = self.digest

        self.records[0]["artifact"][
            "size_bytes"
        ] = len(self.artifact_bytes)

        self.trusted_digests[
            self.component_id
        ] = self.digest

        self._update_attestation()

        self.evidence[
            self.component_id
        ]["attestation"] = self.attestation

        return self.request("ari-release-002")

    def test_001_authorized_deployment(self):
        record = self.deploy()

        self.assertEqual(record.operation, "DEPLOY")
        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-001",
        )

    def test_002_modified_artifact_blocked(self):
        self.artifact_path.write_bytes(b"TAMPERED")

        with self.assertRaises(DeploymentSecurityError):
            self.deploy()

        self.assertIsNone(
            self.controller.active_release_id
        )

    def test_003_untrusted_digest_blocked(self):
        self.trusted_digests[
            self.component_id
        ] = "a" * 64

        with self.assertRaises(DeploymentSecurityError):
            self.deploy()

    def test_004_unauthorized_approver_blocked(self):
        request = self.request()
        request["approver_id"] = "attacker"

        with self.assertRaises(DeploymentSecurityError):
            self.deploy(request)

    def test_005_self_approval_blocked(self):
        request = self.request()
        request["requester_id"] = (
            "ari-security-approver"
        )

        with self.assertRaises(DeploymentSecurityError):
            self.deploy(request)

    def test_006_manifest_substitution_blocked(self):
        request = self.request()
        request["manifest_digest"] = "a" * 64

        with self.assertRaises(DeploymentSecurityError):
            self.deploy(request)

    def test_007_critical_vulnerability_blocked(self):
        self.scan["findings"] = [{
            "finding_id": "CVE-2099-9001",
            "component_id": self.component_id,
            "severity": "critical",
            "applicability": "affected",
            "evidence": "Synthetic blocking finding",
        }]

        with self.assertRaises(DeploymentSecurityError):
            self.deploy()

    def test_008_review_without_acceptance_blocked(self):
        self.scan["scan_status"] = "incomplete"

        with self.assertRaises(DeploymentSecurityError):
            self.deploy()

    def test_009_review_with_risk_acceptance(self):
        self.scan["scan_status"] = "incomplete"

        request = self.accept_current_risks(
            self.request()
        )

        self.assertEqual(
            request["risk_acceptance"]["accepted_risks"],
            [{
                "component_id": self.component_id,
                "risk_id": "POLICY:SCAN_INCOMPLETE",
            }],
        )

        record = self.deploy(request)

        self.assertEqual(record.operation, "DEPLOY")
        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-001",
        )

    def test_010_unknown_rollback_target_blocked(self):
        with self.assertRaises(DeploymentSecurityError):
            self.controller.rollback(
                "ari-release-unknown"
            )

    def test_011_successful_rollback(self):
        self.deploy()
        self.deploy(self.second_release())

        request = self.rollback_request(
            "ari-release-001"
        )

        original = self.controller._releases[
            "ari-release-001"
        ]

        request["manifest_digest"] = (
            original.manifest_digest
        )

        record = self.controller.rollback(
            "ari-release-001",
            governance_request=request,
            now=self.now,
        )

        self.assertEqual(record.operation, "ROLLBACK")
        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-001",
        )
        self.assertEqual(
            len(self.controller.audit_history),
            3,
        )

    def test_012_tampered_rollback_snapshot_blocked(self):
        self.deploy()
        self.deploy(self.second_release())

        snapshot = (
            self.directory
            / "snapshots"
            / "ari-release-001"
            / self.component_id
            / "research-assistant.bin"
        )

        snapshot.write_bytes(b"TAMPERED-SNAPSHOT")

        request = self.rollback_request(
            "ari-release-001"
        )

        request["manifest_digest"] = (
            self.controller._releases[
                "ari-release-001"
            ].manifest_digest
        )

        with self.assertRaises(DeploymentSecurityError):
            self.controller.rollback(
                "ari-release-001",
                governance_request=request,
                now=self.now,
            )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-002",
        )

    def test_013_duplicate_release_id_blocked(self):
        self.deploy()

        with self.assertRaises(DeploymentSecurityError):
            self.deploy()

    def test_014_rollback_to_active_release_blocked(self):
        self.deploy()

        with self.assertRaises(DeploymentSecurityError):
            self.controller.rollback(
                "ari-release-001"
            )

    def test_015_audit_chain_changes_with_operations(self):
        first = self.deploy()
        second = self.deploy(self.second_release())

        self.assertNotEqual(
            first.record_digest,
            second.record_digest,
        )
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)

    def test_016_no_activation_after_rejection(self):
        request = self.request()
        request["decision"] = "reject"

        with self.assertRaises(DeploymentSecurityError):
            self.deploy(request)

        self.assertIsNone(
            self.controller.active_release_id
        )
        self.assertEqual(
            len(self.controller.audit_history),
            0,
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)