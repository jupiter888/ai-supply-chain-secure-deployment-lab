"""
Project 8 — Deployment Trust Enforcement Tests

Adversarial integration tests for P8-H03.

These tests establish that deployment cannot rely
solely on caller-supplied artifact digests.

All artifacts, identities, and signing keys are
synthetic and used only in local tests.
"""

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_deployment_controller as deployment_fixtures

from src.deployment.controller import (
    ControlledDeploymentController,
    DeploymentSecurityError,
)

from src.trust.registry import (
    TrustedReleaseRegistry,
    sign_synthetic_trust_record,
)


class TestDeploymentTrustEnforcement(unittest.TestCase):

    def setUp(self):
        self.fixture = (
            deployment_fixtures.TestControlledDeployment(
                methodName="test_001_authorized_deployment"
            )
        )

        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

        self.trust_key = (
            b"ari-independent-trust-authority-"
            + b"x" * 32
        )

        self.issuer_id = "ari-security-authority"

        self.registry = TrustedReleaseRegistry({
            self.issuer_id: self.trust_key,
        })

        self.controller = ControlledDeploymentController(
            release_gate=self.fixture.gate,
            governance_engine=self.fixture.governance,
            storage_directory=(
                self.fixture.directory / "trusted-snapshots"
            ),
            trust_registry=self.registry,
        )

    def _trust_record(self, release_id="ari-release-001"):
        return {
            "schema_version": "1.0.0",
            "release_id": release_id,
            "manifest_digest": (
                self.controller.manifest_digest(
                    self.fixture.records
                )
            ),
            "component_digests": dict(
                self.fixture.trusted_digests
            ),
            "issuer_id": self.issuer_id,
        }

    def _register(self, claims=None):
        record = sign_synthetic_trust_record(
            claims if claims is not None
            else self._trust_record(),
            self.trust_key,
        )

        return self.registry.verify_and_register(
            record
        )

    def _deploy(self, request=None):
        return self.controller.deploy(
            records=self.fixture.records,
            evidence_by_component=self.fixture.evidence,
            trusted_digests=self.fixture.trusted_digests,
            governance_request=(
                request if request is not None
                else self.fixture.request()
            ),
            now=self.fixture.now,
        )

    def test_001_unregistered_release_rejected(self):
        """
        A technically valid release without an
        authenticated trust record must not deploy.
        """

        with self.assertRaises(
            DeploymentSecurityError
        ):
            self._deploy()

        self.assertIsNone(
            self.controller.active_release_id
        )

    def test_002_matching_attacker_digest_rejected(self):
        """
        An attacker controlling both artifact bytes
        and caller-supplied digest must not bypass
        the independently registered digest.
        """

        self._register()

        attacker_bytes = (
            b"ATTACKER-CONTROLLED-MODEL"
        )

        attacker_digest = hashlib.sha256(
            attacker_bytes
        ).hexdigest()

        self.fixture.artifact_path.write_bytes(
            attacker_bytes
        )

        self.fixture.records[0]["artifact"][
            "expected_digest"
        ] = attacker_digest

        self.fixture.records[0]["artifact"][
            "size_bytes"
        ] = len(attacker_bytes)

        self.fixture.trusted_digests[
            self.fixture.component_id
        ] = attacker_digest

        self.fixture.digest = attacker_digest
        self.fixture._update_attestation()

        self.fixture.evidence[
            self.fixture.component_id
        ]["attestation"] = (
            self.fixture.attestation
        )

        request = self.fixture.request()

        with self.assertRaises(
            DeploymentSecurityError
        ):
            self._deploy(request)

        self.assertIsNone(
            self.controller.active_release_id
        )

    def test_003_registered_manifest_mismatch_rejected(self):
        """
        An authenticated release record must bind
        the exact release manifest.
        """

        self._register()

        self.fixture.records[0][
            "version"
        ] = "9.9.9"

        request = self.fixture.request()

        with self.assertRaises(
            DeploymentSecurityError
        ):
            self._deploy(request)

        self.assertIsNone(
            self.controller.active_release_id
        )

    def test_004_registered_release_deploys(self):
        """
        Matching authenticated trust, technical
        evidence, and governance authorization
        should permit deployment.
        """

        self._register()

        result = self._deploy()

        self.assertEqual(
            result.operation,
            "DEPLOY",
        )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-001",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)