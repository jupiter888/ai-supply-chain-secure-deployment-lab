"""
Project 8 — Synthetic Provenance Security Tests

Tests authentication, trust policy, and artifact
identity binding.

No production credentials or real infrastructure
are used.
"""

import copy
import hashlib
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.provenance.verifier import (
    ProvenanceTrustPolicy,
    ProvenanceVerifier,
    ProvenanceVerificationError,
    sign_synthetic_attestation,
)


class TestProvenanceVerifier(unittest.TestCase):

    def setUp(self):
        self.secret = b"synthetic-test-key-" + b"x" * 32

        self.subject_id = "model-research-assistant-v1"

        self.digest = hashlib.sha256(
            b"PROJECT8-SYNTHETIC-AI-MODEL-V1"
        ).hexdigest()

        self.policy = ProvenanceTrustPolicy(
            trusted_keys={"ari-builder-key": self.secret},
            allowed_builders=frozenset({
                "ari-trusted-builder"
            }),
            allowed_sources=frozenset({
                "synthetic://ari/source/research-assistant"
            }),
            allowed_revisions=frozenset({
                "revision-001"
            }),
        )

        self.verifier = ProvenanceVerifier(self.policy)

        self.claims = {
            "schema_version": "1.0.0",
            "subject_id": self.subject_id,
            "subject_digest": self.digest,
            "builder_id": "ari-trusted-builder",
            "source_uri": (
                "synthetic://ari/source/research-assistant"
            ),
            "source_revision": "revision-001",
            "key_id": "ari-builder-key",
        }

        self.attestation = sign_synthetic_attestation(
            self.claims,
            self.secret,
        )

    def verify(self, attestation):
        return self.verifier.verify(
            attestation,
            expected_subject_id=self.subject_id,
            expected_digest=self.digest,
        )

    def assert_rejected(self, attestation):
        with self.assertRaises(
            ProvenanceVerificationError
        ):
            self.verify(attestation)

    def test_001_valid_attestation(self):
        result = self.verify(self.attestation)
        self.assertTrue(result.verified)

    def test_002_verified_digest_bound_to_subject(self):
        result = self.verify(self.attestation)
        self.assertEqual(result.subject_digest, self.digest)
        self.assertEqual(result.subject_id, self.subject_id)

    def test_003_modified_builder_claim(self):
        attack = copy.deepcopy(self.attestation)
        attack["builder_id"] = "attacker-builder"
        self.assert_rejected(attack)

    def test_004_modified_source_claim(self):
        attack = copy.deepcopy(self.attestation)
        attack["source_uri"] = "synthetic://attacker/source"
        self.assert_rejected(attack)

    def test_005_modified_revision_claim(self):
        attack = copy.deepcopy(self.attestation)
        attack["source_revision"] = "revision-evil"
        self.assert_rejected(attack)

    def test_006_forged_signature(self):
        attack = copy.deepcopy(self.attestation)
        attack["signature"] = "0" * 64
        self.assert_rejected(attack)

    def test_007_unknown_key(self):
        attack = copy.deepcopy(self.attestation)
        attack["key_id"] = "attacker-key"
        self.assert_rejected(attack)

    def test_008_missing_signature(self):
        attack = copy.deepcopy(self.attestation)
        del attack["signature"]
        self.assert_rejected(attack)

    def test_009_unexpected_property(self):
        attack = copy.deepcopy(self.attestation)
        attack["deployment_authorized"] = True
        self.assert_rejected(attack)

    def test_010_wrong_artifact_digest(self):
        attack = copy.deepcopy(self.attestation)
        attack["subject_digest"] = "a" * 64
        self.assert_rejected(attack)

    def test_011_wrong_subject_identity(self):
        attack = copy.deepcopy(self.attestation)
        attack["subject_id"] = "model-attacker-v1"
        self.assert_rejected(attack)

    def test_012_unauthorized_builder_with_valid_hmac(self):
        claims = copy.deepcopy(self.claims)
        claims["builder_id"] = "attacker-builder"

        attack = sign_synthetic_attestation(
            claims,
            self.secret,
        )
        self.assert_rejected(attack)

    def test_013_unauthorized_source_with_valid_hmac(self):
        claims = copy.deepcopy(self.claims)
        claims["source_uri"] = "synthetic://attacker/source"

        attack = sign_synthetic_attestation(
            claims,
            self.secret,
        )
        self.assert_rejected(attack)

    def test_014_unauthorized_revision_with_valid_hmac(self):
        claims = copy.deepcopy(self.claims)
        claims["source_revision"] = "revision-evil"

        attack = sign_synthetic_attestation(
            claims,
            self.secret,
        )
        self.assert_rejected(attack)

    def test_015_wrong_expected_digest(self):
        with self.assertRaises(
            ProvenanceVerificationError
        ):
            self.verifier.verify(
                self.attestation,
                expected_subject_id=self.subject_id,
                expected_digest="b" * 64,
            )

    def test_016_wrong_expected_subject(self):
        with self.assertRaises(
            ProvenanceVerificationError
        ):
            self.verifier.verify(
                self.attestation,
                expected_subject_id="model-other-v1",
                expected_digest=self.digest,
            )

    def test_017_invalid_signature_encoding(self):
        attack = copy.deepcopy(self.attestation)
        attack["signature"] = "invalid"
        self.assert_rejected(attack)

    def test_018_invalid_attestation_type(self):
        self.assert_rejected("not-an-attestation")

    def test_019_invalid_signing_secret_rejected(self):
        with self.assertRaises(ValueError):
            sign_synthetic_attestation(
                self.claims,
                b"weak",
            )

    def test_020_empty_trust_policy_rejected(self):
        with self.assertRaises(ValueError):
            ProvenanceTrustPolicy(
                trusted_keys={},
                allowed_builders=frozenset(),
                allowed_sources=frozenset(),
                allowed_revisions=frozenset(),
            )

    def test_021_valid_hmac_cannot_override_digest_policy(self):
        claims = copy.deepcopy(self.claims)
        claims["subject_digest"] = "c" * 64

        attack = sign_synthetic_attestation(
            claims,
            self.secret,
        )

        self.assert_rejected(attack)

    def test_022_valid_hmac_cannot_override_subject_policy(self):
        claims = copy.deepcopy(self.claims)
        claims["subject_id"] = "model-substituted-v1"

        attack = sign_synthetic_attestation(
            claims,
            self.secret,
        )

        self.assert_rejected(attack)

if __name__ == "__main__":
    unittest.main(verbosity=2)