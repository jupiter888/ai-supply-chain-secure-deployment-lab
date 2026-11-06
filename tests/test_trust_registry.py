"""
Project 8 — Trusted Release Registry Tests

Synthetic offline trust-boundary validation.
"""

import copy
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.trust.registry import (
    TrustedReleaseRegistry,
    TrustRegistryError,
    sign_synthetic_trust_record,
)


class TestTrustedReleaseRegistry(unittest.TestCase):

    def setUp(self):
        self.secret = b"ari-independent-trust-key-" + b"x" * 32
        self.attacker_key = b"attacker-controlled-key-" + b"z" * 32

        self.registry = TrustedReleaseRegistry({
            "ari-security-authority": self.secret,
        })

        self.digest = hashlib.sha256(
            b"AUTHORIZED-ARTIFACT"
        ).hexdigest()

        self.manifest_digest = hashlib.sha256(
            b"AUTHORIZED-MANIFEST"
        ).hexdigest()

        self.claims = {
            "schema_version": "1.0.0",
            "release_id": "ari-release-001",
            "manifest_digest": self.manifest_digest,
            "component_digests": {
                "model-research-assistant-v1": self.digest,
            },
            "issuer_id": "ari-security-authority",
        }

    def signed(self, claims=None, secret=None):
        return sign_synthetic_trust_record(
            claims if claims is not None else self.claims,
            secret if secret is not None else self.secret,
        )

    def test_001_authorized_record_accepted(self):
        trusted = self.registry.verify_and_register(
            self.signed()
        )

        self.assertEqual(
            trusted.release_id,
            "ari-release-001",
        )

    def test_002_unregistered_release_rejected(self):
        with self.assertRaises(TrustRegistryError):
            self.registry.require(
                "ari-release-001",
                self.manifest_digest,
                {"model-research-assistant-v1": self.digest},
            )

    def test_003_registered_release_matches(self):
        self.registry.verify_and_register(self.signed())

        trusted = self.registry.require(
            "ari-release-001",
            self.manifest_digest,
            {"model-research-assistant-v1": self.digest},
        )

        self.assertEqual(
            dict(trusted.component_digests),
            {"model-research-assistant-v1": self.digest},
        )

    def test_004_artifact_digest_substitution_rejected(self):
        self.registry.verify_and_register(self.signed())

        attacker_digest = hashlib.sha256(
            b"ATTACKER-ARTIFACT"
        ).hexdigest()

        with self.assertRaises(TrustRegistryError):
            self.registry.require(
                "ari-release-001",
                self.manifest_digest,
                {
                    "model-research-assistant-v1":
                        attacker_digest
                },
            )

    def test_005_manifest_substitution_rejected(self):
        self.registry.verify_and_register(self.signed())

        with self.assertRaises(TrustRegistryError):
            self.registry.require(
                "ari-release-001",
                "a" * 64,
                {"model-research-assistant-v1": self.digest},
            )

    def test_006_attacker_signature_rejected(self):
        forged = self.signed(
            secret=self.attacker_key
        )

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(forged)

    def test_007_tampered_signed_digest_rejected(self):
        forged = self.signed()
        forged["component_digests"][
            "model-research-assistant-v1"
        ] = "b" * 64

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(forged)

    def test_008_unknown_issuer_rejected(self):
        claims = copy.deepcopy(self.claims)
        claims["issuer_id"] = "untrusted-issuer"

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(
                self.signed(claims)
            )

    def test_009_conflicting_registration_rejected(self):
        self.registry.verify_and_register(self.signed())

        changed = copy.deepcopy(self.claims)
        changed["component_digests"][
            "model-research-assistant-v1"
        ] = "c" * 64

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(
                self.signed(changed)
            )

    def test_010_identical_registration_idempotent(self):
        first = self.registry.verify_and_register(
            self.signed()
        )
        second = self.registry.verify_and_register(
            self.signed()
        )

        self.assertEqual(first, second)

    def test_011_missing_signature_rejected(self):
        record = self.signed()
        del record["signature"]

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(record)

    def test_012_unknown_field_rejected(self):
        record = self.signed()
        record["debug_override"] = True

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(record)

    def test_013_invalid_digest_rejected(self):
        claims = copy.deepcopy(self.claims)
        claims["component_digests"][
            "model-research-assistant-v1"
        ] = "not-a-digest"

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(
                self.signed(claims)
            )

    def test_014_empty_component_mapping_rejected(self):
        claims = copy.deepcopy(self.claims)
        claims["component_digests"] = {}

        with self.assertRaises(TrustRegistryError):
            self.registry.verify_and_register(
                self.signed(claims)
            )

    def test_015_short_issuer_key_rejected(self):
        with self.assertRaises(TrustRegistryError):
            TrustedReleaseRegistry({
                "ari-security-authority": b"short",
            })

    def test_016_signature_cannot_be_supplied_as_claim(self):
        claims = copy.deepcopy(self.claims)
        claims["signature"] = "a" * 64

        with self.assertRaises(TrustRegistryError):
            sign_synthetic_trust_record(
                claims,
                self.secret,
            )

if __name__ == "__main__":
    unittest.main(verbosity=2)