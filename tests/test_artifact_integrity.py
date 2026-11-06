"""
Project 8 — Artifact Integrity Security Tests

Tests:
    - Valid artifact verification
    - Modified artifact rejection
    - Forged manifest digest rejection
    - Invalid reference rejection
    - Artifact size mismatch
    - Missing artifact rejection
    - Symbolic-link rejection
    - Empty artifact handling
    - Immutable verification results

All artifacts are synthetic and generated locally.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.integrity.verifier import (
    ArtifactIntegrityError,
    ArtifactIntegrityVerifier,
)


class TestArtifactIntegrityVerifier(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.directory = Path(self.temp_dir.name)

        self.artifact_path = (
            self.directory / "synthetic-model.bin"
        )

        self.artifact_bytes = (
            b"PROJECT8-SYNTHETIC-AI-MODEL-V1"
        )

        self.artifact_path.write_bytes(
            self.artifact_bytes
        )

        self.trusted_digest = hashlib.sha256(
            self.artifact_bytes
        ).hexdigest()

        self.verifier = ArtifactIntegrityVerifier()

    def verify_baseline(self):
        return self.verifier.verify(
            artifact_path=self.artifact_path,
            trusted_digest=self.trusted_digest,
            declared_digest=self.trusted_digest,
            declared_size=len(self.artifact_bytes),
        )

    def test_001_valid_artifact(self):
        result = self.verify_baseline()

        self.assertTrue(result.verified)

    def test_002_calculated_digest_matches(self):
        result = self.verify_baseline()

        self.assertEqual(
            result.calculated_digest,
            self.trusted_digest,
        )

    def test_003_actual_size_matches(self):
        result = self.verify_baseline()

        self.assertEqual(
            result.size_bytes,
            len(self.artifact_bytes),
        )

    def test_004_modified_artifact_rejected(self):
        self.artifact_path.write_bytes(
            self.artifact_bytes + b"-TAMPERED"
        )

        with self.assertRaises(ArtifactIntegrityError):
            self.verify_baseline()

    def test_005_same_size_tampering_rejected(self):
        modified = bytearray(self.artifact_bytes)
        modified[0] ^= 1

        self.artifact_path.write_bytes(modified)

        with self.assertRaises(ArtifactIntegrityError):
            self.verify_baseline()

    def test_006_forged_manifest_digest_rejected(self):
        forged_digest = hashlib.sha256(
            b"ATTACKER-CONTROLLED-ARTIFACT"
        ).hexdigest()

        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest,
                declared_digest=forged_digest,
            )

    def test_007_invalid_reference_rejected(self):
        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest="invalid",
            )

    def test_008_uppercase_digest_rejected(self):
        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest.upper(),
            )

    def test_009_declared_size_mismatch(self):
        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest,
                declared_size=999999,
            )

    def test_010_missing_artifact_rejected(self):
        missing = self.directory / "missing.bin"

        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                missing,
                trusted_digest=self.trusted_digest,
            )

    def test_011_symbolic_link_rejected(self):
        link = self.directory / "artifact-link.bin"

        try:
            os.symlink(self.artifact_path, link)
        except (OSError, NotImplementedError):
            self.skipTest(
                "Symbolic links unavailable."
            )

        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                link,
                trusted_digest=self.trusted_digest,
            )

    def test_012_empty_artifact_valid_with_empty_digest(self):
        self.artifact_path.write_bytes(b"")

        empty_digest = hashlib.sha256(
            b""
        ).hexdigest()

        result = self.verifier.verify(
            self.artifact_path,
            trusted_digest=empty_digest,
            declared_size=0,
        )

        self.assertTrue(result.verified)
        self.assertEqual(result.size_bytes, 0)

    def test_013_empty_artifact_rejected_with_old_digest(self):
        self.artifact_path.write_bytes(b"")

        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest,
            )

    def test_014_boolean_size_rejected(self):
        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest,
                declared_size=True,
            )

    def test_015_negative_size_rejected(self):
        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest,
                declared_size=-1,
            )

    def test_016_result_is_immutable(self):
        result = self.verify_baseline()

        with self.assertRaises(FrozenInstanceError):
            result.verified = False

    def test_017_untrusted_digest_not_used_as_reference(self):
        attacker_bytes = b"ATTACKER-MODEL"

        self.artifact_path.write_bytes(
            attacker_bytes
        )

        attacker_digest = hashlib.sha256(
            attacker_bytes
        ).hexdigest()

        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.artifact_path,
                trusted_digest=self.trusted_digest,
                declared_digest=attacker_digest,
            )

    def test_018_digest_without_manifest_claim(self):
        result = self.verifier.verify(
            self.artifact_path,
            trusted_digest=self.trusted_digest,
        )

        self.assertTrue(result.verified)

    def test_019_unreadable_directory_rejected(self):
        with self.assertRaises(ArtifactIntegrityError):
            self.verifier.verify(
                self.directory,
                trusted_digest=self.trusted_digest,
            )

    def test_020_artifact_name_recorded(self):
        result = self.verify_baseline()

        self.assertEqual(
            result.artifact_name,
            "synthetic-model.bin",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)