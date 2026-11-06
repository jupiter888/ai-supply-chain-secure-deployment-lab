"""
Project 8 — Release Security Gate Integration Tests

Tests fail-closed behavior across inventory,
integrity, provenance, and vulnerability controls.

All artifacts, identities, and attestations are
synthetic. No deployment occurs.
"""

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.policy.release_gate import ReleaseSecurityGate
from src.provenance.verifier import (
    ProvenanceTrustPolicy,
    sign_synthetic_attestation,
)


class TestReleaseSecurityGate(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.directory = Path(self.temp.name)

        self.secret = b"project8-synthetic-key-" + b"x" * 32

        self.builder = "ari-trusted-builder"
        self.source = "synthetic://ari/source/research"
        self.revision = "revision-001"
        self.key_id = "ari-builder-key"

        policy = ProvenanceTrustPolicy(
            trusted_keys={
                self.key_id: self.secret
            },
            allowed_builders=frozenset({
                self.builder
            }),
            allowed_sources=frozenset({
                self.source
            }),
            allowed_revisions=frozenset({
                self.revision
            }),
        )

        self.gate = ReleaseSecurityGate(policy)

        manifest_path = (
            PROJECT_ROOT
            / "data"
            / "synthetic"
            / "model-manifest.json"
        )

        self.baseline = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )

        self.records = []
        self.evidence = {}
        self.trusted_digests = {}

        self.add_component(
            "model-research-assistant-v1",
            b"SYNTHETIC-RESEARCH-MODEL-V1",
            "model",
        )

    def add_component(
        self,
        component_id,
        content,
        component_type,
        dependencies=None,
    ):
        filename = f"{component_id}.bin"
        path = self.directory / filename
        path.write_bytes(content)

        digest = hashlib.sha256(
            content
        ).hexdigest()

        manifest = copy.deepcopy(
            self.baseline
        )

        manifest["component_id"] = component_id
        manifest["component_type"] = component_type
        manifest["name"] = component_id
        manifest["dependencies"] = (
            dependencies or []
        )
        manifest["artifact"]["filename"] = filename
        manifest["artifact"]["expected_digest"] = digest
        manifest["artifact"]["size_bytes"] = len(content)

        claims = {
            "schema_version": "1.0.0",
            "subject_id": component_id,
            "subject_digest": digest,
            "builder_id": self.builder,
            "source_uri": self.source,
            "source_revision": self.revision,
            "key_id": self.key_id,
        }

        attestation = sign_synthetic_attestation(
            claims,
            self.secret,
        )

        scan_report = {
            "schema_version": "1.0.0",
            "component_id": component_id,
            "scan_status": "completed",
            "coverage": {
                "dependencies": True,
                "artifact": True,
            },
            "findings": [],
        }

        self.records.append(manifest)

        self.evidence[component_id] = {
            "artifact_path": path,
            "attestation": attestation,
            "vulnerability_report": scan_report,
        }

        self.trusted_digests[
            component_id
        ] = digest

        return path

    def evaluate(self):
        return self.gate.evaluate(
            self.records,
            self.evidence,
            self.trusted_digests,
        )

    def test_001_valid_candidate_eligible(self):
        result = self.evaluate()

        self.assertEqual(
            result.decision,
            "ELIGIBLE",
        )
        self.assertEqual(
            result.evaluated_components,
            1,
        )

    def test_002_modified_artifact_blocked(self):
        path = self.evidence[
            "model-research-assistant-v1"
        ]["artifact_path"]

        path.write_bytes(
            b"ATTACKER-MODIFIED-MODEL"
        )

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_003_forged_manifest_digest_blocked(self):
        self.records[0][
            "artifact"
        ]["expected_digest"] = "a" * 64

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_004_missing_trusted_digest_blocked(self):
        self.trusted_digests.clear()

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_005_missing_provenance_blocked(self):
        self.evidence[
            "model-research-assistant-v1"
        ]["attestation"] = None

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_006_forged_attestation_blocked(self):
        self.evidence[
            "model-research-assistant-v1"
        ]["attestation"]["builder_id"] = "attacker"

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_007_critical_vulnerability_blocked(self):
        report = self.evidence[
            "model-research-assistant-v1"
        ]["vulnerability_report"]

        report["findings"] = [{
            "finding_id": "CVE-2099-0001",
            "component_id": "model-research-assistant-v1",
            "severity": "critical",
            "applicability": "affected",
            "evidence": "Synthetic critical finding",
        }]

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_008_medium_vulnerability_requires_review(self):
        report = self.evidence[
            "model-research-assistant-v1"
        ]["vulnerability_report"]

        report["findings"] = [{
            "finding_id": "CVE-2099-0002",
            "component_id": "model-research-assistant-v1",
            "severity": "medium",
            "applicability": "affected",
            "evidence": "Synthetic medium finding",
        }]

        self.assertEqual(
            self.evaluate().decision,
            "REVIEW",
        )

    def test_009_incomplete_scan_requires_review(self):
        self.evidence[
            "model-research-assistant-v1"
        ]["vulnerability_report"][
            "scan_status"
        ] = "incomplete"

        self.assertEqual(
            self.evaluate().decision,
            "REVIEW",
        )

    def test_010_missing_component_evidence_blocked(self):
        self.evidence.clear()

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_011_extra_component_evidence_blocked(self):
        self.evidence["attacker-component"] = {}

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_012_duplicate_inventory_id_blocked(self):
        self.records.append(
            copy.deepcopy(self.records[0])
        )

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_013_missing_dependency_blocked(self):
        self.records[0]["dependencies"] = [
            "package-missing-v1"
        ]

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_014_two_component_release_eligible(self):
        self.add_component(
            "package-research-utils-v1",
            b"SYNTHETIC-PACKAGE-V1",
            "package",
        )

        self.records[0]["dependencies"] = [
            "package-research-utils-v1"
        ]

        result = self.evaluate()

        self.assertEqual(
            result.decision,
            "ELIGIBLE",
        )
        self.assertEqual(
            result.evaluated_components,
            2,
        )

    def test_015_dependency_vulnerability_blocks_release(self):
        self.add_component(
            "package-research-utils-v1",
            b"SYNTHETIC-PACKAGE-V1",
            "package",
        )

        self.records[0]["dependencies"] = [
            "package-research-utils-v1"
        ]

        report = self.evidence[
            "package-research-utils-v1"
        ]["vulnerability_report"]

        report["findings"] = [{
            "finding_id": "CVE-2099-0003",
            "component_id": "package-research-utils-v1",
            "severity": "high",
            "applicability": "affected",
            "evidence": "Synthetic dependency vulnerability",
        }]

        result = self.evaluate()

        self.assertEqual(
            result.decision,
            "BLOCKED",
        )

    def test_016_review_dependency_prevents_eligibility(self):
        self.add_component(
            "package-research-utils-v1",
            b"SYNTHETIC-PACKAGE-V1",
            "package",
        )

        self.records[0]["dependencies"] = [
            "package-research-utils-v1"
        ]

        self.evidence[
            "package-research-utils-v1"
        ]["vulnerability_report"][
            "scan_status"
        ] = "incomplete"

        self.assertEqual(
            self.evaluate().decision,
            "REVIEW",
        )

    def test_017_block_precedes_review(self):
        self.add_component(
            "package-research-utils-v1",
            b"SYNTHETIC-PACKAGE-V1",
            "package",
        )

        self.records[0]["dependencies"] = [
            "package-research-utils-v1"
        ]

        self.evidence[
            "model-research-assistant-v1"
        ]["vulnerability_report"][
            "scan_status"
        ] = "incomplete"

        self.evidence[
            "package-research-utils-v1"
        ]["artifact_path"].write_bytes(
            b"TAMPERED-PACKAGE"
        )

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_018_forged_approval_flag_blocked(self):
        self.evidence[
            "model-research-assistant-v1"
        ]["approved"] = True

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_019_wrong_artifact_filename_blocked(self):
        original = self.evidence[
            "model-research-assistant-v1"
        ]["artifact_path"]

        alternate = (
            self.directory / "substituted.bin"
        )

        alternate.write_bytes(
            original.read_bytes()
        )

        self.evidence[
            "model-research-assistant-v1"
        ]["artifact_path"] = alternate

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_020_empty_inventory_blocked(self):
        result = self.gate.evaluate(
            [],
            {},
            {},
        )

        self.assertEqual(
            result.decision,
            "BLOCKED",
        )

    def test_021_result_contains_component_decision(self):
        result = self.evaluate()

        self.assertEqual(
            result.component_results[0].component_id,
            "model-research-assistant-v1",
        )
        self.assertEqual(
            result.component_results[0].decision,
            "ELIGIBLE",
        )

    def test_022_missing_vulnerability_report_blocked(self):
        self.evidence[
            "model-research-assistant-v1"
        ]["vulnerability_report"] = None

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_023_untrusted_digest_substitution_blocked(self):
        attacker_bytes = b"ATTACKER-MODEL-V2"

        path = self.evidence[
            "model-research-assistant-v1"
        ]["artifact_path"]

        path.write_bytes(attacker_bytes)

        attacker_digest = hashlib.sha256(
            attacker_bytes
        ).hexdigest()

        self.records[0][
            "artifact"
        ]["expected_digest"] = attacker_digest

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

    def test_024_malformed_inventory_blocked(self):
        self.records[0]["inventory_status"] = "verified"

        self.assertEqual(
            self.evaluate().decision,
            "BLOCKED",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)