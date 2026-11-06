"""
Project 8 — AI Component Inventory Schema Validation

Scope:
    JSON Schema Draft 2020-12 structural validation
    and initial registration-state enforcement.

All test data is synthetic.

These tests do not establish artifact integrity,
authenticated provenance, deployment authorization,
or organizational compliance.
"""

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATH = (
    PROJECT_ROOT
    / "policies"
    / "component-inventory.schema.json"
)

MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "synthetic"
    / "model-manifest.json"
)


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class TestInventorySchema(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.schema = load_json(SCHEMA_PATH)
        cls.manifest = load_json(MANIFEST_PATH)

        Draft202012Validator.check_schema(cls.schema)

        cls.validator = Draft202012Validator(cls.schema)

    def assert_rejected(self, candidate):
        errors = list(self.validator.iter_errors(candidate))

        self.assertTrue(
            errors,
            "Expected invalid manifest to be rejected.",
        )

    def test_001_schema_is_valid_draft_2020_12(self):
        self.assertEqual(
            self.schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )

        Draft202012Validator.check_schema(self.schema)

    def test_002_valid_synthetic_model(self):
        self.validator.validate(self.manifest)

    def test_003_missing_required_field(self):
        candidate = copy.deepcopy(self.manifest)
        del candidate["component_id"]

        self.assert_rejected(candidate)

    def test_004_unsupported_component_type(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["component_type"] = "unknown"

        self.assert_rejected(candidate)

    def test_005_invalid_sha256_digest(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["artifact"]["expected_digest"] = "invalid"

        self.assert_rejected(candidate)

    def test_006_unknown_top_level_property(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["deployment_authorized"] = True

        self.assert_rejected(candidate)

    def test_007_forged_provenance_verification(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["provenance"]["verification_status"] = "verified"

        self.assert_rejected(candidate)

    def test_008_forged_license_approval(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["license"]["review_status"] = "approved"

        self.assert_rejected(candidate)

    def test_009_forged_risk_acceptance(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["governance"]["risk_acceptance_status"] = "accepted"

        self.assert_rejected(candidate)

    def test_010_forged_inventory_verification(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["inventory_status"] = "verified"

        self.assert_rejected(candidate)

    def test_011_duplicate_dependency(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["dependencies"] = [
            "package-research-utils-v1",
            "package-research-utils-v1",
        ]

        self.assert_rejected(candidate)

    def test_012_invalid_component_identifier(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["component_id"] = "../malicious"

        self.assert_rejected(candidate)

    def test_013_nested_unknown_property(self):
        candidate = copy.deepcopy(self.manifest)
        candidate["artifact"]["trusted"] = True

        self.assert_rejected(candidate)

    def test_014_valid_registration_remains_unverified(self):
        self.validator.validate(self.manifest)

        self.assertEqual(
            self.manifest["inventory_status"],
            "unverified",
        )

        self.assertEqual(
            self.manifest["provenance"]["verification_status"],
            "unverified",
        )

        self.assertEqual(
            self.manifest["license"]["review_status"],
            "unreviewed",
        )

        self.assertEqual(
            self.manifest["governance"]["risk_acceptance_status"],
            "not_assessed",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)