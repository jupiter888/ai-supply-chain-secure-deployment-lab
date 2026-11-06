"""
Project 8 — Inventory Graph Security Tests

Tests structural and cross-record registration controls.

All component records are synthetic.

Passing tests do not establish artifact integrity,
authenticated provenance, or deployment authorization.
"""

import copy
import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(PROJECT_ROOT))

from src.inventory.validator import (
    ComponentInventoryValidator,
    InventoryValidationError,
)


MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "synthetic"
    / "model-manifest.json"
)


def load_baseline():
    with MANIFEST_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def component(
    component_id,
    dependencies=None,
    component_type="package",
):
    """Create a synthetic component record."""

    record = copy.deepcopy(load_baseline())

    record["component_id"] = component_id
    record["component_type"] = component_type
    record["name"] = component_id
    record["dependencies"] = (
        list(dependencies)
        if dependencies is not None
        else []
    )

    return record


class TestComponentInventoryValidator(unittest.TestCase):

    def setUp(self):
        self.validator = ComponentInventoryValidator()

    def assert_rejected(self, records):
        with self.assertRaises(InventoryValidationError):
            self.validator.validate(records)

    def test_001_valid_single_component(self):
        record = component("model-alpha-v1", component_type="model")

        inventory = self.validator.validate([record])

        self.assertIn("model-alpha-v1", inventory)

    def test_002_valid_dependency_chain(self):
        records = [
            component(
                "model-alpha-v1",
                ["package-beta-v1"],
                "model",
            ),
            component(
                "package-beta-v1",
                ["dataset-gamma-v1"],
            ),
            component(
                "dataset-gamma-v1",
                component_type="dataset",
            ),
        ]

        inventory = self.validator.validate(records)

        self.assertEqual(len(inventory), 3)

    def test_003_duplicate_component_id(self):
        records = [
            component("package-alpha-v1"),
            component("package-alpha-v1"),
        ]

        self.assert_rejected(records)

    def test_004_missing_dependency(self):
        records = [
            component(
                "model-alpha-v1",
                ["package-missing-v1"],
                "model",
            ),
        ]

        self.assert_rejected(records)

    def test_005_direct_self_dependency(self):
        records = [
            component(
                "package-alpha-v1",
                ["package-alpha-v1"],
            ),
        ]

        self.assert_rejected(records)

    def test_006_two_component_cycle(self):
        records = [
            component(
                "package-alpha-v1",
                ["package-beta-v1"],
            ),
            component(
                "package-beta-v1",
                ["package-alpha-v1"],
            ),
        ]

        self.assert_rejected(records)

    def test_007_three_component_cycle(self):
        records = [
            component(
                "package-alpha-v1",
                ["package-beta-v1"],
            ),
            component(
                "package-beta-v1",
                ["package-gamma-v1"],
            ),
            component(
                "package-gamma-v1",
                ["package-alpha-v1"],
            ),
        ]

        self.assert_rejected(records)

    def test_008_invalid_schema_record(self):
        record = component("package-alpha-v1")
        record["component_type"] = "unsupported"

        self.assert_rejected([record])

    def test_009_forged_inventory_verification(self):
        record = component("package-alpha-v1")
        record["inventory_status"] = "verified"

        self.assert_rejected([record])

    def test_010_forged_provenance_verification(self):
        record = component("package-alpha-v1")
        record["provenance"]["verification_status"] = "verified"

        self.assert_rejected([record])

    def test_011_forged_risk_acceptance(self):
        record = component("package-alpha-v1")
        record["governance"]["risk_acceptance_status"] = "accepted"

        self.assert_rejected([record])

    def test_012_non_list_inventory(self):
        self.assert_rejected(
            {"component_id": "package-alpha-v1"}
        )

    def test_013_non_object_record(self):
        self.assert_rejected(
            ["malicious-record"]
        )

    def test_014_input_not_mutated(self):
        records = [
            component("package-alpha-v1"),
        ]

        original = copy.deepcopy(records)

        self.validator.validate(records)

        self.assertEqual(records, original)

    def test_015_output_is_defensive_copy(self):
        records = [
            component("package-alpha-v1"),
        ]

        inventory = self.validator.validate(records)

        inventory[
            "package-alpha-v1"
        ]["name"] = "modified"

        self.assertNotEqual(
            inventory["package-alpha-v1"]["name"],
            records[0]["name"],
        )

    def test_016_empty_inventory(self):
        inventory = self.validator.validate([])

        self.assertEqual(inventory, {})

    def test_017_multiple_independent_components(self):
        records = [
            component("model-alpha-v1", component_type="model"),
            component("package-beta-v1"),
            component("container-gamma-v1", component_type="container"),
            component("dataset-delta-v1", component_type="dataset"),
        ]

        inventory = self.validator.validate(records)

        self.assertEqual(len(inventory), 4)

    def test_018_shared_dependency(self):
        records = [
            component(
                "model-alpha-v1",
                ["package-common-v1"],
                "model",
            ),
            component(
                "container-beta-v1",
                ["package-common-v1"],
                "container",
            ),
            component("package-common-v1"),
        ]

        inventory = self.validator.validate(records)

        self.assertEqual(len(inventory), 3)

    def test_019_deep_acyclic_chain(self):
        count = 150

        records = []

        for index in range(count):
            component_id = f"package-chain-{index:03d}"

            dependencies = (
                [f"package-chain-{index + 1:03d}"]
                if index + 1 < count
                else []
            )

            records.append(
                component(component_id, dependencies)
            )

        inventory = self.validator.validate(records)

        self.assertEqual(len(inventory), count)

    def test_020_cycle_in_separate_component_group(self):
        records = [
            component("package-safe-v1"),
            component(
                "package-cycle-a",
                ["package-cycle-b"],
            ),
            component(
                "package-cycle-b",
                ["package-cycle-a"],
            ),
        ]

        self.assert_rejected(records)

if __name__ == "__main__":
    unittest.main(verbosity=2)