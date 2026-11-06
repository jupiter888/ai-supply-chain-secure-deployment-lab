"""
Project 8 — AI Component Inventory Validator

Security objective:
    P8-SO01 — Component Identification

Trust boundary:
    TB-01 — External Component to Local Inventory

Controls:
    - JSON Schema Draft 2020-12 validation
    - Duplicate component ID rejection
    - Missing dependency rejection
    - Direct self-dependency rejection
    - Dependency cycle rejection
    - Registration-only security-state enforcement
    - Defensive copying of accepted records

Scope:
    Local, offline, synthetic AI supply-chain inventory.

Out of scope:
    Artifact integrity, authenticated provenance,
    vulnerability assessment, release authorization,
    and production deployment.
"""

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "policies"
    / "component-inventory.schema.json"
)


class InventoryValidationError(ValueError):
    """Raised when an inventory security invariant is violated."""


class ComponentInventoryValidator:
    """
    Validate a complete AI component inventory.

    Each record must satisfy the registration schema.

    Cross-record dependencies must reference existing
    components and form a directed acyclic graph.

    Validation never grants artifact trust or deployment
    authorization.
    """

    def __init__(
        self,
        schema_path: Optional[Path] = None,
    ) -> None:
        path = Path(schema_path or DEFAULT_SCHEMA_PATH)

        with path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)

        Draft202012Validator.check_schema(schema)

        self._schema_validator = Draft202012Validator(schema)

    def validate(
        self,
        records: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Validate and return a defensively copied inventory.

        Raises:
            InventoryValidationError:
                Any schema or graph invariant fails.
        """

        if not isinstance(records, list):
            raise InventoryValidationError(
                "Inventory must be a list of component records."
            )

        inventory: Dict[str, Dict[str, Any]] = {}

        for index, record in enumerate(records):

            if not isinstance(record, dict):
                raise InventoryValidationError(
                    f"Record {index} must be a JSON object."
                )

            errors = sorted(
                self._schema_validator.iter_errors(record),
                key=lambda error: (
                    tuple(str(part) for part in error.path),
                    error.message,
                ),
            )

            if errors:
                first_error = errors[0]

                location = ".".join(
                    str(part) for part in first_error.path
                ) or "<root>"

                raise InventoryValidationError(
                    f"Record {index} failed schema validation "
                    f"at {location}: {first_error.message}"
                )

            component_id = record["component_id"]

            if component_id in inventory:
                raise InventoryValidationError(
                    f"Duplicate component ID: {component_id}"
                )

            inventory[component_id] = copy.deepcopy(record)

        self._validate_dependencies(inventory)
        self._validate_acyclic(inventory)

        return inventory

    def _validate_dependencies(
        self,
        inventory: Dict[str, Dict[str, Any]],
    ) -> None:
        """Reject missing and direct self-dependencies."""

        known_ids = set(inventory)

        for component_id, record in inventory.items():

            for dependency_id in record["dependencies"]:

                if dependency_id == component_id:
                    raise InventoryValidationError(
                        "Self-dependency detected: "
                        f"{component_id}"
                    )

                if dependency_id not in known_ids:
                    raise InventoryValidationError(
                        f"Component {component_id} references "
                        f"missing dependency {dependency_id}"
                    )

    def _validate_acyclic(
        self,
        inventory: Dict[str, Dict[str, Any]],
    ) -> None:
        """
        Reject directed dependency cycles.

        Uses iterative depth-first traversal to avoid
        Python recursion-limit failures on deep graphs.
        """

        visited: Set[str] = set()
        active: Set[str] = set()

        for start_id in inventory:

            if start_id in visited:
                continue

            stack = [(start_id, False)]

            while stack:

                component_id, exiting = stack.pop()

                if exiting:
                    active.remove(component_id)
                    visited.add(component_id)
                    continue

                if component_id in active:
                    raise InventoryValidationError(
                        "Dependency cycle detected involving "
                        f"{component_id}"
                    )

                if component_id in visited:
                    continue

                active.add(component_id)

                stack.append((component_id, True))

                dependencies = inventory[
                    component_id
                ]["dependencies"]

                for dependency_id in reversed(dependencies):

                    if dependency_id in active:
                        raise InventoryValidationError(
                            "Dependency cycle detected: "
                            f"{component_id} -> {dependency_id}"
                        )

                    if dependency_id not in visited:
                        stack.append((dependency_id, False))