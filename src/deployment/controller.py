"""
Project 8 — Controlled Deployment & Rollback

Synthetic offline deployment security controller.

Security properties:
- Mandatory authenticated trusted-release registration
- Release ID, manifest digest, and artifact digest binding
- Fresh technical evaluation for deployment
- Governance authorization before activation
- Artifact integrity verification
- Component-isolated artifact snapshots
- Manifest filename preservation
- Explicit fresh rollback authorization
- Fresh technical verification before rollback
- Trusted-release revalidation before rollback
- Symlink rejection across snapshot paths
- Deterministic chained audit records

Limitations:
- Synthetic governance identities
- Synthetic HMAC-based release trust authority
- Trust authority key custody is externally assumed
- Trusted release records are held in memory
- Deployment registry and audit history are in memory
- No crash-atomic or concurrent transactions
- No production deployment
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from src.trust.registry import (
    TrustedReleaseRegistry,
    TrustRegistryError,
)

from src.policy.release_gate import ReleaseSecurityGate
from src.policy.governance import (
    GovernanceDecisionEngine,
    GovernanceValidationError,
)


class DeploymentSecurityError(ValueError):
    """Deployment or rollback security failure."""


@dataclass(frozen=True)
class DeploymentRecord:
    sequence: int
    operation: str
    release_id: str
    previous_release_id: str | None
    manifest_digest: str
    governance_digest: str
    record_digest: str


@dataclass(frozen=True)
class RegisteredRelease:
    release_id: str
    manifest_digest: str
    trusted_digests: tuple[tuple[str, str], ...]
    snapshot_paths: tuple[tuple[str, str], ...]
    governance_digest: str
    records_json: str
    attestations_json: str
    vulnerability_reports_json: str


class ControlledDeploymentController:

    def __init__(
        self,
        release_gate: ReleaseSecurityGate,
        governance_engine: GovernanceDecisionEngine,
        storage_directory: str | Path,
        trust_registry: TrustedReleaseRegistry,
    ) -> None:

        if not isinstance(
            release_gate, ReleaseSecurityGate
        ):
            raise DeploymentSecurityError(
                "Release security gate required."
            )

        if not isinstance(
            governance_engine, GovernanceDecisionEngine
        ):
            raise DeploymentSecurityError(
                "Governance decision engine required."
            )

        if not isinstance(
            trust_registry, TrustedReleaseRegistry
        ):
            raise DeploymentSecurityError(
                "Trusted release registry required."
            )

        self.release_gate = release_gate
        self.governance_engine = governance_engine
        self.trust_registry = trust_registry

        raw_storage = Path(storage_directory)

        if raw_storage.is_symlink():
            raise DeploymentSecurityError(
                "Storage root cannot be a symlink."
            )

        self.storage_directory = raw_storage.resolve()

        self.storage_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._releases: dict[str, RegisteredRelease] = {}
        self._active_release_id: str | None = None
        self._audit: list[DeploymentRecord] = []

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as stream:
            for chunk in iter(
                lambda: stream.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def _canonical_json(value: Any) -> str:
        try:
            return json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise DeploymentSecurityError(
                "Invalid canonical JSON evidence."
            ) from exc

    @classmethod
    def _canonical_digest(cls, value: Any) -> str:
        return hashlib.sha256(
            cls._canonical_json(value).encode("utf-8")
        ).hexdigest()

    @classmethod
    def manifest_digest(cls, records: list) -> str:

        if not isinstance(records, list):
            raise DeploymentSecurityError(
                "Inventory must be a list."
            )

        if not all(
            isinstance(item, dict)
            and isinstance(item.get("component_id"), str)
            for item in records
        ):
            raise DeploymentSecurityError(
                "Invalid inventory records."
            )

        ordered = sorted(
            records,
            key=lambda item: item["component_id"],
        )

        return cls._canonical_digest(ordered)

    def _require_trusted_release(
        self,
        release_id: str,
        manifest_digest: str,
        component_digests: dict,
    ) -> None:
        """
        Require an authenticated, previously registered
        release identity.

        Caller-provided digests must match the digests
        independently registered by the trust authority.
        """

        try:
            self.trust_registry.require(
                release_id=release_id,
                manifest_digest=manifest_digest,
                component_digests=component_digests,
            )
        except TrustRegistryError as exc:
            raise DeploymentSecurityError(
                f"Release trust verification failed: {exc}"
            ) from exc

    def _snapshot_directory(
        self,
        release_id: str,
    ) -> Path:

        directory = (
            self.storage_directory / release_id
        )

        if directory.is_symlink():
            raise DeploymentSecurityError(
                "Symlinked release directory rejected."
            )

        if not directory.is_dir():
            raise DeploymentSecurityError(
                "Registered release directory missing."
            )

        if directory.resolve().parent != (
            self.storage_directory
        ):
            raise DeploymentSecurityError(
                "Release directory escaped storage boundary."
            )

        return directory

    @staticmethod
    def _safe_component_path(
        release_directory: Path,
        component_id: str,
        filename: str,
    ) -> Path:

        if (
            not isinstance(component_id, str)
            or not component_id
            or Path(component_id).name != component_id
            or component_id in (".", "..")
        ):
            raise DeploymentSecurityError(
                "Unsafe component identifier."
            )

        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or filename in (".", "..")
        ):
            raise DeploymentSecurityError(
                "Unsafe artifact filename."
            )

        component_directory = (
            release_directory / component_id
        )

        if (
            component_directory.is_symlink()
            or not component_directory.is_dir()
        ):
            raise DeploymentSecurityError(
                "Missing or unsafe component directory."
            )

        if (
            component_directory.resolve().parent
            != release_directory
        ):
            raise DeploymentSecurityError(
                "Component directory escaped release boundary."
            )

        artifact_path = (
            component_directory / filename
        )

        if (
            artifact_path.is_symlink()
            or not artifact_path.is_file()
        ):
            raise DeploymentSecurityError(
                "Missing or unsafe snapshot artifact."
            )

        if (
            artifact_path.resolve().parent
            != component_directory
        ):
            raise DeploymentSecurityError(
                "Artifact escaped component boundary."
            )

        return artifact_path

    def _verify_snapshot(
        self,
        release: RegisteredRelease,
    ) -> None:

        directory = self._snapshot_directory(
            release.release_id
        )

        expected = dict(release.trusted_digests)
        paths = dict(release.snapshot_paths)

        if set(expected) != set(paths):
            raise DeploymentSecurityError(
                "Snapshot component mismatch."
            )

        for component_id, filename in paths.items():

            path = self._safe_component_path(
                directory,
                component_id,
                filename,
            )

            if (
                self._sha256(path)
                != expected[component_id]
            ):
                raise DeploymentSecurityError(
                    f"Snapshot digest mismatch: {component_id}"
                )

    def _append_audit(
        self,
        operation: str,
        release: RegisteredRelease,
        previous_release_id: str | None,
        governance_digest: str,
    ) -> DeploymentRecord:

        sequence = len(self._audit) + 1

        payload = {
            "sequence": sequence,
            "operation": operation,
            "release_id": release.release_id,
            "previous_release_id": previous_release_id,
            "manifest_digest": release.manifest_digest,
            "governance_digest": governance_digest,
            "previous_record_digest": (
                self._audit[-1].record_digest
                if self._audit
                else None
            ),
        }

        record = DeploymentRecord(
            sequence=sequence,
            operation=operation,
            release_id=release.release_id,
            previous_release_id=previous_release_id,
            manifest_digest=release.manifest_digest,
            governance_digest=governance_digest,
            record_digest=self._canonical_digest(payload),
        )

        self._audit.append(record)
        return record

    def _authorize(
        self,
        request: dict,
        technical_result,
        release_id: str,
        manifest_digest: str,
        now: datetime,
    ):

        try:
            result = self.governance_engine.evaluate(
                request=request,
                technical_result=technical_result,
                expected_release_id=release_id,
                expected_manifest_digest=manifest_digest,
                now=now,
            )
        except GovernanceValidationError as exc:
            raise DeploymentSecurityError(
                f"Governance authorization failed: {exc}"
            ) from exc

        if result.decision != "APPROVED":
            raise DeploymentSecurityError(
                "Governance did not authorize operation."
            )

        return result

    def deploy(
        self,
        records: list,
        evidence_by_component: dict,
        trusted_digests: dict,
        governance_request: dict,
        now: datetime,
    ) -> DeploymentRecord:

        if not isinstance(governance_request, dict):
            raise DeploymentSecurityError(
                "Governance request required."
            )

        release_id = governance_request.get(
            "release_id"
        )

        if (
            not isinstance(release_id, str)
            or not self.governance_engine.RELEASE_PATTERN.fullmatch(
                release_id
            )
        ):
            raise DeploymentSecurityError(
                "Invalid release ID."
            )

        if release_id in self._releases:
            raise DeploymentSecurityError(
                "Release already registered."
            )

        digest = self.manifest_digest(records)

        # P8-H03: Mandatory independently registered trust.
        # This check must precede technical and governance
        # evaluation so caller-substituted digests cannot
        # become the effective trust anchor.

        self._require_trusted_release(
            release_id,
            digest,
            trusted_digests,
        )

        technical = self.release_gate.evaluate(
            records,
            evidence_by_component,
            trusted_digests,
        )

        if technical.decision == "BLOCKED":
            raise DeploymentSecurityError(
                "Technical gate blocked deployment."
            )

        if technical.decision not in (
            "ELIGIBLE",
            "REVIEW",
        ):
            raise DeploymentSecurityError(
                "Unknown technical decision."
            )

        governance = self._authorize(
            governance_request,
            technical,
            release_id,
            digest,
            now,
        )

        staging = Path(
            tempfile.mkdtemp(
                prefix=".stage-",
                dir=self.storage_directory,
            )
        )

        snapshot_names = {}

        try:
            records_by_id = {
                record["component_id"]: record
                for record in records
            }

            for component_id in sorted(trusted_digests):

                manifest = records_by_id[component_id]

                filename = manifest["artifact"]["filename"]

                if (
                    not isinstance(filename, str)
                    or not filename
                    or Path(filename).name != filename
                    or filename in (".", "..")
                ):
                    raise DeploymentSecurityError(
                        "Unsafe manifest artifact filename."
                    )

                source = Path(
                    evidence_by_component[
                        component_id
                    ]["artifact_path"]
                )

                if source.is_symlink() or not source.is_file():
                    raise DeploymentSecurityError(
                        "Unsafe source artifact."
                    )

                component_directory = (
                    staging / component_id
                )

                component_directory.mkdir()

                destination = (
                    component_directory / filename
                )

                with source.open("rb") as source_stream:
                    with destination.open("xb") as target_stream:
                        shutil.copyfileobj(
                            source_stream,
                            target_stream,
                            length=1024 * 1024,
                        )

                if (
                    self._sha256(destination)
                    != trusted_digests[component_id]
                ):
                    raise DeploymentSecurityError(
                        f"Staging digest mismatch: {component_id}"
                    )

                snapshot_names[component_id] = filename

            final_directory = (
                self.storage_directory / release_id
            )

            if (
                final_directory.exists()
                or final_directory.is_symlink()
            ):
                raise DeploymentSecurityError(
                    "Release snapshot already exists."
                )

            os.rename(staging, final_directory)

            release = RegisteredRelease(
                release_id=release_id,
                manifest_digest=digest,
                trusted_digests=tuple(
                    sorted(trusted_digests.items())
                ),
                snapshot_paths=tuple(
                    sorted(snapshot_names.items())
                ),
                governance_digest=governance.record_digest,
                records_json=self._canonical_json(records),
                attestations_json=self._canonical_json({
                    key: value["attestation"]
                    for key, value
                    in evidence_by_component.items()
                }),
                vulnerability_reports_json=(
                    self._canonical_json({
                        key: value["vulnerability_report"]
                        for key, value
                        in evidence_by_component.items()
                    })
                ),
            )

            self._verify_snapshot(release)

            previous = self._active_release_id

            self._releases[release_id] = release
            self._active_release_id = release_id

            return self._append_audit(
                "DEPLOY",
                release,
                previous,
                governance.record_digest,
            )

        finally:
            if staging.exists():
                shutil.rmtree(staging)

    def rollback(
        self,
        target_release_id: str,
        governance_request: dict | None = None,
        now: datetime | None = None,
    ) -> DeploymentRecord:

        if target_release_id not in self._releases:
            raise DeploymentSecurityError(
                "Rollback target was never registered."
            )

        if target_release_id == self._active_release_id:
            raise DeploymentSecurityError(
                "Target release is already active."
            )

        if (
            not isinstance(governance_request, dict)
            or not isinstance(now, datetime)
            or now.tzinfo is None
        ):
            raise DeploymentSecurityError(
                "Fresh rollback authorization required."
            )

        if governance_request.get("operation") != "rollback":
            raise DeploymentSecurityError(
                "Explicit rollback operation required."
            )

        request = dict(governance_request)
        del request["operation"]

        release = self._releases[target_release_id]

        if request.get("release_id") != target_release_id:
            raise DeploymentSecurityError(
                "Rollback target identity mismatch."
            )

        # P8-H03: Revalidate the rollback target against
        # the independently registered trust authority.

        self._require_trusted_release(
            target_release_id,
            release.manifest_digest,
            dict(release.trusted_digests),
        )

        self._verify_snapshot(release)

        records = json.loads(release.records_json)
        attestations = json.loads(
            release.attestations_json
        )
        reports = json.loads(
            release.vulnerability_reports_json
        )

        directory = self._snapshot_directory(
            target_release_id
        )

        evidence = {}

        for component_id, filename in release.snapshot_paths:

            path = self._safe_component_path(
                directory,
                component_id,
                filename,
            )

            evidence[component_id] = {
                "artifact_path": path,
                "attestation": attestations[component_id],
                "vulnerability_report": reports[component_id],
            }

        technical = self.release_gate.evaluate(
            records,
            evidence,
            dict(release.trusted_digests),
        )

        if technical.decision == "BLOCKED":
            raise DeploymentSecurityError(
                "Rollback blocked by technical gate."
            )

        if technical.decision not in (
            "ELIGIBLE",
            "REVIEW",
        ):
            raise DeploymentSecurityError(
                "Unknown rollback technical decision."
            )

        governance = self._authorize(
            request,
            technical,
            target_release_id,
            release.manifest_digest,
            now,
        )

        # Final snapshot verification immediately
        # before activation.

        self._verify_snapshot(release)

        previous = self._active_release_id
        self._active_release_id = target_release_id

        return self._append_audit(
            "ROLLBACK",
            release,
            previous,
            governance.record_digest,
        )

    @property
    def active_release_id(self) -> str | None:
        return self._active_release_id

    @property
    def audit_history(self) -> tuple[DeploymentRecord, ...]:
        return tuple(self._audit)