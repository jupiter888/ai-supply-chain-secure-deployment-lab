"""
Project 8 — Fail-Closed Release Security Gate

Integrates inventory validation, artifact integrity,
synthetic provenance, and vulnerability assessment.

P8-H06: Structured Review Risk Propagation
P8-H06: Policy/Finding Namespace Collision Hardening

ELIGIBLE means technical checks passed at evaluation
time. It does not authorize deployment.

Review risks are machine-readable and component-bound.
Governance authorization is performed separately.

All identities, resources, and evidence are synthetic.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from src.inventory.validator import (
    ComponentInventoryValidator,
    InventoryValidationError,
)
from src.integrity.verifier import (
    ArtifactIntegrityVerifier,
    ArtifactIntegrityError,
)
from src.provenance.verifier import (
    ProvenanceVerifier,
    ProvenanceVerificationError,
    ProvenanceTrustPolicy,
)
from src.scanning.assessor import (
    VulnerabilityAssessor,
    VulnerabilityAssessmentError,
)


POLICY_RISK_IDS = frozenset({
    "SCAN_INCOMPLETE",
    "COVERAGE_INCOMPLETE",
})


@dataclass(frozen=True, order=True)
class ReviewRisk:
    component_id: str
    risk_id: str


@dataclass(frozen=True)
class ComponentGateResult:
    component_id: str
    decision: str
    reasons: tuple[str, ...]
    review_risks: tuple[ReviewRisk, ...] = ()


@dataclass(frozen=True)
class ReleaseGateResult:
    decision: str
    component_results: tuple[ComponentGateResult, ...]
    evaluated_components: int
    review_risks: tuple[ReviewRisk, ...] = ()


class ReleaseSecurityGate:
    """
    Fail-closed technical release assessment.

    Each component requires:
      - artifact_path
      - attestation
      - vulnerability_report

    Trusted digests must be supplied independently
    of component manifests.

    Review risk namespaces:
      POLICY:<condition>
      FINDING:<finding_id>

    Policy conditions and vulnerability findings are
    identified independently before namespacing.

    A REVIEW decision must expose at least one
    structured review risk.
    """

    REQUIRED_EVIDENCE_FIELDS = frozenset({
        "artifact_path",
        "attestation",
        "vulnerability_report",
    })

    def __init__(
        self,
        provenance_policy: ProvenanceTrustPolicy,
    ) -> None:
        self.inventory_validator = ComponentInventoryValidator()
        self.integrity_verifier = ArtifactIntegrityVerifier()
        self.provenance_verifier = ProvenanceVerifier(
            provenance_policy
        )
        self.vulnerability_assessor = VulnerabilityAssessor()

    @staticmethod
    def _blocked(
        component_id: str,
        reason: str,
    ) -> ComponentGateResult:
        return ComponentGateResult(
            component_id=component_id,
            decision="BLOCKED",
            reasons=(reason,),
        )

    @staticmethod
    def _policy_risks_from_report(
        report: Any,
    ) -> frozenset[str]:
        """
        Derive policy conditions independently of
        vulnerability finding identifiers.

        This prevents a finding identifier from
        masking a policy condition with the same name.

        The vulnerability assessor must validate
        the report before this method is called.
        """

        if not isinstance(report, dict):
            raise ValueError(
                "Invalid vulnerability report."
            )

        status = report.get("scan_status")
        coverage = report.get("coverage")

        if status not in {"completed", "incomplete"}:
            raise ValueError(
                "Invalid vulnerability scan status."
            )

        if (
            not isinstance(coverage, dict)
            or set(coverage) != {
                "dependencies",
                "artifact",
            }
        ):
            raise ValueError(
                "Invalid vulnerability coverage structure."
            )

        if any(
            type(value) is not bool
            for value in coverage.values()
        ):
            raise ValueError(
                "Invalid vulnerability coverage value."
            )

        policy_ids = set()

        if status == "incomplete":
            policy_ids.add("SCAN_INCOMPLETE")

        if not all(coverage.values()):
            policy_ids.add("COVERAGE_INCOMPLETE")

        return frozenset(policy_ids)

    @classmethod
    def _structured_review_risks(
        cls,
        component_id: str,
        assessment: Any,
        report: Any,
    ) -> tuple[ReviewRisk, ...]:
        """
        Convert assessor review evidence into
        namespaced, component-bound risks.

        Finding and policy identifiers are independent.

        Raw assessor identifiers must match the union
        of findings and report-derived policy conditions.

        A collision in unqualified identifiers must
        never suppress either structured risk.
        """

        raw_risks = assessment.review_risk_ids
        finding_ids = assessment.review_findings

        if (
            not isinstance(raw_risks, tuple)
            or not isinstance(finding_ids, tuple)
        ):
            raise ValueError(
                "Invalid structured review evidence."
            )

        if any(
            not isinstance(value, str)
            or not value.strip()
            for value in raw_risks + finding_ids
        ):
            raise ValueError(
                "Invalid review risk identifier."
            )

        if len(raw_risks) != len(set(raw_risks)):
            raise ValueError(
                "Duplicate review risk identifiers."
            )

        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError(
                "Duplicate review finding identifiers."
            )

        raw_set = set(raw_risks)
        finding_set = set(finding_ids)

        policy_set = set(
            cls._policy_risks_from_report(report)
        )

        if not policy_set.issubset(POLICY_RISK_IDS):
            raise ValueError(
                "Unknown synthetic policy risk."
            )

        expected_raw = finding_set | policy_set

        if raw_set != expected_raw:
            raise ValueError(
                "Assessor review evidence does not "
                "match findings and policy conditions."
            )

        risks = set()

        for finding_id in finding_set:
            risks.add(
                ReviewRisk(
                    component_id=component_id,
                    risk_id=f"FINDING:{finding_id}",
                )
            )

        for policy_id in policy_set:
            risks.add(
                ReviewRisk(
                    component_id=component_id,
                    risk_id=f"POLICY:{policy_id}",
                )
            )

        return tuple(sorted(risks))

    def _evaluate_component(
        self,
        component_id: str,
        manifest: dict,
        evidence: Any,
        trusted_digest: Any,
    ) -> ComponentGateResult:

        if (
            not isinstance(evidence, dict)
            or set(evidence) != self.REQUIRED_EVIDENCE_FIELDS
        ):
            return self._blocked(
                component_id,
                "Required component evidence is missing "
                "or malformed.",
            )

        if trusted_digest is None:
            return self._blocked(
                component_id,
                "Independent trusted digest is missing.",
            )

        artifact_path = evidence["artifact_path"]

        if not isinstance(artifact_path, (str, Path)):
            return self._blocked(
                component_id,
                "Artifact path is invalid.",
            )

        try:
            path = Path(artifact_path)

            if path.name != manifest["artifact"]["filename"]:
                return self._blocked(
                    component_id,
                    "Artifact filename does not match "
                    "the inventory manifest.",
                )

            self.integrity_verifier.verify(
                artifact_path=path,
                trusted_digest=trusted_digest,
                declared_digest=manifest[
                    "artifact"
                ]["expected_digest"],
                declared_size=manifest[
                    "artifact"
                ]["size_bytes"],
            )

        except (
            ArtifactIntegrityError,
            OSError,
            ValueError,
            TypeError,
        ) as exc:
            return self._blocked(
                component_id,
                f"Integrity verification failed: {exc}",
            )

        try:
            self.provenance_verifier.verify(
                attestation=evidence["attestation"],
                expected_subject_id=component_id,
                expected_digest=trusted_digest,
            )

        except (
            ProvenanceVerificationError,
            ValueError,
            TypeError,
        ) as exc:
            return self._blocked(
                component_id,
                f"Provenance verification failed: {exc}",
            )

        try:
            assessment = self.vulnerability_assessor.assess(
                report=evidence["vulnerability_report"],
                expected_component_id=component_id,
            )

        except (
            VulnerabilityAssessmentError,
            ValueError,
            TypeError,
        ) as exc:
            return self._blocked(
                component_id,
                f"Vulnerability assessment failed: {exc}",
            )

        if assessment.decision == "DENY":
            return self._blocked(
                component_id,
                "Vulnerability policy denied the component.",
            )

        if assessment.decision == "REVIEW":
            try:
                review_risks = self._structured_review_risks(
                    component_id,
                    assessment,
                    evidence["vulnerability_report"],
                )

            except (
                ValueError,
                TypeError,
                AttributeError,
            ):
                return self._blocked(
                    component_id,
                    "Structured review evidence is invalid.",
                )

            if not review_risks:
                return self._blocked(
                    component_id,
                    "Review decision has no identifiable "
                    "security risks.",
                )

            return ComponentGateResult(
                component_id=component_id,
                decision="REVIEW",
                reasons=assessment.reasons,
                review_risks=review_risks,
            )

        if assessment.decision != "ALLOW":
            return self._blocked(
                component_id,
                "Unknown vulnerability assessment decision.",
            )

        if (
            assessment.review_findings
            or assessment.review_risk_ids
        ):
            return self._blocked(
                component_id,
                "Eligible assessment contains unresolved "
                "review risks.",
            )

        # Defense in depth: an ALLOW assessment cannot
        # silently bypass report-derived policy risks.
        try:
            policy_risks = self._policy_risks_from_report(
                evidence["vulnerability_report"]
            )

        except (ValueError, TypeError):
            return self._blocked(
                component_id,
                "Vulnerability policy evidence is invalid.",
            )

        if policy_risks:
            return self._blocked(
                component_id,
                "Eligible assessment contains unresolved "
                "policy conditions.",
            )

        return ComponentGateResult(
            component_id=component_id,
            decision="ELIGIBLE",
            reasons=(
                "All required technical controls passed.",
            ),
        )

    def evaluate(
        self,
        records: list,
        evidence_by_component: Mapping[str, Any],
        trusted_digests: Mapping[str, str],
    ) -> ReleaseGateResult:
        """
        Evaluate all inventory components.

        Invalid inventories, missing evidence,
        and unexpected evidence scope block release.
        """

        if (
            not isinstance(evidence_by_component, dict)
            or not isinstance(trusted_digests, dict)
        ):
            return ReleaseGateResult(
                decision="BLOCKED",
                component_results=(),
                evaluated_components=0,
            )

        try:
            inventory = self.inventory_validator.validate(
                records
            )

        except (
            InventoryValidationError,
            ValueError,
            TypeError,
        ):
            return ReleaseGateResult(
                decision="BLOCKED",
                component_results=(),
                evaluated_components=0,
            )

        if not inventory:
            return ReleaseGateResult(
                decision="BLOCKED",
                component_results=(),
                evaluated_components=0,
            )

        component_ids = set(inventory)

        if (
            set(evidence_by_component) != component_ids
            or set(trusted_digests) != component_ids
        ):
            return ReleaseGateResult(
                decision="BLOCKED",
                component_results=(),
                evaluated_components=0,
            )

        results = []

        for component_id, manifest in inventory.items():
            result = self._evaluate_component(
                component_id=component_id,
                manifest=manifest,
                evidence=evidence_by_component[
                    component_id
                ],
                trusted_digest=trusted_digests[
                    component_id
                ],
            )
            results.append(result)

        decisions = {
            result.decision
            for result in results
        }

        if "BLOCKED" in decisions:
            final_decision = "BLOCKED"
        elif "REVIEW" in decisions:
            final_decision = "REVIEW"
        else:
            final_decision = "ELIGIBLE"

        all_review_risks = tuple(sorted(
            risk
            for result in results
            for risk in result.review_risks
        ))

        return ReleaseGateResult(
            decision=final_decision,
            component_results=tuple(results),
            evaluated_components=len(results),
            review_risks=all_review_risks,
        )

if __name__ == "__main__":
    raise SystemExit(
        "This module is not a standalone executable."
    )