"""
Project 8 — Synthetic Vulnerability Assessment

P8-SO04: Vulnerability Assessment
TB-04: Vulnerability Findings to Policy Decision

Evaluates strictly structured synthetic scan reports.

ALLOW means no blocking findings under this policy.
It is not deployment authorization.

Structured review risk identifiers support downstream
machine-verifiable governance risk acceptance.

Scanner authenticity, actual scanning, risk acceptance,
and release authorization are outside this module.
"""

import re
from dataclasses import dataclass
from typing import Any


SEVERITIES = frozenset({
    "none",
    "low",
    "medium",
    "high",
    "critical",
})

APPLICABILITY = frozenset({
    "affected",
    "not_affected",
    "unknown",
})

REPORT_FIELDS = frozenset({
    "schema_version",
    "component_id",
    "scan_status",
    "coverage",
    "findings",
})

FINDING_FIELDS = frozenset({
    "finding_id",
    "component_id",
    "severity",
    "applicability",
    "evidence",
})

COVERAGE_FIELDS = frozenset({
    "dependencies",
    "artifact",
})

COMPONENT_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]{2,63}$"
)

SCAN_INCOMPLETE = "SCAN_INCOMPLETE"
COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"


class VulnerabilityAssessmentError(ValueError):
    """Malformed or inconsistent assessment evidence."""


@dataclass(frozen=True)
class AssessmentResult:
    component_id: str
    decision: str
    reasons: tuple[str, ...]
    blocking_findings: tuple[str, ...]
    review_findings: tuple[str, ...]
    finding_count: int
    review_risk_ids: tuple[str, ...] = ()


class VulnerabilityAssessor:
    """
    Evaluate a report under a fixed local security policy.

    Policy:
      - Affected high/critical: DENY
      - Unknown applicability: REVIEW
      - Incomplete scan or coverage: REVIEW
      - Affected low/medium: REVIEW
      - No unresolved findings: ALLOW

    DENY takes precedence over REVIEW.

    Review risk identifiers:
      - SCAN_INCOMPLETE
      - COVERAGE_INCOMPLETE
      - Original vulnerability finding IDs

    Synthetic policy identifiers are not CVE IDs.
    """

    @staticmethod
    def _nonempty(value: Any) -> bool:
        return (
            isinstance(value, str)
            and bool(value.strip())
            and len(value) <= 2048
        )

    def assess(
        self,
        report: dict,
        expected_component_id: str,
    ) -> AssessmentResult:

        if not isinstance(report, dict):
            raise VulnerabilityAssessmentError(
                "Report must be a JSON object."
            )

        if set(report) != REPORT_FIELDS:
            raise VulnerabilityAssessmentError(
                "Report fields are missing or unexpected."
            )

        if report["schema_version"] != "1.0.0":
            raise VulnerabilityAssessmentError(
                "Unsupported report schema version."
            )

        if (
            not self._nonempty(expected_component_id)
            or COMPONENT_PATTERN.fullmatch(
                expected_component_id
            ) is None
        ):
            raise VulnerabilityAssessmentError(
                "Invalid expected component ID."
            )

        if report["component_id"] != expected_component_id:
            raise VulnerabilityAssessmentError(
                "Report component identity mismatch."
            )

        if report["scan_status"] not in {
            "completed",
            "incomplete",
            "failed",
        }:
            raise VulnerabilityAssessmentError(
                "Invalid scan status."
            )

        coverage = report["coverage"]

        if (
            not isinstance(coverage, dict)
            or set(coverage) != COVERAGE_FIELDS
            or any(
                not isinstance(value, bool)
                for value in coverage.values()
            )
        ):
            raise VulnerabilityAssessmentError(
                "Invalid scan coverage declaration."
            )

        findings = report["findings"]

        if not isinstance(findings, list):
            raise VulnerabilityAssessmentError(
                "Findings must be an array."
            )

        seen = set()
        blocking = []
        review = []
        reasons = []
        review_risks = []

        for index, finding in enumerate(findings):

            if (
                not isinstance(finding, dict)
                or set(finding) != FINDING_FIELDS
            ):
                raise VulnerabilityAssessmentError(
                    f"Invalid finding structure at {index}."
                )

            finding_id = finding["finding_id"]

            if not self._nonempty(finding_id):
                raise VulnerabilityAssessmentError(
                    "Invalid finding identifier."
                )

            if finding_id in seen:
                raise VulnerabilityAssessmentError(
                    f"Duplicate finding: {finding_id}"
                )

            seen.add(finding_id)

            if finding["component_id"] != expected_component_id:
                raise VulnerabilityAssessmentError(
                    "Finding component identity mismatch."
                )

            severity = finding["severity"]
            applicability = finding["applicability"]

            if (
                not isinstance(severity, str)
                or severity not in SEVERITIES
            ):
                raise VulnerabilityAssessmentError(
                    "Invalid finding severity."
                )

            if (
                not isinstance(applicability, str)
                or applicability not in APPLICABILITY
            ):
                raise VulnerabilityAssessmentError(
                    "Invalid finding applicability."
                )

            if not self._nonempty(finding["evidence"]):
                raise VulnerabilityAssessmentError(
                    "Missing finding evidence."
                )

            if applicability == "not_affected":
                continue

            if applicability == "unknown":
                review.append(finding_id)
                review_risks.append(finding_id)
                continue

            if severity in {"critical", "high"}:
                blocking.append(finding_id)

            elif severity in {"medium", "low"}:
                review.append(finding_id)
                review_risks.append(finding_id)

        if report["scan_status"] != "completed":
            reasons.append(
                "Assessment did not complete successfully."
            )
            review_risks.append(SCAN_INCOMPLETE)

        if not all(coverage.values()):
            reasons.append(
                "Required assessment coverage is incomplete."
            )
            review_risks.append(COVERAGE_INCOMPLETE)

        if blocking:
            reasons.append(
                "Applicable high or critical vulnerabilities."
            )

        if review:
            reasons.append(
                "Findings require additional risk assessment."
            )

        if blocking:
            decision = "DENY"

        elif reasons:
            decision = "REVIEW"

        else:
            decision = "ALLOW"
            reasons.append(
                "No blocking or unresolved findings "
                "under the configured policy."
            )

        return AssessmentResult(
            component_id=expected_component_id,
            decision=decision,
            reasons=tuple(reasons),
            blocking_findings=tuple(blocking),
            review_findings=tuple(review),
            finding_count=len(findings),
            review_risk_ids=tuple(
                sorted(set(review_risks))
            ),
        )