"""
Project 8 — Governance Authorization & Risk Acceptance

P8-H06: Machine-Verifiable Risk Acceptance
P8-H06: Technical Result Consistency Hardening

Synthetic, offline governance decision engine.

Security properties:
- Independent authorized authority registry
- Separation of duties
- Release and manifest digest binding
- Fail-closed technical gate integration
- Component-bound and finding-bound risk acceptance
- Exact risk coverage verification
- Expiring governance decisions and risk acceptance
- Consistent component and release technical results
- Canonical inactive risk-acceptance records
- Deterministic decision record hashing

Limitations:
- Authority registry is trusted input, not authentication
- No cryptographic approval signatures
- No persistent audit ledger
- No deployment authorization issued by this module
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re

from src.policy.release_gate import (
    ComponentGateResult,
    ReleaseGateResult,
    ReviewRisk,
)


class GovernanceValidationError(ValueError):
    """Invalid or unauthorized governance decision."""


@dataclass(frozen=True)
class GovernanceResult:
    release_id: str
    manifest_digest: str
    decision: str
    approver_id: str
    risk_owner_id: str | None
    expires_at: str
    reason: str
    record_digest: str


class GovernanceDecisionEngine:

    DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

    RELEASE_PATTERN = re.compile(
        r"^[a-z][a-z0-9-]{2,63}$"
    )

    COMPONENT_PATTERN = re.compile(
        r"^[a-z][a-z0-9-]{2,63}$"
    )

    REQUIRED_FIELDS = frozenset({
        "schema_version",
        "release_id",
        "manifest_digest",
        "requester_id",
        "approver_id",
        "decision",
        "justification",
        "expires_at",
        "risk_acceptance",
    })

    RISK_FIELDS = frozenset({
        "accepted",
        "risk_owner_id",
        "release_id",
        "manifest_digest",
        "accepted_risks",
        "justification",
        "expires_at",
    })

    ACCEPTED_RISK_FIELDS = frozenset({
        "component_id",
        "risk_id",
    })

    def __init__(
        self,
        authorized_approvers: frozenset[str],
        authorized_risk_owners: frozenset[str],
    ) -> None:

        if (
            not isinstance(authorized_approvers, frozenset)
            or not authorized_approvers
            or not all(
                isinstance(value, str) and value.strip()
                for value in authorized_approvers
            )
        ):
            raise GovernanceValidationError(
                "Invalid authorized approver registry."
            )

        if (
            not isinstance(authorized_risk_owners, frozenset)
            or not authorized_risk_owners
            or not all(
                isinstance(value, str) and value.strip()
                for value in authorized_risk_owners
            )
        ):
            raise GovernanceValidationError(
                "Invalid authorized risk owner registry."
            )

        self.authorized_approvers = authorized_approvers
        self.authorized_risk_owners = authorized_risk_owners

    @staticmethod
    def _parse_time(value: str) -> datetime:
        if not isinstance(value, str):
            raise GovernanceValidationError(
                "Timestamp must be a string."
            )

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise GovernanceValidationError(
                "Invalid ISO 8601 timestamp."
            ) from exc

        if parsed.tzinfo is None:
            raise GovernanceValidationError(
                "Timezone-aware timestamp required."
            )

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _require_text(value, label: str) -> str:
        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise GovernanceValidationError(
                f"{label} must be nonempty text."
            )

        return value

    @staticmethod
    def _record_digest(record: dict) -> str:
        canonical = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def _validate_risk_identifier(
        cls,
        value: str,
    ) -> None:
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 2048
            or not (
                value.startswith("FINDING:")
                or value.startswith("POLICY:")
            )
        ):
            raise GovernanceValidationError(
                "Invalid namespaced risk identifier."
            )

        if value.startswith("POLICY:"):
            if value not in {
                "POLICY:SCAN_INCOMPLETE",
                "POLICY:COVERAGE_INCOMPLETE",
            }:
                raise GovernanceValidationError(
                    "Unknown policy risk identifier."
                )

        if value == "FINDING:":
            raise GovernanceValidationError(
                "Empty vulnerability finding identifier."
            )

    @classmethod
    def _parse_accepted_risks(
        cls,
        value,
    ) -> frozenset[ReviewRisk]:

        if not isinstance(value, list):
            raise GovernanceValidationError(
                "Accepted risks must be an array."
            )

        parsed = set()

        for entry in value:
            if (
                not isinstance(entry, dict)
                or set(entry) != cls.ACCEPTED_RISK_FIELDS
            ):
                raise GovernanceValidationError(
                    "Invalid accepted risk structure."
                )

            component_id = entry["component_id"]
            risk_id = entry["risk_id"]

            if (
                not isinstance(component_id, str)
                or not cls.COMPONENT_PATTERN.fullmatch(
                    component_id
                )
            ):
                raise GovernanceValidationError(
                    "Invalid accepted risk component."
                )

            cls._validate_risk_identifier(risk_id)

            risk = ReviewRisk(
                component_id=component_id,
                risk_id=risk_id,
            )

            if risk in parsed:
                raise GovernanceValidationError(
                    "Duplicate accepted risk."
                )

            parsed.add(risk)

        return frozenset(parsed)

    @classmethod
    def _validate_technical_result(
        cls,
        technical_result: ReleaseGateResult,
    ) -> frozenset[ReviewRisk]:
        """
        Verify consistency between release-level and
        component-level technical gate decisions.

        Reject contradictory, duplicate, or malformed
        technical results before governance evaluation.
        """

        if not isinstance(
            technical_result,
            ReleaseGateResult,
        ):
            raise GovernanceValidationError(
                "Invalid technical gate result."
            )

        if technical_result.decision not in {
            "ELIGIBLE",
            "REVIEW",
            "BLOCKED",
        }:
            raise GovernanceValidationError(
                "Unknown technical gate decision."
            )

        if not isinstance(
            technical_result.component_results,
            tuple,
        ):
            raise GovernanceValidationError(
                "Invalid technical component structure."
            )

        if (
            type(technical_result.evaluated_components)
            is not int
            or technical_result.evaluated_components < 0
            or technical_result.evaluated_components
            != len(technical_result.component_results)
        ):
            raise GovernanceValidationError(
                "Technical component count mismatch."
            )

        if not isinstance(
            technical_result.review_risks,
            tuple,
        ):
            raise GovernanceValidationError(
                "Invalid technical review risk structure."
            )

        components = set()
        component_decisions = set()
        collected_risks = set()

        for component in technical_result.component_results:
            if not isinstance(
                component,
                ComponentGateResult,
            ):
                raise GovernanceValidationError(
                    "Invalid technical component result."
                )

            component_id = component.component_id

            if (
                not isinstance(component_id, str)
                or not cls.COMPONENT_PATTERN.fullmatch(
                    component_id
                )
            ):
                raise GovernanceValidationError(
                    "Invalid technical component identity."
                )

            if component_id in components:
                raise GovernanceValidationError(
                    "Duplicate technical component."
                )

            components.add(component_id)

            if component.decision not in {
                "ELIGIBLE",
                "REVIEW",
                "BLOCKED",
            }:
                raise GovernanceValidationError(
                    "Unknown component gate decision."
                )

            component_decisions.add(
                component.decision
            )

            if not isinstance(
                component.reasons,
                tuple,
            ):
                raise GovernanceValidationError(
                    "Invalid component reason structure."
                )

            if not isinstance(
                component.review_risks,
                tuple,
            ):
                raise GovernanceValidationError(
                    "Invalid component review risk structure."
                )

            local_risks = set()

            for risk in component.review_risks:
                if not isinstance(risk, ReviewRisk):
                    raise GovernanceValidationError(
                        "Invalid component review risk."
                    )

                if risk.component_id != component_id:
                    raise GovernanceValidationError(
                        "Review risk component mismatch."
                    )

                cls._validate_risk_identifier(
                    risk.risk_id
                )

                if risk in local_risks:
                    raise GovernanceValidationError(
                        "Duplicate component review risk."
                    )

                local_risks.add(risk)

            if (
                component.decision == "REVIEW"
                and not local_risks
            ):
                raise GovernanceValidationError(
                    "Review component lacks risks."
                )

            if (
                component.decision != "REVIEW"
                and local_risks
            ):
                raise GovernanceValidationError(
                    "Non-review component contains risks."
                )

            collected_risks.update(local_risks)

        actual_risks = set()

        for risk in technical_result.review_risks:
            if not isinstance(risk, ReviewRisk):
                raise GovernanceValidationError(
                    "Invalid technical review risk."
                )

            if (
                not isinstance(risk.component_id, str)
                or not cls.COMPONENT_PATTERN.fullmatch(
                    risk.component_id
                )
            ):
                raise GovernanceValidationError(
                    "Invalid technical risk component."
                )

            cls._validate_risk_identifier(
                risk.risk_id
            )

            if risk in actual_risks:
                raise GovernanceValidationError(
                    "Duplicate technical review risk."
                )

            actual_risks.add(risk)

        if actual_risks != collected_risks:
            raise GovernanceValidationError(
                "Release review risks do not match "
                "component review risks."
            )

        if "BLOCKED" in component_decisions:
            expected_decision = "BLOCKED"
        elif "REVIEW" in component_decisions:
            expected_decision = "REVIEW"
        elif component_decisions:
            expected_decision = "ELIGIBLE"
        else:
            expected_decision = "BLOCKED"

        if technical_result.decision != expected_decision:
            raise GovernanceValidationError(
                "Release decision contradicts "
                "component gate decisions."
            )

        if (
            technical_result.decision == "REVIEW"
            and not actual_risks
        ):
            raise GovernanceValidationError(
                "Review decision lacks structured risks."
            )

        if (
            technical_result.decision == "ELIGIBLE"
            and actual_risks
        ):
            raise GovernanceValidationError(
                "Eligible release contains review risks."
            )

        return frozenset(actual_risks)

    @classmethod
    def _validate_inactive_risk_acceptance(
        cls,
        risk: dict,
    ) -> None:
        """
        An inactive acceptance must not contain
        dormant authority, scope, or expiry values.
        """

        if risk != {
            "accepted": False,
            "risk_owner_id": None,
            "release_id": None,
            "manifest_digest": None,
            "accepted_risks": [],
            "justification": None,
            "expires_at": None,
        }:
            raise GovernanceValidationError(
                "Inactive risk acceptance must have "
                "empty authority and scope fields."
            )

    def evaluate(
        self,
        request: dict,
        technical_result: ReleaseGateResult,
        expected_release_id: str,
        expected_manifest_digest: str,
        now: datetime,
    ) -> GovernanceResult:

        if (
            not isinstance(request, dict)
            or set(request) != self.REQUIRED_FIELDS
        ):
            raise GovernanceValidationError(
                "Governance request structure is invalid."
            )

        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
        ):
            raise GovernanceValidationError(
                "Invalid evaluation time."
            )

        now_utc = now.astimezone(timezone.utc)

        if request["schema_version"] != "1.0.0":
            raise GovernanceValidationError(
                "Unsupported governance schema version."
            )

        release_id = request["release_id"]
        manifest_digest = request["manifest_digest"]

        if (
            not isinstance(release_id, str)
            or not self.RELEASE_PATTERN.fullmatch(
                release_id
            )
            or release_id != expected_release_id
        ):
            raise GovernanceValidationError(
                "Release identity mismatch."
            )

        if (
            not isinstance(manifest_digest, str)
            or not self.DIGEST_PATTERN.fullmatch(
                manifest_digest
            )
            or manifest_digest != expected_manifest_digest
        ):
            raise GovernanceValidationError(
                "Manifest digest mismatch."
            )

        requester = self._require_text(
            request["requester_id"],
            "Requester",
        )

        approver = self._require_text(
            request["approver_id"],
            "Approver",
        )

        if approver not in self.authorized_approvers:
            raise GovernanceValidationError(
                "Approver is not authorized."
            )

        if requester == approver:
            raise GovernanceValidationError(
                "Requester cannot approve own release."
            )

        decision = request["decision"]

        if decision not in {"approve", "reject"}:
            raise GovernanceValidationError(
                "Invalid governance decision."
            )

        self._require_text(
            request["justification"],
            "Justification",
        )

        expiry = self._parse_time(
            request["expires_at"]
        )

        if expiry <= now_utc:
            raise GovernanceValidationError(
                "Governance decision has expired."
            )

        risk = request["risk_acceptance"]

        if (
            not isinstance(risk, dict)
            or set(risk) != self.RISK_FIELDS
        ):
            raise GovernanceValidationError(
                "Invalid risk acceptance structure."
            )

        if not isinstance(risk["accepted"], bool):
            raise GovernanceValidationError(
                "Risk acceptance must be boolean."
            )

        technical_risks = self._validate_technical_result(
            technical_result
        )

        if not risk["accepted"]:
            self._validate_inactive_risk_acceptance(
                risk
            )

        risk_owner_id = risk["risk_owner_id"]

        if technical_result.decision == "BLOCKED":
            final_decision = "REJECTED"
            reason = (
                "Technical security controls blocked release."
            )

        elif decision == "reject":
            final_decision = "REJECTED"
            reason = "Authorized governance rejection."

        elif technical_result.decision == "ELIGIBLE":
            if risk["accepted"]:
                raise GovernanceValidationError(
                    "Risk acceptance is not permitted "
                    "for an eligible release."
                )

            final_decision = "APPROVED"
            reason = (
                "Technical controls passed and "
                "governance approval was authorized."
            )

        elif not risk["accepted"]:
            final_decision = "REVIEW_REQUIRED"
            reason = (
                "Technical review requires "
                "explicit risk acceptance."
            )

        else:
            if (
                not isinstance(risk_owner_id, str)
                or risk_owner_id
                not in self.authorized_risk_owners
            ):
                raise GovernanceValidationError(
                    "Risk owner is not authorized."
                )

            if risk_owner_id in {requester, approver}:
                raise GovernanceValidationError(
                    "Risk owner must be independent "
                    "of requester and approver."
                )

            if risk["release_id"] != release_id:
                raise GovernanceValidationError(
                    "Risk acceptance release mismatch."
                )

            if risk["manifest_digest"] != manifest_digest:
                raise GovernanceValidationError(
                    "Risk acceptance manifest mismatch."
                )

            self._require_text(
                risk["justification"],
                "Risk justification",
            )

            risk_expiry = self._parse_time(
                risk["expires_at"]
            )

            if risk_expiry <= now_utc:
                raise GovernanceValidationError(
                    "Risk acceptance has expired."
                )

            if risk_expiry > expiry:
                raise GovernanceValidationError(
                    "Risk acceptance cannot outlive "
                    "governance approval."
                )

            accepted_risks = self._parse_accepted_risks(
                risk["accepted_risks"]
            )

            if accepted_risks != technical_risks:
                raise GovernanceValidationError(
                    "Accepted risk scope does not exactly "
                    "match technical review risks."
                )

            final_decision = "APPROVED"
            reason = (
                "Technical review risks explicitly "
                "accepted by an independent "
                "authorized risk owner."
            )

        record = {
            "release_id": release_id,
            "manifest_digest": manifest_digest,
            "decision": final_decision,
            "approver_id": approver,
            "risk_owner_id": (
                risk_owner_id
                if (
                    final_decision == "APPROVED"
                    and technical_result.decision == "REVIEW"
                )
                else None
            ),
            "expires_at": expiry.isoformat(),
            "reason": reason,
            "request": request,
            "technical_decision": technical_result.decision,
            "technical_review_risks": [
                {
                    "component_id": item.component_id,
                    "risk_id": item.risk_id,
                }
                for item in sorted(technical_risks)
            ],
        }

        digest = self._record_digest(record)

        return GovernanceResult(
            release_id=release_id,
            manifest_digest=manifest_digest,
            decision=final_decision,
            approver_id=approver,
            risk_owner_id=record["risk_owner_id"],
            expires_at=expiry.isoformat(),
            reason=reason,
            record_digest=digest,
        )