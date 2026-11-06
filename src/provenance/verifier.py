"""
Project 8 — Synthetic Provenance Assurance

Security objective:
    P8-SO03 — Provenance Assurance

Trust boundary:
    TB-03 — Provenance Evidence to Trust Decision

This module demonstrates authenticated provenance
metadata using HMAC-SHA256 and an independent trust
policy.

HMAC is a laboratory mechanism, not production
SLSA provenance or independent builder identity
attestation.

The signing secret and trust policy must be supplied
through a trusted channel, never from the attestation.

A successful result does not authorize deployment.
"""

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

ATTESTATION_FIELDS = frozenset({
    "schema_version",
    "subject_id",
    "subject_digest",
    "builder_id",
    "source_uri",
    "source_revision",
    "key_id",
    "signature",
})

SIGNED_FIELDS = ATTESTATION_FIELDS - {"signature"}


class ProvenanceVerificationError(ValueError):
    """Raised when provenance authentication or policy fails."""


@dataclass(frozen=True)
class ProvenanceResult:
    subject_id: str
    subject_digest: str
    builder_id: str
    source_uri: str
    source_revision: str
    key_id: str
    verified: bool
    assurance: str = "synthetic-hmac"


@dataclass(frozen=True)
class ProvenanceTrustPolicy:
    """
    Independently configured verification policy.

    The policy must not be derived from an untrusted
    attestation or component manifest.
    """

    trusted_keys: Mapping[str, bytes]
    allowed_builders: frozenset[str]
    allowed_sources: frozenset[str]
    allowed_revisions: frozenset[str]

    def __post_init__(self):
        if not self.trusted_keys:
            raise ValueError("At least one trusted key is required.")

        for key_id, secret in self.trusted_keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("Invalid trusted key identifier.")

            if not isinstance(secret, bytes) or len(secret) < 32:
                raise ValueError(
                    "Synthetic HMAC secrets must contain "
                    "at least 32 bytes."
                )

        for values in (
            self.allowed_builders,
            self.allowed_sources,
            self.allowed_revisions,
        ):
            if not values or not all(
                isinstance(value, str) and value
                for value in values
            ):
                raise ValueError(
                    "Trust policy allowlists must be nonempty."
                )


def canonical_payload(fields: Mapping[str, Any]) -> bytes:
    """
    Serialize signed fields deterministically.

    This canonicalization is specific to this
    laboratory and is not a general-purpose
    JSON canonicalization standard.
    """

    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sign_synthetic_attestation(
    claims: Mapping[str, Any],
    secret: bytes,
) -> dict:
    """
    Generate synthetic test attestations.

    This helper represents a simulated producer.
    It must not be exposed to untrusted callers
    as an authorization or signing service.
    """

    if not isinstance(claims, dict):
        raise ValueError("Claims must be a dictionary.")

    if set(claims) != SIGNED_FIELDS:
        raise ValueError("Incorrect signed claim fields.")

    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("Invalid synthetic signing secret.")

    payload = canonical_payload(claims)

    signature = hmac.new(
        secret,
        payload,
        hashlib.sha256,
    ).hexdigest()

    return {**claims, "signature": signature}


class ProvenanceVerifier:
    """Authenticate and evaluate synthetic provenance."""

    def __init__(self, policy: ProvenanceTrustPolicy):
        if not isinstance(policy, ProvenanceTrustPolicy):
            raise TypeError("A trusted policy is required.")

        self.policy = policy

    def verify(
        self,
        attestation: dict,
        expected_subject_id: str,
        expected_digest: str,
    ) -> ProvenanceResult:

        if not isinstance(attestation, dict):
            raise ProvenanceVerificationError(
                "Attestation must be an object."
            )

        if set(attestation) != ATTESTATION_FIELDS:
            raise ProvenanceVerificationError(
                "Attestation fields are missing or unexpected."
            )

        if not all(
            isinstance(value, str) and value
            for value in attestation.values()
        ):
            raise ProvenanceVerificationError(
                "Attestation fields must be nonempty strings."
            )

        if attestation["schema_version"] != "1.0.0":
            raise ProvenanceVerificationError(
                "Unsupported attestation schema version."
            )

        if not isinstance(expected_subject_id, str) or not expected_subject_id:
            raise ProvenanceVerificationError(
                "Invalid expected subject identifier."
            )

        if (
            not isinstance(expected_digest, str)
            or DIGEST_PATTERN.fullmatch(expected_digest) is None
        ):
            raise ProvenanceVerificationError(
                "Invalid expected artifact digest."
            )

        if DIGEST_PATTERN.fullmatch(
            attestation["subject_digest"]
        ) is None:
            raise ProvenanceVerificationError(
                "Invalid attestation subject digest."
            )

        signature = attestation["signature"]

        if DIGEST_PATTERN.fullmatch(signature) is None:
            raise ProvenanceVerificationError(
                "Invalid signature encoding."
            )

        key_id = attestation["key_id"]

        if key_id not in self.policy.trusted_keys:
            raise ProvenanceVerificationError(
                "Untrusted signing key identifier."
            )

        claims = {
            field: attestation[field]
            for field in SIGNED_FIELDS
        }

        calculated_signature = hmac.new(
            self.policy.trusted_keys[key_id],
            canonical_payload(claims),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_signature,
            signature,
        ):
            raise ProvenanceVerificationError(
                "Attestation authentication failed."
            )

        if attestation["subject_id"] != expected_subject_id:
            raise ProvenanceVerificationError(
                "Attestation subject identity mismatch."
            )

        if not hmac.compare_digest(
            attestation["subject_digest"],
            expected_digest,
        ):
            raise ProvenanceVerificationError(
                "Attestation artifact digest mismatch."
            )

        if (
            attestation["builder_id"]
            not in self.policy.allowed_builders
        ):
            raise ProvenanceVerificationError(
                "Builder is not authorized."
            )

        if (
            attestation["source_uri"]
            not in self.policy.allowed_sources
        ):
            raise ProvenanceVerificationError(
                "Source is not authorized."
            )

        if (
            attestation["source_revision"]
            not in self.policy.allowed_revisions
        ):
            raise ProvenanceVerificationError(
                "Source revision is not authorized."
            )

        return ProvenanceResult(
            subject_id=attestation["subject_id"],
            subject_digest=attestation["subject_digest"],
            builder_id=attestation["builder_id"],
            source_uri=attestation["source_uri"],
            source_revision=attestation["source_revision"],
            key_id=key_id,
            verified=True,
        )