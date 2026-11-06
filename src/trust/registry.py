"""
Project 8 — Synthetic Trusted Release Registry

Offline HMAC-authenticated release trust records.

The verification key must be configured independently
from the release-submitting caller.

This module does not implement production key custody,
a transparency log, or external identity authentication.
"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Mapping


class TrustRegistryError(ValueError):
    """Trusted-release record verification failure."""


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TrustRegistryError(
            "Trust record cannot be canonicalized."
        ) from exc


@dataclass(frozen=True)
class TrustedRelease:
    release_id: str
    manifest_digest: str
    component_digests: tuple[tuple[str, str], ...]
    issuer_id: str
    record_digest: str


class TrustedReleaseRegistry:
    """
    Verifies externally issued synthetic trust records.

    A valid HMAC is necessary but not sufficient for
    production authenticity: key custody and issuer
    authorization are external trust assumptions.
    """

    def __init__(
        self,
        trusted_issuers: Mapping[str, bytes],
    ) -> None:
        if not isinstance(trusted_issuers, Mapping):
            raise TrustRegistryError(
                "Trusted issuer mapping required."
            )

        if not trusted_issuers:
            raise TrustRegistryError(
                "At least one issuer is required."
            )

        self._keys = {}

        for issuer, key in trusted_issuers.items():
            if (
                not isinstance(issuer, str)
                or not _ID.fullmatch(issuer)
            ):
                raise TrustRegistryError(
                    "Invalid issuer identifier."
                )

            if (
                not isinstance(key, bytes)
                or len(key) < 32
            ):
                raise TrustRegistryError(
                    "Issuer key must contain at least 32 bytes."
                )

            self._keys[issuer] = bytes(key)

        self._registered = {}

    def verify_and_register(
        self,
        record: dict,
    ) -> TrustedRelease:

        if not isinstance(record, dict):
            raise TrustRegistryError(
                "Trust record must be an object."
            )

        expected_fields = {
            "schema_version",
            "release_id",
            "manifest_digest",
            "component_digests",
            "issuer_id",
            "signature",
        }

        if set(record) != expected_fields:
            raise TrustRegistryError(
                "Invalid trust record fields."
            )

        if record["schema_version"] != "1.0.0":
            raise TrustRegistryError(
                "Unsupported trust record version."
            )

        release_id = record["release_id"]
        issuer = record["issuer_id"]
        manifest_digest = record["manifest_digest"]
        components = record["component_digests"]
        signature = record["signature"]

        if (
            not isinstance(release_id, str)
            or not _ID.fullmatch(release_id)
        ):
            raise TrustRegistryError(
                "Invalid release identifier."
            )

        if issuer not in self._keys:
            raise TrustRegistryError(
                "Untrusted record issuer."
            )

        if (
            not isinstance(manifest_digest, str)
            or not _DIGEST.fullmatch(manifest_digest)
        ):
            raise TrustRegistryError(
                "Invalid manifest digest."
            )

        if (
            not isinstance(components, dict)
            or not components
        ):
            raise TrustRegistryError(
                "Component digest mapping required."
            )

        for component_id, digest in components.items():
            if (
                not isinstance(component_id, str)
                or not _ID.fullmatch(component_id)
                or not isinstance(digest, str)
                or not _DIGEST.fullmatch(digest)
            ):
                raise TrustRegistryError(
                    "Invalid component digest entry."
                )

        if (
            not isinstance(signature, str)
            or not _DIGEST.fullmatch(signature)
        ):
            raise TrustRegistryError(
                "Invalid record signature."
            )

        claims = {
            key: value
            for key, value in record.items()
            if key != "signature"
        }

        expected_signature = hmac.new(
            self._keys[issuer],
            _canonical(claims),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            expected_signature,
            signature,
        ):
            raise TrustRegistryError(
                "Trust record authentication failed."
            )

        record_digest = hashlib.sha256(
            _canonical(record)
        ).hexdigest()

        trusted = TrustedRelease(
            release_id=release_id,
            manifest_digest=manifest_digest,
            component_digests=tuple(
                sorted(components.items())
            ),
            issuer_id=issuer,
            record_digest=record_digest,
        )

        existing = self._registered.get(release_id)

        if existing is not None:
            if existing != trusted:
                raise TrustRegistryError(
                    "Conflicting release registration."
                )
            return existing

        self._registered[release_id] = trusted
        return trusted

    def require(
        self,
        release_id: str,
        manifest_digest: str,
        component_digests: Mapping[str, str],
    ) -> TrustedRelease:

        trusted = self._registered.get(release_id)

        if trusted is None:
            raise TrustRegistryError(
                "Release is not registered as trusted."
            )

        if trusted.manifest_digest != manifest_digest:
            raise TrustRegistryError(
                "Trusted manifest digest mismatch."
            )

        if (
            dict(trusted.component_digests)
            != dict(component_digests)
        ):
            raise TrustRegistryError(
                "Trusted component digests mismatch."
            )

        return trusted


def sign_synthetic_trust_record(
    claims: dict,
    secret: bytes,
) -> dict:
    """
    Test-only synthetic record issuer.

    Do not expose this signing capability to the
    deployment-submitting actor in a real system.
    """

    if not isinstance(claims, dict):
        raise TrustRegistryError(
            "Claims must be an object."
        )

    if "signature" in claims:
        raise TrustRegistryError(
            "Claims must not include a signature."
        )

    if (
        not isinstance(secret, bytes)
        or len(secret) < 32
    ):
        raise TrustRegistryError(
            "Invalid signing key."
        )

    record = dict(claims)

    record["signature"] = hmac.new(
        secret,
        _canonical(claims),
        hashlib.sha256,
    ).hexdigest()

    return record