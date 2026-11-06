"""
Project 8 — Artifact Integrity Verifier

Security objective:
    P8-SO02 — Artifact Integrity Verification

Trust boundary:
    TB-02 — Artifact to Integrity Verifier

Implemented controls:
    - SHA-256 calculation over artifact bytes
    - Strict reference-digest validation
    - Constant-time digest comparison
    - Artifact size verification
    - Manifest/reference consistency checks
    - Explicit failure on missing or unreadable artifacts

Trust model:
    The expected digest is supplied independently
    from the untrusted component manifest.

    The caller is responsible for obtaining that
    reference from an authorized trust source.

    This module does not authenticate the reference,
    establish provenance, or authorize deployment.

Environment:
    Local, offline, synthetic artifacts.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

CHUNK_SIZE = 1024 * 1024


class ArtifactIntegrityError(ValueError):
    """Raised when an artifact fails integrity verification."""


@dataclass(frozen=True)
class IntegrityResult:
    artifact_name: str
    algorithm: str
    calculated_digest: str
    expected_digest: str
    size_bytes: int
    verified: bool


class ArtifactIntegrityVerifier:
    """
    Verify a local artifact against an independently
    supplied SHA-256 reference digest.

    A successful result means that the bytes read
    matched the supplied reference.

    It does not establish artifact safety, origin,
    or authorization.
    """

    @staticmethod
    def _validate_digest(digest: str) -> None:
        if (
            not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise ArtifactIntegrityError(
                "Expected digest must contain exactly "
                "64 lowercase hexadecimal characters."
            )

    @staticmethod
    def calculate_sha256(path: Path) -> tuple[str, int]:
        """
        Calculate SHA-256 and byte count from one
        streamed read of the artifact.
        """

        path = Path(path)

        if path.is_symlink():
            raise ArtifactIntegrityError(
                "Symbolic-link artifacts are not permitted."
            )

        if not path.is_file():
            raise ArtifactIntegrityError(
                "Artifact does not exist or is not a regular file."
            )

        hasher = hashlib.sha256()
        size_bytes = 0

        try:
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(CHUNK_SIZE)

                    if not chunk:
                        break

                    hasher.update(chunk)
                    size_bytes += len(chunk)

        except OSError as exc:
            raise ArtifactIntegrityError(
                f"Unable to read artifact: {exc}"
            ) from exc

        return hasher.hexdigest(), size_bytes

    def verify(
        self,
        artifact_path: Path,
        trusted_digest: str,
        declared_digest: Optional[str] = None,
        declared_size: Optional[int] = None,
    ) -> IntegrityResult:
        """
        Verify an artifact against a trusted reference.

        Args:
            artifact_path:
                Local artifact path.

            trusted_digest:
                Independently supplied expected SHA-256.

            declared_digest:
                Optional digest from an untrusted manifest.
                Must match the trusted reference.

            declared_size:
                Optional expected byte count from the
                manifest.

        Returns:
            IntegrityResult if every check succeeds.

        Raises:
            ArtifactIntegrityError on any failed check.
        """

        self._validate_digest(trusted_digest)

        if declared_digest is not None:
            self._validate_digest(declared_digest)

            if not hmac.compare_digest(
                declared_digest,
                trusted_digest,
            ):
                raise ArtifactIntegrityError(
                    "Manifest digest differs from "
                    "the trusted reference digest."
                )

        if declared_size is not None:
            if (
                isinstance(declared_size, bool)
                or not isinstance(declared_size, int)
                or declared_size < 0
            ):
                raise ArtifactIntegrityError(
                    "Declared size must be a "
                    "nonnegative integer."
                )

        calculated_digest, actual_size = (
            self.calculate_sha256(artifact_path)
        )

        if declared_size is not None:
            if actual_size != declared_size:
                raise ArtifactIntegrityError(
                    "Artifact size does not match "
                    "the declared size."
                )

        if not hmac.compare_digest(
            calculated_digest,
            trusted_digest,
        ):
            raise ArtifactIntegrityError(
                "Artifact SHA-256 digest does not match "
                "the trusted reference."
            )

        return IntegrityResult(
            artifact_name=Path(artifact_path).name,
            algorithm="sha256",
            calculated_digest=calculated_digest,
            expected_digest=trusted_digest,
            size_bytes=actual_size,
            verified=True,
        )