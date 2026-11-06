"""
Project 8 — Deployment & Rollback Hardening Tests

P8-H06: Machine-Verifiable Risk Acceptance
P8-H06: Expired Exception Reuse Verification

Adversarial validation of:
- Symlinked release directory rejection
- Symlinked snapshot artifact rejection
- Mandatory fresh rollback authorization
- Expired risk acceptance rejection
- Preservation of active release after failed rollback
- Preservation of audit history after failed rollback

All artifacts, identities, and authorization
records are synthetic.

No external deployment occurs.
"""

from datetime import timedelta
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_deployment_controller as deployment_fixtures

from src.deployment.controller import (
    DeploymentSecurityError,
)


class TestDeploymentHardening(unittest.TestCase):

    def setUp(self):
        self.fixture = (
            deployment_fixtures.TestControlledDeployment(
                methodName="test_001_authorized_deployment"
            )
        )

        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

        self.controller = self.fixture.controller

    def prepare_two_releases(self):
        self.fixture.deploy()
        self.fixture.deploy(
            self.fixture.second_release()
        )

    def rollback_authorization(
        self,
        release_id="ari-release-001",
    ):
        request = self.fixture.rollback_request(
            release_id
        )

        request["manifest_digest"] = (
            self.controller._releases[
                release_id
            ].manifest_digest
        )

        return request

    def test_001_reject_symlinked_release_directory(self):
        """
        A valid rollback authorization must not
        permit a symlinked release directory.
        """

        self.prepare_two_releases()

        storage = (
            self.fixture.directory / "snapshots"
        )

        original = storage / "ari-release-001"
        relocated = storage / "relocated-release"

        original.rename(relocated)
        original.symlink_to(
            relocated,
            target_is_directory=True,
        )

        request = self.rollback_authorization()

        audit_before = self.controller.audit_history

        with self.assertRaisesRegex(
            DeploymentSecurityError,
            "Symlinked release directory",
        ):
            self.controller.rollback(
                "ari-release-001",
                governance_request=request,
                now=self.fixture.now,
            )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-002",
        )

        self.assertEqual(
            self.controller.audit_history,
            audit_before,
        )

    def test_002_reject_symlinked_snapshot_file(self):
        """
        A valid rollback authorization must not
        permit a symlinked artifact snapshot.
        """

        self.prepare_two_releases()

        storage = (
            self.fixture.directory / "snapshots"
        )

        snapshot = (
            storage
            / "ari-release-001"
            / self.fixture.component_id
            / "research-assistant.bin"
        )

        relocated = (
            self.fixture.directory
            / "relocated-model.bin"
        )

        snapshot.rename(relocated)
        snapshot.symlink_to(relocated)

        request = self.rollback_authorization()

        audit_before = self.controller.audit_history

        with self.assertRaisesRegex(
            DeploymentSecurityError,
            "Missing or unsafe snapshot artifact",
        ):
            self.controller.rollback(
                "ari-release-001",
                governance_request=request,
                now=self.fixture.now,
            )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-002",
        )

        self.assertEqual(
            self.controller.audit_history,
            audit_before,
        )

    def test_003_rollback_requires_fresh_authorization(self):
        """
        A registered release cannot be reactivated
        without a new rollback authorization request.
        """

        self.prepare_two_releases()

        audit_before = self.controller.audit_history

        with self.assertRaisesRegex(
            DeploymentSecurityError,
            "Fresh rollback authorization required",
        ):
            self.controller.rollback(
                "ari-release-001"
            )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-002",
        )

        self.assertEqual(
            self.controller.audit_history,
            audit_before,
        )

    def test_004_expired_exception_not_implicitly_reusable(self):
        """
        An expired risk exception must not authorize
        rollback even when the original release was
        previously approved.

        Verify the specific expiration rejection,
        unchanged active release, and unchanged
        audit history.
        """

        # Initial release requires risk acceptance
        # because vulnerability scanning is incomplete.
        self.fixture.scan[
            "scan_status"
        ] = "incomplete"

        original_request = self.fixture.request()

        original_request = (
            self.fixture.accept_current_risks(
                original_request,
                expires_after=timedelta(hours=1),
            )
        )

        self.assertEqual(
            original_request["risk_acceptance"][
                "accepted_risks"
            ],
            [{
                "component_id": self.fixture.component_id,
                "risk_id": "POLICY:SCAN_INCOMPLETE",
            }],
        )

        self.fixture.deploy(original_request)

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-001",
        )

        # Deploy a second release with completed
        # vulnerability scanning.
        self.fixture.scan[
            "scan_status"
        ] = "completed"

        self.fixture.deploy(
            self.fixture.second_release()
        )

        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-002",
        )

        # Advance beyond the original risk
        # acceptance expiration.
        later = (
            self.fixture.now + timedelta(days=2)
        )

        request = self.rollback_authorization()

        # Fresh governance approval, but reuse
        # the expired risk exception.
        request["expires_at"] = (
            later + timedelta(days=1)
        ).isoformat()

        request["risk_acceptance"] = (
            original_request["risk_acceptance"].copy()
        )

        audit_before = self.controller.audit_history

        # Require the precise governance rejection
        # reason rather than an arbitrary error.
        with self.assertRaisesRegex(
            DeploymentSecurityError,
            "Governance authorization failed: "
            "Risk acceptance has expired",
        ):
            self.controller.rollback(
                "ari-release-001",
                governance_request=request,
                now=later,
            )

        # Failed rollback must not activate the
        # expired-exception release.
        self.assertEqual(
            self.controller.active_release_id,
            "ari-release-002",
        )

        # Failed authorization must not append
        # a successful rollback audit record.
        self.assertEqual(
            self.controller.audit_history,
            audit_before,
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)