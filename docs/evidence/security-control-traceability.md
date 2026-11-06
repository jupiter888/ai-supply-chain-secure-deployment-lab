# Project 8 — Security-Control Traceability Matrix

**Project:** AI Supply Chain and Secure Deployment Lab  
**Document status:** Initial implementation-to-test traceability baseline  
**Environment:** Local, offline, synthetic Python security laboratory  
**Regression baseline:** 242 automated tests passing  
**Evidence basis:** Reviewed implementation modules, registration schema, test-function inventory, and successful regression execution

---

## 1. Purpose

This document establishes traceability between the security objectives, trust boundaries, implemented controls, automated tests, and residual limitations of Project 8.

The purpose is to demonstrate which security requirements have supporting implementation and validation evidence.

The matrix distinguishes:

- Implemented controls.
- Identified automated test coverage.
- Independently reviewed implementation behavior.
- Test assertions requiring further examination.
- Residual security risks and operational limitations.

A passing automated test is evidence of the behavior exercised by that test. It does not establish universal security assurance.

## 2. Evidence Classification

The following classifications are used throughout this document.

| Classification | Meaning |
|---|---|
| IMPLEMENTED | The relevant implementation has been identified in the repository |
| CODE REVIEWED | The relevant implementation behavior has been examined |
| TEST IDENTIFIED | A named automated test addresses the security scenario |
| REGRESSION PASSED | The test is included in the successfully executed regression suite |
| ASSERTION REVIEW PENDING | The complete test body and assertions have not been independently examined |
| ARCHITECTURAL ASSUMPTION | The control depends on an explicitly stated trust or operational assumption |
| OUT OF SCOPE | The capability is not provided by the synthetic laboratory |

These classifications are not mutually exclusive.

For example, a control may be implemented and regression-tested while still requiring assertion-level review.

## 3. Validation Baseline

### 3.1 Regression Execution

The complete test suite is executed using:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

**Latest recorded result:**

```text
Ran 242 tests in 2.264s

OK
```

### 3.2 Test Inventory

| Test module | Tests |
|---|---:|
| `test_inventory_schema.py` | 14 |
| `test_inventory_validator.py` | 20 |
| `test_artifact_integrity.py` | 20 |
| `test_provenance_verifier.py` | 22 |
| `test_vulnerability_assessor.py` | 30 |
| `test_release_gate.py` | 24 |
| `test_governance.py` | 44 |
| `test_governance_consistency.py` | 18 |
| `test_risk_acceptance_integration.py` | 10 |
| `test_trust_registry.py` | 16 |
| `test_deployment_controller.py` | 16 |
| `test_deployment_trust_enforcement.py` | 4 |
| `test_deployment_hardening.py` | 4 |
| **Total** | **242** |

The test counts are derived from the supplied test-function inventory.

The complete regression has been executed successfully.

Individual test assertions have not all been independently reviewed for this traceability assessment.

## 4. Security Objective Traceability

| Objective | Security requirement | Primary implementation | Test evidence | Trust boundary |
|---|---|---|---|---|
| P8-SO01 | Validate component identity and dependencies | `src/inventory/validator.py` | Inventory schema and validator tests | TB-01 |
| P8-SO02 | Detect modified artifacts | `src/integrity/verifier.py` | Artifact integrity tests | TB-02 |
| P8-SO03 | Evaluate provenance evidence | `src/provenance/verifier.py` | Provenance verifier tests | TB-03 |
| P8-SO04 | Assess vulnerability findings | `src/scanning/assessor.py` | Vulnerability assessor tests | TB-04 |
| P8-SO05 | Enforce technical release requirements | `src/policy/release_gate.py` | Release gate tests | TB-04, TB-05 |
| P8-SO06 | Require validated release authorization | `src/policy/governance.py` | Governance and integration tests | TB-05 |
| P8-SO07 | Permit only verified, authorized rollback | `src/deployment/controller.py` | Deployment and hardening tests | TB-07 |
| P8-SO08 | Preserve traceable security decisions | Governance and deployment modules | Governance digest and audit-chain tests | TB-08 |
| P8-SO09 | Enforce risk ownership and acceptance requirements | `src/policy/governance.py` | Governance and risk acceptance tests | TB-05, TB-08 |

The mappings identify supporting implementation and test coverage.

They do not constitute a formal proof that every possible violation of an objective is prevented.

## 5. P8-SO01 — Component Identification

**Primary trust boundary:** TB-01

### Implemented Controls

- JSON Schema Draft 2020-12 registration validation.
- Required-field and allowed-value enforcement.
- Duplicate component identifier rejection.
- Dependency existence validation.
- Direct self-dependency rejection.
- Directed dependency-cycle detection.
- Registration-only security-state enforcement.
- Defensive copying of accepted records.

**Implementation:**

- `policies/component-inventory.schema.json`
- `src/inventory/validator.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_inventory_schema.py::test_003_missing_required_field` | Missing mandatory field rejection |
| `test_inventory_schema.py::test_007_forged_provenance_verification` | Unauthorized provenance-state rejection |
| `test_inventory_schema.py::test_008_forged_license_approval` | Unauthorized license approval rejection |
| `test_inventory_schema.py::test_009_forged_risk_acceptance` | Unauthorized initial risk acceptance rejection |
| `test_inventory_validator.py::test_003_duplicate_component_id` | Duplicate identity rejection |
| `test_inventory_validator.py::test_004_missing_dependency` | Missing dependency rejection |
| `test_inventory_validator.py::test_005_direct_self_dependency` | Self-dependency rejection |
| `test_inventory_validator.py::test_006_two_component_cycle` | Dependency-cycle rejection |
| `test_inventory_validator.py::test_019_deep_acyclic_chain` | Deep dependency-graph handling |
| `test_inventory_validator.py::test_015_output_is_defensive_copy` | Defensive copying |

**Evidence status:** IMPLEMENTED, CODE REVIEWED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Validated registration metadata is not independently authenticated component provenance or artifact integrity evidence.

## 6. P8-SO02 — Artifact Integrity

**Primary trust boundary:** TB-02

### Implemented Controls

- Local artifact digest calculation.
- Expected-digest comparison.
- Artifact-size verification.
- Rejection of modified artifacts.
- Rejection of selected malformed integrity references.
- Separation of declared digests from trusted references.

**Implementation:** `src/integrity/verifier.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_artifact_integrity.py::test_004_modified_artifact_rejected` | Modified artifact rejection |
| `test_artifact_integrity.py::test_005_same_size_tampering_rejected` | Detection of same-size modification |
| `test_artifact_integrity.py::test_006_forged_manifest_digest_rejected` | Forged digest rejection |
| `test_artifact_integrity.py::test_011_symbolic_link_rejected` | Symbolic-link rejection |
| `test_artifact_integrity.py::test_017_untrusted_digest_not_used_as_reference` | Trusted-reference separation |
| `test_artifact_integrity.py::test_016_result_is_immutable` | Immutable result representation |

**Evidence status:** IMPLEMENTED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Digest verification does not establish that an artifact is benign. Filesystem verification is not a substitute for crash-atomic or concurrency-safe deployment.

## 7. P8-SO03 — Provenance Assurance

**Primary trust boundary:** TB-03

### Implemented Controls

- Dedicated provenance verification.
- Subject and digest binding.
- Builder and source-policy evaluation.
- Signature and signing-key validation within the synthetic trust model.
- Rejection of inconsistent or unauthorized provenance claims.

**Implementation:** `src/provenance/verifier.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_provenance_verifier.py::test_001_valid_attestation` | Valid synthetic attestation |
| `test_provenance_verifier.py::test_006_forged_signature` | Forged signature rejection |
| `test_provenance_verifier.py::test_007_unknown_key` | Unknown key rejection |
| `test_provenance_verifier.py::test_010_wrong_artifact_digest` | Artifact digest mismatch |
| `test_provenance_verifier.py::test_012_unauthorized_builder_with_valid_hmac` | Builder policy enforcement |
| `test_provenance_verifier.py::test_021_valid_hmac_cannot_override_digest_policy` | Signature validity does not override digest policy |
| `test_provenance_verifier.py::test_022_valid_hmac_cannot_override_subject_policy` | Signature validity does not override subject policy |

**Evidence status:** IMPLEMENTED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** The laboratory does not independently establish production builder identities or externally protected signing-key custody.

## 8. P8-SO04 — Vulnerability Assessment

**Primary trust boundary:** TB-04

### Implemented Controls

- Structured vulnerability finding assessment.
- Severity and applicability evaluation.
- Scan-completeness handling.
- Dependency and artifact coverage assessment.
- Rejection of malformed or inconsistent evidence.
- Deterministic assessment results.

**Implementation:** `src/scanning/assessor.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_vulnerability_assessor.py::test_002_critical_affected_denies` | Critical vulnerability denial |
| `test_vulnerability_assessor.py::test_003_high_affected_denies` | High-severity vulnerability denial |
| `test_vulnerability_assessor.py::test_004_medium_affected_requires_review` | Medium-severity review |
| `test_vulnerability_assessor.py::test_008_incomplete_scan_requires_review` | Incomplete scan review |
| `test_vulnerability_assessor.py::test_010_missing_dependency_coverage` | Missing dependency coverage |
| `test_vulnerability_assessor.py::test_018_forged_approval_property` | Forged approval metadata rejection |
| `test_vulnerability_assessor.py::test_023_deny_precedes_review` | Denial precedence |
| `test_vulnerability_assessor.py::test_025_result_is_deterministic` | Deterministic evaluation |

**Evidence status:** IMPLEMENTED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** The laboratory evaluates synthetic vulnerability evidence and does not demonstrate complete live vulnerability intelligence or production scanner integration.

## 9. P8-SO05 — Release Policy Enforcement

**Primary trust boundaries:** TB-04, TB-05

### Implemented Controls

- Component-level security evaluation.
- Aggregate technical release decisions.
- Explicit `ELIGIBLE`, `REVIEW`, and `BLOCKED` outcomes.
- Mandatory block precedence.
- Component-specific review-risk identification.
- Rejection of missing or inconsistent component evidence.

**Implementation:** `src/policy/release_gate.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_release_gate.py::test_001_valid_candidate_eligible` | Eligible release evaluation |
| `test_release_gate.py::test_002_modified_artifact_blocked` | Integrity failure blocks release |
| `test_release_gate.py::test_006_forged_attestation_blocked` | Forged provenance blocks release |
| `test_release_gate.py::test_007_critical_vulnerability_blocked` | Critical vulnerability blocks release |
| `test_release_gate.py::test_008_medium_vulnerability_requires_review` | Review-required finding |
| `test_release_gate.py::test_015_dependency_vulnerability_blocks_release` | Dependency risk propagation |
| `test_release_gate.py::test_017_block_precedes_review` | Blocking decision precedence |
| `test_release_gate.py::test_023_untrusted_digest_substitution_blocked` | Digest substitution rejection |

**Evidence status:** IMPLEMENTED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Technical eligibility does not independently establish governance authorization or production security assurance.

## 10. P8-SO06 — Release Authorization

**Primary trust boundary:** TB-05

### Implemented Controls

- Release-bound governance authorization.
- Manifest-digest binding.
- Operation-specific authorization.
- Authorized approver validation.
- Separation-of-duties checks.
- Expiration validation.
- Technical-result consistency checks.
- Explicit handling of review-required risks.

**Implementation:** `src/policy/governance.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_governance.py::test_002_unauthorized_approver` | Unauthorized approver rejection |
| `test_governance.py::test_003_self_approval_rejected` | Separation-of-duties enforcement |
| `test_governance.py::test_004_wrong_release_id` | Release binding |
| `test_governance.py::test_005_wrong_manifest_digest` | Manifest binding |
| `test_governance.py::test_006_expired_approval` | Expired approval rejection |
| `test_governance.py::test_007_blocked_gate_cannot_be_approved` | Blocked technical decision enforcement |
| `test_governance_consistency.py::test_002_component_count_mismatch_rejected` | Component-count consistency |
| `test_governance_consistency.py::test_011_cross_component_risk_substitution` | Risk-component binding |
| `test_governance_consistency.py::test_013_review_component_without_risks` | Invalid review evidence rejection |

**Evidence status:** IMPLEMENTED, CODE REVIEWED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Authorization uses synthetic identities and modeled authority rather than independently authenticated enterprise identities.

## 11. P8-SO07 — Verified Rollback

**Primary trust boundary:** TB-07

### Implemented Controls

- Explicit rollback request.
- Trusted recovery-release verification.
- Recovery snapshot verification.
- Fresh technical evaluation.
- New governance authorization.
- Expired risk-acceptance rejection.
- Selected symlink and path-safety protections.
- Active-release preservation following rejected transitions.

**Implementation:** `src/deployment/controller.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_deployment_controller.py::test_011_successful_rollback` | Authorized rollback |
| `test_deployment_controller.py::test_012_tampered_rollback_snapshot_blocked` | Recovery artifact tampering |
| `test_deployment_controller.py::test_014_rollback_to_active_release_blocked` | Invalid rollback target |
| `test_deployment_controller.py::test_016_no_activation_after_rejection` | Rejected transition preserves active release |
| `test_deployment_hardening.py::test_001_reject_symlinked_release_directory` | Symlinked release-directory rejection |
| `test_deployment_hardening.py::test_002_reject_symlinked_snapshot_file` | Symlinked snapshot rejection |
| `test_deployment_hardening.py::test_003_rollback_requires_fresh_authorization` | Fresh rollback authorization |
| `test_deployment_hardening.py::test_004_expired_exception_not_implicitly_reusable` | Expired exception rejection |

**Evidence status:** IMPLEMENTED, CODE REVIEWED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Rollback is simulated and explicitly requested. The controller does not implement production crash recovery or concurrent transactional state management.

## 12. P8-SO08 — Auditability

**Primary trust boundary:** TB-08

### Implemented Controls

- Deterministic governance decision digests.
- Chained in-memory release audit records.
- Recorded deployment and rollback outcomes.
- Rejection-path state-preservation checks.

**Implementations:**

- `src/policy/governance.py`
- `src/deployment/controller.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_governance.py::test_024_record_digest_is_deterministic` | Deterministic governance evidence |
| `test_governance.py::test_025_changed_justification_changes_digest` | Decision digest reflects justification |
| `test_deployment_controller.py::test_015_audit_chain_changes_with_operations` | Audit-chain changes across operations |
| `test_deployment_hardening.py::test_004_expired_exception_not_implicitly_reusable` | Rejected rollback preserves audit history |

**Evidence status:** IMPLEMENTED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Audit records are maintained in memory and are not externally anchored, independently immutable, or durably retained.

## 13. P8-SO09 — Governance and Risk Acceptance

**Primary trust boundaries:** TB-05, TB-08

### Implemented Controls

- Authorized risk-owner validation.
- Requester and approver separation.
- Exact release and manifest binding.
- Component-specific risk binding.
- Exact accepted-risk set validation.
- Justification requirements.
- Expiration enforcement.
- Rejection of duplicate and unrelated accepted risks.
- Prevention of ordinary acceptance overriding blocked technical decisions.

**Implementation:** `src/policy/governance.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_governance.py::test_010_unauthorized_risk_owner` | Risk-owner authority |
| `test_governance.py::test_011_requester_cannot_accept_risk` | Requester separation |
| `test_governance.py::test_012_approver_cannot_accept_risk` | Approver separation |
| `test_governance.py::test_013_expired_risk_acceptance` | Expiration enforcement |
| `test_governance.py::test_031_cross_release_acceptance_rejected` | Release binding |
| `test_governance.py::test_032_cross_manifest_acceptance_rejected` | Manifest binding |
| `test_governance.py::test_033_cross_component_acceptance_rejected` | Component binding |
| `test_governance.py::test_036_duplicate_accepted_risk_rejected` | Duplicate acceptance rejection |
| `test_governance.py::test_038_blocked_gate_cannot_be_overridden` | Mandatory block enforcement |
| `test_risk_acceptance_integration.py::test_008_policy_finding_collision_blocked` | Namespaced risk-identity protection |
| `test_risk_acceptance_integration.py::test_010_valid_exact_risk_acceptance` | Valid exact risk acceptance |

**Evidence status:** IMPLEMENTED, CODE REVIEWED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Governance decisions model organizational authority using synthetic identity records rather than an operational enterprise approval system.

## 14. Trusted Release Registry — Cross-Cutting Control

**Primary trust boundaries:** TB-02, TB-06

### Implemented Controls

- Synthetic authenticated release registration.
- Release identity and manifest binding.
- Component artifact digest binding.
- Rejection of unregistered releases.
- Rejection of invalid or conflicting registrations.
- Rejection of forged or tampered signatures.

**Implementation:** `src/trust/registry.py`

### Representative Test Evidence

| Test | Security behavior |
|---|---|
| `test_trust_registry.py::test_001_authorized_record_accepted` | Authorized registration |
| `test_trust_registry.py::test_002_unregistered_release_rejected` | Unregistered release rejection |
| `test_trust_registry.py::test_004_artifact_digest_substitution_rejected` | Component digest binding |
| `test_trust_registry.py::test_005_manifest_substitution_rejected` | Manifest binding |
| `test_trust_registry.py::test_006_attacker_signature_rejected` | Forged signature rejection |
| `test_trust_registry.py::test_009_conflicting_registration_rejected` | Conflicting registration rejection |
| `test_deployment_trust_enforcement.py::test_002_matching_attacker_digest_rejected` | Attacker-controlled digest cannot establish trust |

**Evidence status:** IMPLEMENTED, TEST IDENTIFIED, REGRESSION PASSED.

**Residual limitation:** Trust authority is synthetic, HMAC key custody is externally assumed, and registry state is maintained locally in memory.

## 15. Trust Boundary Coverage

| Boundary | Principal control | Relevant tests |
|---|---|---|
| TB-01 | Inventory registration | Inventory schema and validator |
| TB-02 | Artifact integrity and trusted references | Artifact integrity, trust registry |
| TB-03 | Provenance verification | Provenance verifier |
| TB-04 | Vulnerability evidence and technical policy | Vulnerability assessor, release gate |
| TB-05 | Technical-to-governance authorization | Governance, consistency, risk acceptance |
| TB-06 | Authorized release transition | Trust enforcement, deployment controller |
| TB-07 | Recovery authorization and integrity | Deployment controller, deployment hardening |
| TB-08 | Decision and audit evidence | Governance, deployment controller |

All eight trust boundaries have identified implementation and automated test evidence.

This does not imply exhaustive attack-path coverage.

## 16. Residual Risk Register — Initial Baseline

| ID | Residual risk | Existing boundary | Required production consideration |
|---|---|---|---|
| RR-01 | Synthetic identity impersonation | Modeled governance roles | Enterprise identity authentication and authorization |
| RR-02 | Trust-authority key compromise | Synthetic HMAC verification | Protected key custody, rotation, and compromise response |
| RR-03 | In-memory registry loss or modification | Local release registry | Durable, access-controlled trust records |
| RR-04 | In-memory audit loss or alteration | Chained local audit records | External immutable or tamper-evident audit retention |
| RR-05 | Concurrent artifact modification | Local digest and snapshot verification | Atomic artifact handling and concurrency controls |
| RR-06 | Interrupted deployment transition | Simulated state updates | Transactional deployment and recovery design |
| RR-07 | Incomplete vulnerability intelligence | Synthetic finding assessment | Authenticated scanner integration and coverage monitoring |
| RR-08 | Compromised provenance authority | Synthetic provenance verification | Independent build identity and protected signing infrastructure |
| RR-09 | Incomplete adversarial coverage | Automated regression suite | Broader threat-driven validation and security review |
| RR-10 | Unverified organizational governance | Synthetic approval model | Real decision authority, accountable ownership, and durable approval records |

These entries identify architectural limitations and production risk considerations.

They are not formal organizational risk acceptances.

No residual risk is considered accepted merely because it appears in this register.

## 17. Evidence Gaps and Follow-Up Work

The following work remains to strengthen the security assurance record.

### EG-01 — Assertion-Level Test Review

Review the actual test bodies and assertions for each mapped control.

Confirm that each test proves the stated expected behavior rather than merely invoking the relevant code path.

### EG-02 — Threat-to-Control Mapping

Create an explicit STRIDE threat model mapping:

- Threat identifier.
- Threatened asset.
- Trust boundary.
- Attack precondition.
- Implemented mitigation.
- Test evidence.
- Residual risk.

### EG-03 — Governance Framework Mapping

Develop documented mappings to:

- NIST AI RMF 1.0.
- ISO/IEC 42001:2023.
- NIST SSDF.
- Relevant SLSA concepts.
- MITRE ATLAS techniques.

Distinguish conceptual alignment from verified implementation.

### EG-04 — Reproducible Evidence Capture

Record a reproducible regression execution with:

- Test command.
- Execution environment.
- Execution timestamp.
- Test count.
- Result.
- Relevant source revision.

The current evidence confirms the passing test count but does not yet provide a revision-bound evidence package.

### EG-05 — Residual Risk Assessment

Expand the initial residual risk register with:

- Likelihood and impact.
- Existing mitigation effectiveness.
- Risk owner.
- Treatment recommendation.
- Acceptance authority.
- Review date.

Do not mark a risk accepted without an independently documented authorization decision.

## 18. Assurance Statement

Project 8 implements a synthetic AI supply-chain security architecture with automated tests across inventory validation, artifact integrity, provenance, vulnerability assessment, release policy, trusted release registration, governance authorization, deployment, and rollback.

The recorded regression baseline is 242 passing tests.

The reviewed evidence supports the existence of implemented security controls and successful execution of the identified automated test suite.

However, the laboratory does not demonstrate:

- Production cloud deployment.
- Independently authenticated enterprise identities.
- Production signing-key custody.
- Durable trust and audit storage.
- Crash-atomic release transactions.
- Concurrency-safe deployment.
- Complete vulnerability intelligence.
- Comprehensive adversarial coverage.
- Regulatory certification or organizational compliance.

**Overall assessment:** Implemented and regression-tested synthetic security laboratory, with assertion-level traceability review and additional architecture evidence remaining.

---

**Document status:** Initial security-control traceability baseline.

**Regression result:** 242/242 tests passing.

**Production readiness:** Not claimed.

**Residual risk acceptance:** Not established by this document.