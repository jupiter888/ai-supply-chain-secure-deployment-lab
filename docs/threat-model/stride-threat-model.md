# Project 8 — STRIDE Threat Model

**Project:** AI Supply Chain and Secure Deployment Lab  
**Document status:** Architecture-level threat assessment  
**Environment:** Local, offline, synthetic security laboratory  
**Methodology:** STRIDE  
**Validation baseline:** 242 automated tests passing  
**Scope:** Component inventory, artifact integrity, provenance, vulnerability assessment, trusted release registration, governance, deployment, rollback, and audit evidence

---

## 1. Executive Summary

This threat model evaluates security risks across the Project 8 AI supply-chain and controlled deployment architecture.

The primary concern is the promotion of untrusted component information, artifact references, security findings, or governance assertions into higher-trust release decisions.

The architecture separates component registration, technical verification, trusted release identity, governance authorization, and deployment state transitions.

STRIDE is used to identify threats involving:

- Spoofing.
- Tampering.
- Repudiation.
- Information disclosure.
- Denial of service.
- Elevation of privilege.

The assessment identifies implemented mitigations, supporting automated tests, and residual risks.

The model does not establish production security assurance.

## 2. System Scope

### 2.1 Protected Assets

| Asset ID | Protected asset | Security requirement |
|---|---|---|
| A-01 | Component inventory | Valid identity and dependency relationships |
| A-02 | Artifact bytes | Integrity relative to trusted references |
| A-03 | Provenance evidence | Authenticity within the modeled trust policy |
| A-04 | Vulnerability evidence | Accurate policy-relevant assessment |
| A-05 | Release policy results | Consistent technical decisions |
| A-06 | Trusted release registry | Authentic release and digest bindings |
| A-07 | Governance authorization | Valid authority, scope, and expiration |
| A-08 | Active release state | Authorized state transitions only |
| A-09 | Recovery snapshots | Verified recovery artifacts |
| A-10 | Audit evidence | Traceable and consistent release history |

### 2.2 Threat Actors

The laboratory considers attackers who may control or manipulate:

- Component registration inputs.
- Declared artifact metadata.
- Untrusted artifact bytes.
- Provenance claims.
- Synthetic vulnerability evidence.
- Release requests.
- Governance requests.
- Risk acceptance claims.
- Recovery requests.
- Selected filesystem objects.

These capabilities are evaluated within the boundaries of the implemented tests.

The model does not assume that an attacker controls every component of the synthetic trust authority.

### 2.3 Trust Assumptions

The architecture assumes:

1. The trusted release authority's HMAC key is protected.
2. Trusted registry configuration is established independently of attacker-controlled release claims.
3. The Python execution environment is not already compromised.
4. The local operating system and relevant cryptographic primitives operate as expected.
5. The modeled governance authority represents valid synthetic organizational policy.
6. Test fixtures represent controlled, synthetic security evidence.

Violating these assumptions may invalidate the laboratory's security guarantees.

## 3. STRIDE Classification

| Category | Security concern |
|---|---|
| S — Spoofing | Impersonation of components, producers, issuers, or decision-makers |
| T — Tampering | Unauthorized modification of artifacts, evidence, or release state |
| R — Repudiation | Disputing actions because evidence is missing or insufficiently protected |
| I — Information Disclosure | Unauthorized exposure of artifacts, metadata, or sensitive records |
| D — Denial of Service | Preventing evaluation, deployment, or recovery |
| E — Elevation of Privilege | Obtaining unauthorized verification, approval, or deployment authority |

STRIDE categories describe potential threat mechanisms.

Not every category has a dedicated implemented mitigation or automated test.

## 4. Trust Boundary Inventory

| Boundary | Source | Destination | Primary security concern |
|---|---|---|---|
| TB-01 | External component records | Inventory validator | Untrusted registration metadata |
| TB-02 | Artifact bytes and digest claims | Integrity verifier | Artifact and reference integrity |
| TB-03 | Provenance assertions | Provenance verifier | Origin and producer authenticity |
| TB-04 | Vulnerability findings | Security policy | Evidence completeness and integrity |
| TB-05 | Technical decisions | Governance engine | Authorization and risk acceptance |
| TB-06 | Release request | Deployment controller | Authorized release activation |
| TB-07 | Recovery request | Rollback controller | Authorized restoration |
| TB-08 | Operational decisions | Audit evidence | Traceability and integrity |

## 5. TB-01 — Component Inventory Threats

### P8-T01 — Component Identity Spoofing

**STRIDE:** Spoofing  
**Asset:** A-01  
**Boundary:** TB-01

**Attack scenario:** An attacker submits records with duplicate component identifiers or misleading component metadata.

**Potential impact:** Component substitution or ambiguity in dependency and release evaluation.

**Implemented mitigation:**

- Strict registration schema.
- Duplicate identifier rejection.
- Component identifier constraints.
- Dependency validation.

**Evidence:**

- `test_inventory_validator.py::test_003_duplicate_component_id`
- `test_inventory_schema.py::test_012_invalid_component_identifier`

**Residual risk:** The inventory validates identity structure but does not independently authenticate an external component publisher.

### P8-T02 — Unauthorized Verification-State Elevation

**STRIDE:** Elevation of Privilege  
**Asset:** A-01  
**Boundary:** TB-01

**Attack scenario:** A submitted manifest claims verified provenance, approved licensing, accepted risk, or verified inventory status.

**Potential impact:** Untrusted declarations could be mistaken for authorized security decisions.

**Implemented mitigation:**

The registration schema requires initial non-authoritative states.

**Evidence:**

- `test_inventory_schema.py::test_007_forged_provenance_verification`
- `test_inventory_schema.py::test_008_forged_license_approval`
- `test_inventory_schema.py::test_009_forged_risk_acceptance`
- `test_inventory_schema.py::test_010_forged_inventory_verification`

**Residual risk:** Trusted downstream state transitions require separate authority controls.

### P8-T03 — Dependency Graph Manipulation

**STRIDE:** Tampering  
**Asset:** A-01  
**Boundary:** TB-01

**Attack scenario:** A component references nonexistent dependencies or introduces dependency cycles.

**Potential impact:** Incorrect dependency evaluation, incomplete supply-chain analysis, or processing failures.

**Implemented mitigation:**

- Dependency existence checks.
- Self-dependency rejection.
- Directed-cycle detection.
- Iterative graph traversal.

**Evidence:**

- `test_inventory_validator.py::test_004_missing_dependency`
- `test_inventory_validator.py::test_005_direct_self_dependency`
- `test_inventory_validator.py::test_006_two_component_cycle`
- `test_inventory_validator.py::test_019_deep_acyclic_chain`

**Residual risk:** Graph validity does not establish that referenced components are trustworthy.

## 6. TB-02 — Artifact Integrity Threats

### P8-T04 — Artifact Modification

**STRIDE:** Tampering  
**Asset:** A-02  
**Boundary:** TB-02

**Attack scenario:** Artifact bytes are modified after their expected digest is recorded.

**Potential impact:** Deployment of an unauthorized or altered artifact.

**Implemented mitigation:**

- SHA-256 verification.
- Artifact-size checks.
- Integrity-based release rejection.

**Evidence:**

- `test_artifact_integrity.py::test_004_modified_artifact_rejected`
- `test_artifact_integrity.py::test_005_same_size_tampering_rejected`
- `test_release_gate.py::test_002_modified_artifact_blocked`

**Residual risk:** Digest verification cannot determine whether an otherwise authentic artifact contains malicious functionality.

### P8-T05 — Digest Reference Substitution

**STRIDE:** Tampering  
**Asset:** A-02, A-06  
**Boundary:** TB-02

**Attack scenario:** An attacker replaces an artifact and supplies a matching attacker-controlled digest.

**Potential impact:** Unauthorized artifacts appear valid when compared only against attacker-supplied metadata.

**Implemented mitigation:**

- Separation of declared and trusted digests.
- Trusted release registration.
- Release-bound artifact verification.

**Evidence:**

- `test_artifact_integrity.py::test_017_untrusted_digest_not_used_as_reference`
- `test_deployment_trust_enforcement.py::test_002_matching_attacker_digest_rejected`
- `test_trust_registry.py::test_004_artifact_digest_substitution_rejected`

**Residual risk:** Compromise of the trusted reference authority would undermine this boundary.

### P8-T06 — Artifact Processing Exhaustion

**STRIDE:** Denial of Service  
**Asset:** A-02  
**Boundary:** TB-02

**Attack scenario:** An attacker supplies excessively large or repeatedly changing artifacts to consume verification resources.

**Potential impact:** Verification delays, resource exhaustion, or unavailable release processing.

**Implemented mitigation:** No comprehensive resource-quota or rate-limiting control has been established by the reviewed evidence.

**Evidence status:** Dedicated adversarial validation not established.

**Residual risk:** Resource-exhaustion resistance remains outside the demonstrated assurance boundary.

## 7. TB-03 — Provenance Threats

### P8-T07 — Forged Provenance Attestation

**STRIDE:** Spoofing, Tampering  
**Asset:** A-03  
**Boundary:** TB-03

**Attack scenario:** An attacker submits a fabricated attestation or modifies signed provenance claims.

**Potential impact:** Unauthorized artifacts appear to originate from trusted builders or sources.

**Implemented mitigation:**

- Synthetic HMAC verification.
- Trusted signing-key selection.
- Subject and artifact digest binding.
- Builder and source policy validation.

**Evidence:**

- `test_provenance_verifier.py::test_006_forged_signature`
- `test_provenance_verifier.py::test_007_unknown_key`
- `test_provenance_verifier.py::test_010_wrong_artifact_digest`
- `test_provenance_verifier.py::test_012_unauthorized_builder_with_valid_hmac`

**Residual risk:** The laboratory assumes protected signing-key custody and does not establish production builder authentication.

### P8-T08 — Authorized Signature with Unauthorized Subject

**STRIDE:** Spoofing  
**Asset:** A-03  
**Boundary:** TB-03

**Attack scenario:** An otherwise valid attestation is presented for an unauthorized artifact or subject.

**Potential impact:** Provenance evidence is reused outside its intended scope.

**Implemented mitigation:** Independent subject and digest policy checks.

**Evidence:**

- `test_provenance_verifier.py::test_021_valid_hmac_cannot_override_digest_policy`
- `test_provenance_verifier.py::test_022_valid_hmac_cannot_override_subject_policy`

**Residual risk:** External trust-policy configuration and authority management are not production-hardened.

## 8. TB-04 — Vulnerability Evidence Threats

### P8-T09 — Incomplete Vulnerability Evidence

**STRIDE:** Tampering  
**Asset:** A-04, A-05  
**Boundary:** TB-04

**Attack scenario:** A release candidate is submitted with incomplete scanning or missing component coverage.

**Potential impact:** Vulnerable components proceed without adequate assessment.

**Implemented mitigation:**

- Scan-completeness evaluation.
- Component coverage validation.
- Explicit review requirements.
- Release-policy enforcement.

**Evidence:**

- `test_vulnerability_assessor.py::test_008_incomplete_scan_requires_review`
- `test_vulnerability_assessor.py::test_010_missing_dependency_coverage`
- `test_release_gate.py::test_009_incomplete_scan_requires_review`

**Residual risk:** The laboratory uses synthetic findings and does not demonstrate authenticated production scanner integration.

### P8-T10 — Critical Vulnerability Policy Bypass

**STRIDE:** Elevation of Privilege  
**Asset:** A-05  
**Boundary:** TB-04

**Attack scenario:** An attacker attempts to obtain release eligibility despite a critical vulnerability.

**Potential impact:** Deployment of a release that violates mandatory security policy.

**Implemented mitigation:**

- Critical vulnerability blocking.
- Block precedence over review.
- Governance rejection of blocked releases.

**Evidence:**

- `test_vulnerability_assessor.py::test_002_critical_affected_denies`
- `test_release_gate.py::test_007_critical_vulnerability_blocked`
- `test_governance.py::test_038_blocked_gate_cannot_be_overridden`

**Residual risk:** Policy effectiveness depends on the completeness and correctness of supplied vulnerability evidence.

## 9. TB-05 — Governance Authorization Threats

### P8-T11 — Forged Release Approval

**STRIDE:** Spoofing, Elevation of Privilege  
**Asset:** A-07  
**Boundary:** TB-05

**Attack scenario:** An unauthorized actor supplies a release approval or attempts self-approval.

**Potential impact:** Unauthorized deployment.

**Implemented mitigation:**

- Authorized approver validation.
- Separation-of-duties checks.
- Release and manifest binding.

**Evidence:**

- `test_governance.py::test_002_unauthorized_approver`
- `test_governance.py::test_003_self_approval_rejected`
- `test_governance.py::test_004_wrong_release_id`
- `test_governance.py::test_005_wrong_manifest_digest`

**Residual risk:** Identity assertions are synthetic and are not independently authenticated through an enterprise identity provider.

### P8-T12 — Risk Acceptance Substitution

**STRIDE:** Tampering, Elevation of Privilege  
**Asset:** A-07  
**Boundary:** TB-05

**Attack scenario:** An attacker reuses acceptance across releases, manifests, components, or unrelated findings.

**Potential impact:** Risks are accepted outside the authority and scope of the original decision.

**Implemented mitigation:**

- Exact release and manifest binding.
- Component-specific risk identifiers.
- Exact accepted-risk set validation.
- Duplicate and unrelated risk rejection.

**Evidence:**

- `test_risk_acceptance_integration.py::test_001_cross_release_acceptance_blocked`
- `test_risk_acceptance_integration.py::test_002_cross_manifest_acceptance_blocked`
- `test_risk_acceptance_integration.py::test_003_cross_component_acceptance_blocked`
- `test_risk_acceptance_integration.py::test_004_finding_substitution_blocked`
- `test_risk_acceptance_integration.py::test_007_duplicate_risk_acceptance_blocked`

**Residual risk:** Production risk acceptance requires independently authenticated decision-makers and durable approval evidence.

### P8-T13 — Inconsistent Technical Evidence

**STRIDE:** Tampering  
**Asset:** A-05, A-07  
**Boundary:** TB-05

**Attack scenario:** A governance request is evaluated against contradictory component decisions, aggregate results, or review risks.

**Potential impact:** Incorrect authorization based on internally inconsistent technical evidence.

**Implemented mitigation:**

- Component-count consistency.
- Duplicate component rejection.
- Aggregate decision validation.
- Exact aggregate review-risk consistency.

**Evidence:**

- `test_governance_consistency.py::test_002_component_count_mismatch_rejected`
- `test_governance_consistency.py::test_004_duplicate_components_rejected`
- `test_governance_consistency.py::test_007_blocked_component_must_block_release`
- `test_governance_consistency.py::test_011_cross_component_risk_substitution`

**Residual risk:** Consistency checks do not independently prove the authenticity of every upstream evidence source.

## 10. TB-06 — Deployment Threats

### P8-T14 — Untrusted Release Activation

**STRIDE:** Elevation of Privilege  
**Asset:** A-06, A-08  
**Boundary:** TB-06

**Attack scenario:** An attacker attempts to deploy an unregistered release or substitutes release identity information.

**Potential impact:** Unauthorized active-release state.

**Implemented mitigation:**

- Trusted release registry.
- Manifest and artifact digest binding.
- Technical release evaluation.
- Governance authorization.

**Evidence:**

- `test_deployment_trust_enforcement.py::test_001_unregistered_release_rejected`
- `test_deployment_trust_enforcement.py::test_003_registered_manifest_mismatch_rejected`
- `test_deployment_controller.py::test_006_manifest_substitution_blocked`

**Residual risk:** The trusted registry is synthetic and maintained in memory.

### P8-T15 — Filesystem Reference Manipulation

**STRIDE:** Tampering  
**Asset:** A-08, A-09  
**Boundary:** TB-06

**Attack scenario:** An attacker attempts to redirect artifact handling through symbolic links.

**Potential impact:** Unauthorized artifact access or release-state manipulation.

**Implemented mitigation:**

- Selected symlink checks.
- Snapshot verification.
- Controlled artifact handling.

**Evidence:**

- `test_deployment_hardening.py::test_001_reject_symlinked_release_directory`
- `test_deployment_hardening.py::test_002_reject_symlinked_snapshot_file`

**Residual risk:** The implementation does not establish comprehensive protection against concurrent filesystem modification or all path-race conditions.

## 11. TB-07 — Rollback Threats

### P8-T16 — Unauthorized Recovery Transition

**STRIDE:** Elevation of Privilege  
**Asset:** A-08, A-09  
**Boundary:** TB-07

**Attack scenario:** An attacker attempts rollback without a new valid authorization.

**Potential impact:** Restoration of an unauthorized or outdated release.

**Implemented mitigation:**

- Explicit rollback request.
- Fresh technical evaluation.
- New rollback-specific governance authorization.
- Trusted recovery-release verification.

**Evidence:**

- `test_deployment_hardening.py::test_003_rollback_requires_fresh_authorization`
- `test_deployment_controller.py::test_011_successful_rollback`

**Residual risk:** Rollback is a simulated state transition rather than a production recovery operation.

### P8-T17 — Tampered Recovery Snapshot

**STRIDE:** Tampering  
**Asset:** A-09  
**Boundary:** TB-07

**Attack scenario:** An attacker modifies a stored recovery artifact before rollback.

**Potential impact:** Restoration of compromised artifact bytes.

**Implemented mitigation:**

- Recovery snapshot verification.
- Trusted release digest comparison.
- Rejection before active-release modification.

**Evidence:**

- `test_deployment_controller.py::test_012_tampered_rollback_snapshot_blocked`
- `test_deployment_controller.py::test_016_no_activation_after_rejection`

**Residual risk:** Snapshot verification does not establish crash-atomic recovery.

### P8-T18 — Expired Exception Reuse

**STRIDE:** Elevation of Privilege  
**Asset:** A-07, A-08  
**Boundary:** TB-07

**Attack scenario:** A previously valid risk acceptance is reused after expiration to authorize rollback.

**Potential impact:** Unauthorized recovery under obsolete governance authority.

**Implemented mitigation:**

- Fresh governance evaluation.
- Expiration enforcement.
- Rejected-transition state preservation.

**Evidence:**

- `test_deployment_hardening.py::test_004_expired_exception_not_implicitly_reusable`

**Residual risk:** Real-world approval revocation and identity lifecycle management are not implemented.

## 12. TB-08 — Audit and Evidence Threats

### P8-T19 — Governance Evidence Manipulation

**STRIDE:** Tampering, Repudiation  
**Asset:** A-07, A-10  
**Boundary:** TB-08

**Attack scenario:** An attacker changes governance decision details or attempts to substitute approval evidence.

**Potential impact:** Misrepresentation of the decision that authorized a release.

**Implemented mitigation:**

- Deterministic governance decision digests.
- Strict request validation.
- Release- and risk-bound authorization.

**Evidence:**

- `test_governance.py::test_024_record_digest_is_deterministic`
- `test_governance.py::test_025_changed_justification_changes_digest`

**Residual risk:** Decision digests alone do not authenticate the author or provide independently immutable evidence storage.

### P8-T20 — Audit History Loss or Modification

**STRIDE:** Repudiation, Tampering  
**Asset:** A-10  
**Boundary:** TB-08

**Attack scenario:** An attacker with sufficient local access modifies or removes in-memory audit history.

**Potential impact:** Loss of reliable release traceability.

**Implemented mitigation:**

- Chained audit digests.
- Deterministic audit-history construction.
- State-preservation checks on rejected transitions.

**Evidence:**

- `test_deployment_controller.py::test_015_audit_chain_changes_with_operations`
- `test_deployment_hardening.py::test_004_expired_exception_not_implicitly_reusable`

**Residual risk:** The audit mechanism is not durable, externally anchored, or protected against a fully privileged local attacker.

## 13. Cross-Cutting Threats

### P8-T21 — Sensitive Metadata Disclosure

**STRIDE:** Information Disclosure

**Attack scenario:** Component records, provenance metadata, governance decisions, or local artifacts expose sensitive information.

**Potential impact:** Disclosure of internal component information or sensitive records.

**Implemented mitigation:** The laboratory uses synthetic information and does not intentionally process production secrets or sensitive enterprise datasets.

**Evidence status:** No dedicated confidentiality enforcement test has been established from the supplied test inventory.

**Residual risk:** Production confidentiality controls, access restrictions, and data classification enforcement remain outside demonstrated scope.

### P8-T22 — Concurrent Release-State Manipulation

**STRIDE:** Tampering, Denial of Service

**Attack scenario:** Multiple concurrent operations interfere with artifact verification, active-release updates, or audit-state changes.

**Potential impact:** Inconsistent deployment state, interrupted transitions, or corrupted release history.

**Implemented mitigation:** Sequential local release evaluation and selected artifact revalidation.

**Evidence status:** No comprehensive concurrency or crash-atomicity validation established.

**Residual risk:** Production concurrency control and transactional recovery are not implemented.

## 14. Threat-to-Control Summary

| Threat | STRIDE | Boundary | Mitigation status |
|---|---|---|---|
| P8-T01 | S | TB-01 | Implemented and test identified |
| P8-T02 | E | TB-01 | Implemented and test identified |
| P8-T03 | T | TB-01 | Implemented and test identified |
| P8-T04 | T | TB-02 | Implemented and test identified |
| P8-T05 | T | TB-02 | Implemented and test identified |
| P8-T06 | D | TB-02 | Residual gap |
| P8-T07 | S, T | TB-03 | Implemented and test identified |
| P8-T08 | S | TB-03 | Implemented and test identified |
| P8-T09 | T | TB-04 | Implemented and test identified |
| P8-T10 | E | TB-04 | Implemented and test identified |
| P8-T11 | S, E | TB-05 | Implemented and test identified |
| P8-T12 | T, E | TB-05 | Implemented and test identified |
| P8-T13 | T | TB-05 | Implemented and test identified |
| P8-T14 | E | TB-06 | Implemented and test identified |
| P8-T15 | T | TB-06 | Implemented and test identified |
| P8-T16 | E | TB-07 | Implemented and test identified |
| P8-T17 | T | TB-07 | Implemented and test identified |
| P8-T18 | E | TB-07 | Implemented and test identified |
| P8-T19 | T, R | TB-08 | Implemented and test identified |
| P8-T20 | R, T | TB-08 | Partial mitigation |
| P8-T21 | I | Cross-cutting | Residual gap |
| P8-T22 | T, D | Cross-cutting | Residual gap |

A test-identified mitigation does not establish complete elimination of the associated threat.

## 15. Residual Risk Assessment

The principal residual risks are:

| Risk ID | Residual risk | Treatment recommendation |
|---|---|---|
| RR-01 | Synthetic identity impersonation | Integrate authenticated enterprise identities |
| RR-02 | Trust-authority key compromise | Protected key custody and rotation |
| RR-03 | In-memory trust registry | Durable, access-controlled storage |
| RR-04 | In-memory audit history | External tamper-evident retention |
| RR-05 | Concurrent artifact modification | Atomic artifact handling |
| RR-06 | Interrupted release transitions | Transactional deployment design |
| RR-07 | Incomplete vulnerability intelligence | Authenticated scanning and coverage monitoring |
| RR-08 | Compromised provenance authority | Protected signing and builder identity |
| RR-09 | Incomplete adversarial coverage | Broader security validation |
| RR-10 | Synthetic organizational governance | Enterprise authorization and accountable approval |

These risks are documented but not formally accepted.

Risk acceptance requires a separate authorized decision.

## 16. Security Validation and Evidence

The project contains 13 automated test modules covering:

- Component inventory.
- Artifact integrity.
- Provenance.
- Vulnerability assessment.
- Release policy.
- Trusted release registration.
- Governance.
- Risk acceptance.
- Deployment.
- Rollback.

**Recorded baseline:** 242 passing tests.

The test-function inventory provides named evidence references for the threat scenarios in this document.

The complete assertions for every mapped test have not yet been independently reviewed.

Accordingly, the evidence classification is:

**Implemented controls with identified, regression-passing tests; assertion-level review pending where not explicitly completed.**

## 17. Architectural Security Conclusions

The laboratory demonstrates a defense-in-depth approach to AI supply-chain release security.

Its strongest implemented architectural properties include:

1. Separation of untrusted component declarations from trusted security decisions.
2. Independent artifact integrity and provenance evaluation.
3. Explicit vulnerability and release-policy enforcement.
4. Trusted release-reference verification.
5. Machine-verifiable governance authorization.
6. Exact risk-acceptance scope and expiration enforcement.
7. Fresh authorization for rollback.
8. Rejection-path preservation of active-release state.
9. Traceable governance and deployment evidence.

The implementation remains subject to the documented limitations of synthetic identities, local trust assumptions, in-memory state, and non-transactional deployment behavior.

## 18. Recommended Next Steps

The remaining security architecture evidence should include:

1. Assertion-level review of representative adversarial tests.
2. Formal residual-risk assessment with likelihood, impact, and treatment decisions.
3. NIST AI RMF governance mapping.
4. ISO/IEC 42001 architectural control mapping.
5. MITRE ATLAS technique mapping where applicable.
6. Revision-bound regression evidence.
7. Final consistency review across architecture, threat model, and README.

---

**Threat-model status:** Initial STRIDE assessment completed.

**Threat scenarios:** 22 identified.

**Trust boundaries:** 8 modeled.

**Regression baseline:** 242/242 tests passing.

**Production readiness:** Not claimed.