# Project 8 — AI Supply Chain and Secure Deployment

## System Architecture and Trust Boundaries

**Document status:** Implemented local security laboratory — regression validated  
**Project:** AI Supply Chain and Secure Deployment  
**Scope:** Synthetic AI component inventory, artifact integrity, provenance, vulnerability assessment, release policy, governance, controlled deployment, and rollback  
**Environment:** Local, offline, synthetic Python testbed  
**Regression baseline:** 242 automated tests passing

---

## 1. Purpose

This document describes the implemented reference security architecture for Project 8.

The laboratory evaluates AI supply-chain components and enforces security requirements before permitting simulated deployment or rollback.

The architecture demonstrates how organizations can establish component transparency, verify artifact integrity, assess provenance and vulnerability evidence, enforce release policies, authorize risk decisions, and preserve traceable security outcomes.

The implementation prioritizes:

- AI and software component transparency.
- Artifact integrity and trusted reference verification.
- Provenance validation.
- Vulnerability assessment and policy enforcement.
- Explicit release authorization.
- Separation of technical evaluation and governance approval.
- Machine-verifiable, narrowly scoped risk acceptance.
- Controlled deployment and independently authorized rollback.
- Deterministic security decisions and traceable audit evidence.

All components, identities, releases, and artifacts used in the laboratory are synthetic.

No production cloud infrastructure or enterprise identity service is deployed.

## 2. Security Objectives

| ID | Objective | Implementation |
|---|---|---|
| P8-SO01 | Component identification | JSON Schema and dependency-graph validation |
| P8-SO02 | Integrity verification | Local artifact digest verification |
| P8-SO03 | Provenance assurance | Dedicated provenance verification module |
| P8-SO04 | Vulnerability assessment | Structured finding assessment |
| P8-SO05 | Policy enforcement | Component and aggregate release security gates |
| P8-SO06 | Authorization | Release-bound governance decision engine |
| P8-SO07 | Rollback | Verified, separately authorized rollback |
| P8-SO08 | Auditability | Deterministic decision evidence and chained in-memory audit records |
| P8-SO09 | Governance | Risk ownership, acceptance validation, and separation-of-duties controls |

These objectives are implemented within the synthetic laboratory's defined scope.

Implementation does not imply production readiness or comprehensive assurance against all attack classes.

## 3. System Components

### 3.1 AI Component Inventory

**Implementation:** `src/inventory/validator.py`  
**Registration schema:** `policies/component-inventory.schema.json`

The inventory supports four component classes:

- AI models.
- Software packages.
- Container images.
- Datasets.

The registration schema uses JSON Schema Draft 2020-12 and schema version `1.0.0`.

It enforces required fields, supported component types, identifier syntax, SHA-256 digest format, enumerated values, and rejection of unexpected properties.

The Python validator additionally enforces:

- Unique component identifiers.
- Existing dependency references.
- No direct self-dependencies.
- No dependency cycles.
- Defensive copying of accepted records.

Dependency-cycle detection uses iterative depth-first traversal.

Initial registration requires:

| Security state | Required value |
|---|---|
| Inventory status | `unverified` |
| Provenance verification | `unverified` |
| License review | `unreviewed` |
| Risk acceptance | `not_assessed` |

A valid inventory record establishes registration eligibility only.

It does not establish artifact trust, authenticated provenance, vulnerability clearance, risk acceptance, or deployment authorization.

### 3.2 Artifact Integrity Verification

**Implementation:** `src/integrity/verifier.py`

The integrity subsystem evaluates local artifact bytes against expected cryptographic digests.

Artifact digest declarations supplied by untrusted inventory records are not independently authoritative.

Release authorization relies on separately established trusted release references and subsequent artifact verification.

The architecture distinguishes:

1. A declared artifact digest.
2. A calculated artifact digest.
3. A trusted release-bound digest reference.

A digest match demonstrates consistency between the evaluated bytes and the reference. It does not establish that an artifact is free from malicious functionality.

The deployment controller verifies artifact digests and performs additional verification during controlled release transitions.

### 3.3 Provenance Verification

**Implementation:** `src/provenance/verifier.py`

The provenance subsystem evaluates artifact-origin evidence separately from inventory registration.

The trust model distinguishes declared provenance metadata from evidence accepted under the laboratory's verification policy.

Self-declared builder identities, source revisions, and attestation references are not automatically authenticated.

The synthetic environment does not establish production-grade builder identity, external key custody, or independent third-party provenance assurance.

### 3.4 Vulnerability Assessment

**Implementation:** `src/scanning/assessor.py`

The vulnerability assessment subsystem evaluates structured findings associated with supply-chain components.

Its output provides security evidence for release-policy decisions.

Vulnerability assessment and release authorization remain separate functions.

The architecture must not interpret a missing finding, incomplete scan, or unsupported assessment as proof that an artifact is secure.

The release policy includes explicit handling of incomplete scanning and coverage evidence.

### 3.5 Release Security Policy

**Implementation:** `src/policy/release_gate.py`

The release gate evaluates component-level security evidence and produces an aggregate technical decision.

Supported decisions are:

| Decision | Meaning |
|---|---|
| `ELIGIBLE` | The evaluated technical requirements permit progression to governance authorization |
| `REVIEW` | Identified risks require explicit authorized disposition |
| `BLOCKED` | A mandatory security condition prevents release authorization |

A technically eligible release is not automatically authorized for deployment.

A `REVIEW` result requires an explicit governance decision covering the relevant risks.

A `BLOCKED` result cannot be converted into an authorized deployment through ordinary risk acceptance.

The technical result contains component-level decisions, reasons, evaluated component counts, and applicable review risks.

Review risks are identified by component and risk identifier.

The governance layer verifies consistency between component results and the aggregate technical decision.

### 3.6 Trusted Release Registry

**Implementation:** `src/trust/registry.py`

The trusted release registry establishes the synthetic release authority used by the deployment controller.

Registered release identity is associated with approved manifest and component artifact digests.

The laboratory models trust using HMAC-based authentication.

This mechanism demonstrates release-reference authentication under an assumed protected-key boundary.

It does not implement an enterprise signing infrastructure, hardware-backed key custody, or an external trust service.

Registry state and trust authority are local to the laboratory.

A caller-supplied release identifier or digest does not independently establish trusted release status.

### 3.7 Governance Authorization

**Implementation:** `src/policy/governance.py`

The governance engine evaluates authorization requests against technical release results.

It enforces consistency of the evaluated component set, aggregate decision, and review-risk identifiers.

Governance authorization is bound to the applicable:

- Release identifier.
- Manifest digest.
- Requested operation.
- Technical release evaluation.
- Identified review risks.
- Authorized risk-owner context.
- Acceptance validity period, where applicable.

The engine validates risk acceptance rather than treating an unverified acceptance claim as sufficient.

Active acceptance must satisfy the applicable ownership, authorization, scope, justification, and expiration requirements.

Inactive acceptance must conform to the defined non-acceptance structure.

The implementation includes separation-of-duties checks and deterministic decision digests.

Identity and authority are synthetic laboratory constructs. They are not backed by production authentication or organizational identity governance.

### 3.8 Controlled Deployment and Rollback

**Implementation:** `src/deployment/controller.py`

The controller coordinates trusted release verification, technical policy evaluation, governance authorization, artifact verification, and simulated deployment state changes.

Deployment requires a registered trusted release and successful evaluation of the applicable technical and governance requirements.

The controller verifies artifact identity and maintains local release snapshots.

A successful deployment updates the active release and appends an audit record.

Rollback is an explicit operation requiring fresh authorization.

The rollback path:

1. Identifies the requested recovery release.
2. Verifies its registered trust context.
3. Validates the stored recovery artifacts and applicable path restrictions.
4. Reevaluates technical security requirements.
5. Evaluates a new governance request for the rollback operation.
6. Rechecks the recovery snapshot before changing active release state.
7. Updates the active release and audit history only after successful authorization.

Expired risk acceptance cannot authorize rollback.

The controller rejects symlinked release directories and snapshot files within its implemented path-safety checks.

Rollback is not an automatic incident-recovery service.

### 3.9 Audit and Decision Evidence

The laboratory generates deterministic governance decision digests and maintains chained audit records for controlled release transitions.

Audit records provide traceability within the running synthetic environment.

The audit history is held in memory.

It is not an externally anchored, independently immutable, or durable enterprise audit system.

## 4. Implemented Reference Data Flow

### 4.1 Component Registration

1. Receive synthetic component records.
2. Validate each record against the registration schema.
3. Reject malformed records and unauthorized initial security states.
4. Reject duplicate component identities.
5. Validate dependency references and graph acyclicity.
6. Return a defensively copied inventory.

Registration does not authorize deployment.

### 4.2 Release Evaluation

1. Identify the release candidate and its component set.
2. Establish the applicable trusted release references.
3. Evaluate artifact integrity and provenance evidence.
4. Assess vulnerability findings and evidence completeness.
5. Evaluate component-level security policy.
6. Aggregate component decisions and review risks.
7. Validate the technical result's consistency.
8. Evaluate the applicable governance authorization.
9. Reject blocked, inconsistent, unauthorized, or expired decisions.

Technical eligibility and organizational authorization remain separate decisions.

### 4.3 Simulated Deployment

1. Validate the requested release against the trusted registry.
2. Verify release and component artifact identities.
3. Perform the required technical and governance evaluations.
4. Stage and verify release artifacts.
5. Commit the permitted simulated active-release transition.
6. Append the corresponding audit record.

The controller must not activate a release that fails the required security checks.

### 4.4 Simulated Rollback

1. Receive an explicit rollback request.
2. Identify the target recovery release.
3. Validate registered trust and recovery snapshot integrity.
4. Perform fresh technical evaluation.
5. Validate a new rollback-specific governance request.
6. Reject expired or otherwise invalid risk acceptance.
7. Reverify the snapshot.
8. Transition to the authorized recovery release.
9. Append the rollback audit record.

A previous deployment approval does not automatically authorize rollback.

## 5. Trust Boundaries

### TB-01 — External Component to Local Inventory

**Untrusted inputs:** Component manifests, declared origins, metadata, and dependency references.

**Implemented controls:** Strict JSON Schema validation, registration-state restrictions, identifier uniqueness, dependency validation, and defensive copying.

**Primary threats:** Component spoofing, malformed metadata, dependency substitution, and unauthorized verification-state elevation.

### TB-02 — Artifact to Integrity Verifier

**Untrusted inputs:** Artifact bytes, caller-provided paths, and declared digests.

**Implemented controls:** Cryptographic digest verification, trusted release references, and artifact revalidation during controlled release transitions.

**Primary threats:** Artifact tampering, digest substitution, and artifact replacement between checks.

**Residual limitation:** The laboratory does not provide production-grade atomic filesystem transactions or concurrency isolation.

### TB-03 — Provenance Evidence to Trust Decision

**Untrusted inputs:** Claimed builder identities, source revisions, and provenance metadata.

**Implemented component:** Dedicated provenance verifier.

**Required assurance distinction:** Accepted laboratory provenance evidence must not be represented as independently authenticated production provenance.

**Primary threats:** Forged provenance, source substitution, and fabricated build claims.

### TB-04 — Vulnerability Evidence to Policy Decision

**Lower-assurance inputs:** Synthetic scan findings, assessment completeness, and vulnerability metadata.

**Implemented controls:** Structured vulnerability assessment and technical release-policy evaluation.

**Primary threats:** Suppressed findings, incomplete coverage, fabricated clean results, and unauthorized exception handling.

### TB-05 — Technical Evaluation to Governance Authorization

**Lower authority:** Technical eligibility and review recommendations.

**Higher authority:** Validated governance authorization.

**Implemented controls:** Aggregate consistency checks, component-bound review risks, risk-owner authorization, expiration enforcement, and separation-of-duties validation.

**Primary threats:** Forged acceptance, risk substitution, inconsistent technical evidence, and unauthorized release approval.

### TB-06 — Authorized Release to Deployment State

**Untrusted inputs:** Deployment requests and mutable artifact references.

**Implemented controls:** Trusted release registration, manifest and component digest verification, technical evaluation, governance authorization, and controlled state transitions.

**Primary threats:** Unauthorized deployment, artifact substitution, and release-reference manipulation.

### TB-07 — Recovery Request to Rollback State

**Untrusted inputs:** Recovery requests, stored artifact paths, and rollback authorization claims.

**Implemented controls:** Trusted recovery release verification, snapshot integrity checks, path-safety restrictions, fresh technical evaluation, and new rollback-specific governance authorization.

**Primary threats:** Malicious rollback, compromised recovery artifacts, expired approval reuse, and unauthorized recovery-state changes.

### TB-08 — Operational Evidence to Governance Records

**Lower-assurance inputs:** Synthetic scanner outputs, operator claims, and component evidence.

**Implemented controls:** Governance consistency validation, deterministic decision digests, and chained in-memory release audit records.

**Primary threats:** Evidence substitution, false authorization claims, and audit-history manipulation.

**Residual limitation:** In-memory audit chaining does not provide independent, durable, tamper-resistant evidence retention.

## 6. Security Invariants

The implementation is designed to enforce the following invariants within the laboratory's tested scope.

| ID | Security invariant |
|---|---|
| INV-01 | Failed required integrity verification cannot authorize deployment |
| INV-02 | A caller-controlled digest cannot independently establish release trust |
| INV-03 | Inventory registration cannot establish authenticated provenance |
| INV-04 | A blocked technical release cannot silently become authorized |
| INV-05 | Governance authorization must match the evaluated release and manifest |
| INV-06 | Invalid or expired risk acceptance cannot authorize a release transition |
| INV-07 | A rejected deployment must not replace the active release |
| INV-08 | Rollback requires verified recovery artifacts and fresh authorization |
| INV-09 | Accepted review risks must match the applicable technical risk scope |
| INV-10 | Synthetic security controls must not be described as production guarantees |

The automated regression suite exercises these security boundaries through unit, integration, and adversarial tests.

The suite does not constitute formal verification of every possible state or adversarial interaction.

## 7. Governance and Accountability

The project models distinct security responsibilities.

| Role | Responsibility |
|---|---|
| Component owner | Maintains component identity and dependency declarations |
| Security reviewer | Evaluates findings and security requirements |
| Risk owner | Accepts specified residual risks within modeled authority |
| Release approver | Authorizes the applicable release action |
| Deployment operator | Requests permitted deployment or rollback transitions |
| Auditor | Reviews recorded evidence and decisions |

The governance engine enforces machine-verifiable authorization constraints within the synthetic identity model.

### 7.1 Risk Acceptance

Risk acceptance is not inferred from inventory metadata.

A valid active acceptance must be tied to the applicable release and manifest, identify the accepted risks, satisfy authorization requirements, include justification, and remain within its validity period.

The governance engine rejects inconsistent, unauthorized, improperly scoped, or expired acceptance.

### 7.2 Separation of Duties

The implementation models separation between the requesting operator and the authority responsible for applicable governance decisions.

This is a synthetic authorization control, not integration with an enterprise identity provider.

### 7.3 Decision Traceability

Governance decisions produce deterministic evidence suitable for reproducible testing.

Deployment and rollback outcomes are represented in chained in-memory audit history.

### 7.4 Accountability Limitations

The laboratory does not independently authenticate real organizational users or prove that a named individual holds enterprise decision authority.

Production implementation would require trusted identity integration, protected approval records, durable audit retention, and operational governance procedures.

## 8. Standards and Framework Alignment

The architecture draws on the following standards and frameworks.

| Framework | Architectural relevance |
|---|---|
| NIST AI RMF 1.0 | AI supply-chain risk identification, governance, measurement, and risk treatment |
| ISO/IEC 42001:2023 | AI management-system accountability, risk ownership, documented decisions, and operational governance |
| NIST SSDF | Secure development and software supply-chain assurance |
| SLSA | Artifact provenance and build-integrity concepts |
| OWASP | Software and AI supply-chain threats and defensive design |
| MITRE ATLAS | Adversarial AI threat scenarios |
| STRIDE | Structured threat analysis across trust boundaries |

These are architectural alignments.

They do not establish certification, compliance, or satisfaction of every framework requirement.

Mappings must distinguish implemented controls, tested controls, conceptual alignment, and residual limitations.

## 9. Adversarial Validation

The project includes automated tests covering inventory, integrity, provenance, vulnerability assessment, release policy, governance, trusted release registration, deployment, and rollback.

### 9.1 Representative Security Scenarios

| Scenario | Security expectation |
|---|---|
| Invalid inventory record | Reject registration |
| Duplicate component identity | Reject inventory |
| Missing or cyclic dependency | Reject inventory |
| Unauthorized initial verification state | Reject registration |
| Modified artifact | Reject when required integrity verification fails |
| Inconsistent component or aggregate decision | Reject governance evaluation |
| Review-risk substitution | Reject governance evaluation |
| Invalid risk acceptance | Reject authorization |
| Expired risk acceptance | Reject authorization |
| Unauthorized rollback | Preserve existing active release |
| Invalid recovery snapshot | Reject rollback |
| Invalid release trust context | Reject release transition |

### 9.2 Governance Consistency Regression

The dedicated governance-consistency tests exercise:

- Evaluated-component count mismatches.
- Duplicate component identities.
- Inconsistent aggregate decisions.
- Inconsistent aggregate review risks.
- Cross-component risk substitutions.
- Malformed inactive acceptance.
- Valid technical and governance decision structures.

### 9.3 Deployment Hardening Regression

Deployment hardening tests include expired risk-acceptance rejection and preservation of active-release and audit state following rejected rollback operations.

### 9.4 Regression Baseline

**Verified result:** 242 automated tests passing.

**Command:**

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

The passing baseline demonstrates successful execution of the implemented test suite at the recorded development checkpoint.

It does not prove complete resistance to supply-chain compromise or production operational resilience.

## 10. Implementation Boundaries

### 10.1 Implemented Environment

The laboratory uses:

- Python security-control modules.
- JSON Schema Draft 2020-12.
- Synthetic component manifests and artifacts.
- Local filesystem artifact handling.
- Synthetic vulnerability and provenance evidence.
- HMAC-based synthetic release trust.
- Machine-verifiable governance requests.
- Simulated deployment and rollback state.
- Automated unit, integration, and adversarial regression tests.

### 10.2 Explicit Limitations

The implementation does not provide:

- Production AWS, Azure, or other cloud deployment.
- Enterprise identity authentication.
- Production signing infrastructure or externally verified key custody.
- Hardware-backed trust authority.
- Durable external release registry or audit storage.
- Crash-atomic deployment transactions.
- Concurrency-safe release-state transitions.
- Production incident-response orchestration.
- Independently verified organizational compliance.

Trust key custody is assumed to be managed outside the synthetic laboratory.

Release registry and audit state are maintained in memory.

Filesystem verification reduces selected artifact-substitution risks but does not establish transactional atomicity against concurrent modification.

## 11. Deliverables and Evidence

### 11.1 Implemented Security Modules

| Component | Implementation |
|---|---|
| Inventory validation | `src/inventory/validator.py` |
| Inventory registration schema | `policies/component-inventory.schema.json` |
| Artifact integrity | `src/integrity/verifier.py` |
| Provenance verification | `src/provenance/verifier.py` |
| Vulnerability assessment | `src/scanning/assessor.py` |
| Release policy | `src/policy/release_gate.py` |
| Governance authorization | `src/policy/governance.py` |
| Trusted release registry | `src/trust/registry.py` |
| Controlled deployment and rollback | `src/deployment/controller.py` |

### 11.2 Automated Evidence

The test suite contains dedicated modules for:

- Inventory schema validation.
- Inventory dependency and registration validation.
- Artifact integrity.
- Provenance verification.
- Vulnerability assessment.
- Release policy evaluation.
- Governance validation and consistency.
- Risk acceptance integration.
- Trusted release registration.
- Deployment trust enforcement.
- Deployment controller behavior.
- Deployment and rollback hardening.

The validated regression baseline is 242 passing tests.

### 11.3 Documentation Reconciliation

The architecture and inventory specification are being reconciled with the implemented controls.

Additional documentation, diagrams, framework mappings, evidence records, and residual-risk assessments must be identified and completed separately.

Their existence must not be inferred solely from the implementation or passing tests.

## 12. Acceptance Criteria

The following criteria define the security architecture's intended completion standard.

| ID | Criterion | Current assessment |
|---|---|---|
| AC-01 | Support four component classes | Implemented in registration schema |
| AC-02 | Reject malformed and inconsistent inventories | Implemented in schema and validator |
| AC-03 | Verify artifact integrity against trusted references | Implemented within laboratory scope |
| AC-04 | Evaluate provenance evidence under defined trust policy | Dedicated implementation and tests |
| AC-05 | Evaluate vulnerability findings and release policy | Dedicated implementation and tests |
| AC-06 | Prevent blocked releases from obtaining ordinary authorization | Implemented governance boundary |
| AC-07 | Bind authorization to release and manifest identity | Implemented |
| AC-08 | Enforce explicit, scoped risk acceptance | Implemented |
| AC-09 | Require fresh authorization for rollback | Implemented |
| AC-10 | Reject invalid recovery artifacts | Implemented |
| AC-11 | Preserve traceable release outcomes | Chained in-memory audit records |
| AC-12 | Maintain reproducible security regression evidence | 242 passing tests |
| AC-13 | Document threat mappings and residual risks | Documentation reconciliation ongoing |
| AC-14 | Distinguish synthetic validation from production assurance | Explicitly documented |

Project completion requires both validated implementation and documentation that accurately represents its limitations.

---

**Architecture status:** Implemented synthetic security laboratory with 242 passing regression tests at the recorded checkpoint.

**Production readiness:** Not claimed.

**Security assurance:** Limited to the implemented controls, synthetic trust assumptions, and validated test scenarios.