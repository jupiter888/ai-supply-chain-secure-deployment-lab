# Project 8 — Residual Risk Register

**Project:** AI Supply Chain & Secure Deployment Security Lab  
**Document ID:** P8-GOV-RR-001  
**Status:** Initial architecture-level risk assessment  
**Environment:** Local, offline, synthetic security laboratory  
**Assessment methodology:** Qualitative likelihood and impact scoring  
**Technical validation baseline:** 242 automated tests passing

---

## 1. Executive Summary

This register documents the residual security risks associated with the AI Supply Chain & Secure Deployment Security Lab.

The project implements security controls covering component inventory, artifact integrity, provenance verification, vulnerability assessment, release policy, trusted release registration, governance authorization, deployment, rollback, and audit evidence.

However, the implementation operates within a synthetic laboratory environment.

The purpose of this assessment is to:

1. Identify risks remaining after implemented controls.
2. Distinguish laboratory risks from production deployment gaps.
3. Assign provisional likelihood and impact ratings.
4. Recommend risk treatment.
5. Define accountable ownership roles.
6. Identify evidence needed before production adoption.
7. Prevent architectural limitations from being misrepresented as accepted organizational risk.

No risk in this document has been formally accepted.

## 2. Assessment Scope

### 2.1 Laboratory Scope

The implemented laboratory includes:

- Synthetic identities and authorization roles.
- Synthetic HMAC-based trust authorities.
- Local artifact and snapshot verification.
- Structured synthetic vulnerability evidence.
- Machine-verifiable governance decisions.
- Simulated deployment and rollback.
- In-memory release registry and audit history.
- Automated security regression testing.

### 2.2 Production Scope

Production deployment is outside the implemented laboratory.

Production-oriented risk assessments are therefore conditional: they describe what could become material if this architecture were adapted for a real enterprise environment.

The production ratings are planning estimates, not measurements of a deployed system.

## 3. Risk Assessment Methodology

### 3.1 Likelihood Scale

| Score | Classification | Definition |
|---|---|---|
| 1 | Rare | Requires exceptional conditions |
| 2 | Unlikely | Plausible but dependent on uncommon conditions |
| 3 | Possible | Credible under realistic conditions |
| 4 | Likely | Expected under multiple plausible conditions |
| 5 | Almost certain | Expected frequently without additional controls |

### 3.2 Impact Scale

| Score | Classification | Definition |
|---|---|---|
| 1 | Insignificant | Negligible operational or security effect |
| 2 | Minor | Limited, recoverable impact |
| 3 | Moderate | Meaningful operational or security degradation |
| 4 | Major | Significant compromise or service disruption |
| 5 | Severe | Critical compromise, major data exposure, or prolonged operational disruption |

### 3.3 Risk Calculation

Risk score = Likelihood × Impact.

| Score | Rating | Treatment priority |
|---|---|---|
| 1–4 | Low | Monitor |
| 5–9 | Moderate | Planned treatment |
| 10–16 | High | Prioritized mitigation |
| 17–25 | Critical | Immediate treatment before production adoption |

These thresholds are project-defined assessment conventions, not official NIST or ISO scoring requirements.

### 3.4 Assessment Constraints

Scores are provisional architectural judgments.

They have not been validated against:

- A production threat environment.
- Enterprise asset criticality.
- Actual threat intelligence.
- Operational incident data.
- Organizational risk appetite.
- Business impact analysis.

A production risk owner must reassess the scores before relying on them for an authorization decision.

## 4. Risk Register

The following ratings represent conditional production exposure **if the architecture were adopted without the additional controls identified below**.

| ID | Residual risk | L | I | Score | Rating | Treatment |
|---|---|---:|---:|---:|---|---|
| RR-01 | Synthetic identity impersonation | 4 | 5 | 20 | Critical | Mitigate |
| RR-02 | Trust-authority key compromise | 3 | 5 | 15 | High | Mitigate |
| RR-03 | In-memory release registry | 4 | 4 | 16 | High | Mitigate |
| RR-04 | In-memory audit history | 4 | 4 | 16 | High | Mitigate |
| RR-05 | Concurrent artifact modification | 3 | 5 | 15 | High | Mitigate |
| RR-06 | Interrupted release transitions | 3 | 4 | 12 | High | Mitigate |
| RR-07 | Incomplete vulnerability intelligence | 4 | 4 | 16 | High | Mitigate |
| RR-08 | Compromised provenance authority | 3 | 5 | 15 | High | Mitigate |
| RR-09 | Incomplete adversarial coverage | 4 | 4 | 16 | High | Mitigate |
| RR-10 | Synthetic organizational governance | 4 | 5 | 20 | Critical | Mitigate |

**Important:** These scores are hypothetical production-adoption ratings. They are not measured residual risk levels for the offline laboratory.

## 5. Detailed Risk Assessments

### RR-01 — Synthetic Identity Impersonation

**Related threats:** P8-T11, P8-T12, P8-T16  
**Affected assets:** Governance authorization and release state  
**Primary boundary:** TB-05  
**Proposed owner:** Enterprise IAM / Security Architecture

**Risk statement:** If production authorization relied on caller-supplied identity assertions rather than independently authenticated identities, an attacker could impersonate a requester, approver, or risk owner.

**Existing laboratory controls:**

- Role authorization checks.
- Separation-of-duties validation.
- Release-bound approvals.
- Risk-owner authorization requirements.

**Residual limitation:** The laboratory does not independently authenticate enterprise identities.

**Conditional production assessment:**

- Likelihood: 4 — Likely.
- Impact: 5 — Severe.
- Score: 20 — Critical.

**Required treatment:**

- Integrate enterprise identity authentication.
- Validate authoritative role membership.
- Bind approvals to authenticated principals.
- Enforce separation of duties using trusted identity attributes.
- Implement identity lifecycle and revocation handling.

**Required evidence:** Identity-provider integration tests, unauthorized approval tests, role-revocation tests, and authenticated approval records.

**Disposition:** Mitigation required before production adoption.

### RR-02 — Trust-Authority Key Compromise

**Related threats:** P8-T05, P8-T07, P8-T14  
**Affected assets:** Trusted release registry and provenance evidence  
**Primary boundaries:** TB-02, TB-03, TB-06  
**Proposed owner:** Platform Security / Cryptographic Key Management

**Risk statement:** Compromise of the trusted signing or authentication key could permit an attacker to produce apparently authorized release or provenance records.

**Existing laboratory controls:**

- HMAC verification.
- Trusted issuer checks.
- Release and digest binding.
- Rejection of invalid signatures.

**Residual limitation:** Secure key custody and rotation are assumed rather than implemented.

**Conditional production assessment:**

- Likelihood: 3 — Possible.
- Impact: 5 — Severe.
- Score: 15 — High.

**Required treatment:**

- Protected key custody.
- Restricted signing authority.
- Key rotation and revocation.
- Signing activity monitoring.
- Documented key-compromise response.

**Required evidence:** Key-management architecture, authorization tests, rotation tests, revocation tests, and incident-response procedures.

**Disposition:** Mitigation required.

### RR-03 — In-Memory Release Registry

**Related threats:** P8-T14, P8-T22  
**Affected asset:** Trusted release registry  
**Primary boundary:** TB-06  
**Proposed owner:** Platform Engineering / Release Engineering

**Risk statement:** A production release registry maintained only in process memory could lose trusted registration state or become inconsistent after a process failure.

**Existing laboratory controls:**

- Registered release identity checks.
- Manifest and artifact digest binding.
- Conflicting registration rejection.

**Residual limitation:** Registry state is not durably persisted.

**Conditional production assessment:**

- Likelihood: 4 — Likely.
- Impact: 4 — Major.
- Score: 16 — High.

**Required treatment:**

- Durable registry storage.
- Access-controlled registration updates.
- Transactional consistency.
- Backup and recovery.
- Integrity monitoring.

**Required evidence:** Restart-recovery tests, access-control tests, consistency tests, and backup restoration tests.

**Disposition:** Mitigation required.

### RR-04 — In-Memory Audit History

**Related threats:** P8-T19, P8-T20  
**Affected asset:** Audit evidence  
**Primary boundary:** TB-08  
**Proposed owner:** Security Operations / Audit and Compliance

**Risk statement:** An attacker or process failure could remove or modify locally maintained audit records, weakening accountability and incident reconstruction.

**Existing laboratory controls:**

- Deterministic decision digests.
- Chained audit records.
- Rejected-transition audit preservation.

**Residual limitation:** Audit evidence is neither durably retained nor independently anchored.

**Conditional production assessment:**

- Likelihood: 4 — Likely.
- Impact: 4 — Major.
- Score: 16 — High.

**Required treatment:**

- Centralized audit collection.
- Append-only or tamper-evident retention.
- Restricted audit administration.
- Independent integrity verification.
- Defined retention and monitoring policies.

**Required evidence:** Audit integrity tests, access-control tests, deletion-attempt tests, and recovery tests.

**Disposition:** Mitigation required.

### RR-05 — Concurrent Artifact Modification

**Related threats:** P8-T15, P8-T22  
**Affected assets:** Artifact bytes and active release state  
**Primary boundaries:** TB-02, TB-06  
**Proposed owner:** Platform Engineering

**Risk statement:** Concurrent filesystem modifications could invalidate assumptions made between artifact verification and release activation.

**Existing laboratory controls:**

- Artifact digest verification.
- Snapshot verification.
- Selected symlink checks.
- Reverification during controlled transitions.

**Residual limitation:** The implementation does not establish complete protection against concurrent modification or filesystem race conditions.

**Conditional production assessment:**

- Likelihood: 3 — Possible.
- Impact: 5 — Severe.
- Score: 15 — High.

**Required treatment:**

- Immutable content-addressed artifacts.
- Atomic artifact promotion.
- Concurrency controls.
- Filesystem-safe artifact access.
- Final verification at the activation boundary.

**Required evidence:** Concurrent modification tests, race-condition tests, and atomic promotion validation.

**Disposition:** Mitigation required.

### RR-06 — Interrupted Release Transitions

**Related threat:** P8-T22  
**Affected asset:** Active release state  
**Primary boundaries:** TB-06, TB-07  
**Proposed owner:** Release Engineering / Site Reliability Engineering

**Risk statement:** Process termination or infrastructure failure during deployment or rollback could leave release state inconsistent.

**Existing laboratory controls:**

- Controlled state transitions.
- Rejected-operation state preservation.
- Artifact staging and verification.

**Residual limitation:** The controller does not provide crash-atomic deployment transactions.

**Conditional production assessment:**

- Likelihood: 3 — Possible.
- Impact: 4 — Major.
- Score: 12 — High.

**Required treatment:**

- Atomic state transitions.
- Durable transaction records.
- Recovery checkpoints.
- Idempotent operations.
- Failure-injection testing.

**Required evidence:** Crash-recovery tests, restart tests, interrupted deployment tests, and state-reconciliation tests.

**Disposition:** Mitigation required.

### RR-07 — Incomplete Vulnerability Intelligence

**Related threats:** P8-T09, P8-T10  
**Affected assets:** Vulnerability evidence and release policy  
**Primary boundary:** TB-04  
**Proposed owner:** Product Security / Vulnerability Management

**Risk statement:** A production release could be incorrectly assessed if vulnerability findings were incomplete, stale, incorrectly attributed, or supplied by an untrusted source.

**Existing laboratory controls:**

- Structured finding validation.
- Severity and applicability assessment.
- Scan-completeness checks.
- Component coverage checks.
- Mandatory blocking decisions.

**Residual limitation:** The laboratory does not integrate authenticated live vulnerability intelligence.

**Conditional production assessment:**

- Likelihood: 4 — Likely.
- Impact: 4 — Major.
- Score: 16 — High.

**Required treatment:**

- Authenticated scanner integrations.
- Vulnerability database update monitoring.
- Coverage verification.
- Evidence freshness requirements.
- Defined exception and remediation workflows.

**Required evidence:** Scanner integration tests, stale-evidence tests, coverage tests, and vulnerability reconciliation reports.

**Disposition:** Mitigation required.

### RR-08 — Compromised Provenance Authority

**Related threats:** P8-T07, P8-T08  
**Affected asset:** Provenance evidence  
**Primary boundary:** TB-03  
**Proposed owner:** Build Platform Security / Software Supply Chain Security

**Risk statement:** Compromise of a build identity, signing service, or provenance authority could permit malicious artifacts to receive apparently valid attestations.

**Existing laboratory controls:**

- Synthetic attestation verification.
- Subject and digest binding.
- Builder and source policy checks.
- Signing-key validation.

**Residual limitation:** Production build identity and protected signing infrastructure are not implemented.

**Conditional production assessment:**

- Likelihood: 3 — Possible.
- Impact: 5 — Severe.
- Score: 15 — High.

**Required treatment:**

- Isolated build environments.
- Protected signing infrastructure.
- Authenticated builder identities.
- Attestation policy enforcement.
- Build-system monitoring and incident response.

**Required evidence:** Build provenance verification tests, signing authority tests, unauthorized builder tests, and key-compromise exercises.

**Disposition:** Mitigation required.

### RR-09 — Incomplete Adversarial Coverage

**Related threats:** P8-T06, P8-T21, P8-T22  
**Affected assets:** All security-relevant components  
**Primary boundaries:** Cross-cutting  
**Proposed owner:** Security Architecture / Security Testing

**Risk statement:** Security weaknesses outside the automated test scenarios could remain undetected.

**Existing laboratory controls:**

- 242 automated tests.
- Malformed input rejection.
- Selected adversarial scenarios.
- Governance consistency tests.
- Deployment and rollback hardening tests.

**Residual limitation:** The suite is not an exhaustive security verification method.

**Conditional production assessment:**

- Likelihood: 4 — Likely.
- Impact: 4 — Major.
- Score: 16 — High.

**Required treatment:**

- Threat-driven test expansion.
- Property-based testing.
- Fuzz testing.
- Concurrency testing.
- Independent security review.
- Periodic threat-model updates.

**Required evidence:** Security test coverage reports, fuzzing results, review findings, and remediation records.

**Disposition:** Mitigation required.

### RR-10 — Synthetic Organizational Governance

**Related threats:** P8-T11, P8-T12, P8-T18  
**Affected assets:** Governance decisions and release authorization  
**Primary boundaries:** TB-05, TB-08  
**Proposed owner:** AI Governance / Enterprise Risk Management

**Risk statement:** A production organization could incorrectly treat technically valid synthetic governance records as evidence of real organizational authorization.

**Existing laboratory controls:**

- Explicit requester and approver roles.
- Authorized risk-owner checks.
- Separation-of-duties rules.
- Exact risk acceptance scope.
- Approval expiration.
- Deterministic decision evidence.

**Residual limitation:** The laboratory does not establish actual organizational delegation, enterprise approval workflows, or independently authenticated risk acceptance.

**Conditional production assessment:**

- Likelihood: 4 — Likely.
- Impact: 5 — Severe.
- Score: 20 — Critical.

**Required treatment:**

- Define formal risk acceptance authority.
- Establish accountable approval roles.
- Integrate authenticated approval workflows.
- Maintain durable decision records.
- Define risk escalation and expiration procedures.
- Establish governance oversight and periodic review.

**Required evidence:** Approved governance policy, authority matrix, authenticated decision records, and risk acceptance audit trails.

**Disposition:** Mitigation required.

## 6. Laboratory Versus Production Risk

| Risk | Laboratory relevance | Production relevance |
|---|---|---|
| RR-01 | Synthetic identity-model limitation | Enterprise identity compromise |
| RR-02 | Assumed key custody | Production trust-authority compromise |
| RR-03 | Expected in-memory behavior | Registry durability and integrity |
| RR-04 | Expected in-memory behavior | Audit retention and accountability |
| RR-05 | Local filesystem limitation | Concurrent artifact integrity |
| RR-06 | Simulated transition limitation | Operational deployment resilience |
| RR-07 | Synthetic evidence limitation | Scanner completeness and freshness |
| RR-08 | Synthetic signing limitation | Build and provenance authority compromise |
| RR-09 | Directly relevant to laboratory assurance | Production validation gaps |
| RR-10 | Synthetic governance-model limitation | Organizational authorization failure |

For the current laboratory, the primary actionable assurance concern is RR-09.

The other risks are principally architectural assumptions or capabilities that would require additional engineering before production adoption.

This classification does not imply that the laboratory is immune to those threats.

## 7. Risk Ownership and Accountability

The ownership assignments in this register are proposed enterprise roles.

They do not identify actual appointed risk owners.

| Responsibility | Proposed accountable function |
|---|---|
| Identity authorization | Enterprise IAM |
| Cryptographic trust | Platform Security |
| Release integrity | Release Engineering |
| Audit integrity | Security Operations |
| Vulnerability assessment | Product Security |
| Provenance assurance | Supply Chain Security |
| Security validation | Security Architecture |
| Risk acceptance governance | Enterprise Risk Management |

An actual production organization must assign named accountable owners before relying on this register.

## 8. Risk Treatment Decisions

The proposed treatment for all ten risks is mitigation before production adoption.

This is an architectural recommendation, not a recorded organizational decision.

No entry is classified as:

- Formally accepted.
- Transferred.
- Closed.
- Fully remediated.

The project does not implement an enterprise risk acceptance workflow outside its synthetic governance model.

## 9. Risk Acceptance Requirements

Any future organizational risk acceptance should document:

1. Risk identifier and description.
2. Affected assets and business processes.
3. Current likelihood and impact.
4. Existing controls and evidence.
5. Residual risk after proposed treatment.
6. Explicit acceptance justification.
7. Authorized risk owner.
8. Independent approval where required.
9. Acceptance expiration.
10. Review and revocation conditions.

The risk owner must possess documented authority.

A project author or technical implementer cannot independently establish enterprise acceptance authority.

## 10. Relationship to the Implemented Governance Engine

The laboratory's governance engine demonstrates machine-verifiable acceptance of specific review risks associated with technical release evaluations.

The residual risks in this document are broader architectural and operational risks.

These two concepts must remain distinct.

A valid synthetic release risk acceptance does not automatically authorize:

- Production deployment.
- Enterprise policy exceptions.
- Organizational acceptance of infrastructure risks.
- Acceptance of compromised identity or trust infrastructure.
- Acceptance of incomplete security validation.

## 11. Recommended Risk Treatment Sequence

### Priority 1 — Governance and Trust Foundations

Address RR-01, RR-02, and RR-10.

Establish authenticated identities, protected trust authorities, and formal organizational authorization.

### Priority 2 — Release and Evidence Integrity

Address RR-03, RR-04, RR-05, and RR-06.

Establish durable state, tamper-evident audit evidence, atomic artifact handling, and reliable release recovery.

### Priority 3 — Security Evidence Assurance

Address RR-07 and RR-08.

Integrate trustworthy vulnerability and provenance evidence.

### Priority 4 — Independent Validation

Address RR-09.

Expand adversarial testing and obtain independent security review.

The sequence is a preliminary planning recommendation. Actual prioritization must account for dependencies, exposure, and business impact.

## 12. Governance Review Requirements

The register should be reviewed when:

- A new threat or attack path is identified.
- A trust assumption changes.
- A control is materially modified.
- A new external integration is introduced.
- A deployment environment changes.
- A vulnerability affects a security-critical component.
- A risk owner or approval authority changes.
- A production adoption decision is considered.

Every material revision should preserve a record of changed assumptions, ratings, treatment decisions, and approval status.

## 13. Evidence and Traceability

Related documents:

- `docs/architecture/system-architecture.md`
- `docs/architecture/component-inventory-schema.md`
- `docs/evidence/security-control-traceability.md`
- `docs/threat-model/stride-threat-model.md`

Supporting implementation:

- `src/inventory/validator.py`
- `src/integrity/verifier.py`
- `src/provenance/verifier.py`
- `src/scanning/assessor.py`
- `src/policy/release_gate.py`
- `src/policy/governance.py`
- `src/trust/registry.py`
- `src/deployment/controller.py`

Supporting validation:

- 13 automated test modules.
- 242 passing tests.
- Selected adversarial authorization, integrity, provenance, and rollback scenarios.

The current regression result is not yet bound to a recorded source revision or independently retained evidence package.

## 14. Final Assessment

The project demonstrates a substantial set of implemented security controls in a synthetic AI supply-chain environment.

The principal architecture limitations are explicitly identified and are not presented as production-ready capabilities.

The risk register provides a preliminary framework for assessing the additional controls required for enterprise adoption.

**Laboratory status:** Implemented and regression-tested.

**Production status:** Not deployed or certified.

**Risk assessment status:** Provisional architectural assessment.

**Formal risk acceptance:** None established.

**Next review trigger:** Material architecture change or production adoption assessment.