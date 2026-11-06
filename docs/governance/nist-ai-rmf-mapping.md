# Project 8 — NIST AI RMF 1.0 Governance Mapping

**Project:** AI Supply Chain & Secure Deployment Security Lab  
**Document ID:** P8-GOV-NIST-001  
**Status:** Architecture-level framework alignment  
**Framework:** NIST AI Risk Management Framework (AI RMF 1.0), AI 100-1  
**Environment:** Local, offline, synthetic laboratory  
**Validation baseline:** 242 automated tests passing  
**Compliance status:** Not assessed; no compliance claim

---

## 1. Executive Summary

This document maps the implemented Project 8 security architecture to selected categories of the NIST AI Risk Management Framework (AI RMF 1.0).

The purpose is to demonstrate how technical supply-chain controls, governance authorization, risk acceptance, threat modeling, and validation evidence can support AI risk management.

The mapping addresses four NIST AI RMF functions:

1. GOVERN — Establishing organizational risk governance.
2. MAP — Understanding system context and identifying risks.
3. MEASURE — Evaluating and documenting risks.
4. MANAGE — Prioritizing, responding to, and monitoring risks.

The laboratory demonstrates selected technical mechanisms that could support these functions in an enterprise AI governance program.

It does not implement a complete organizational AI risk management system.

## 2. Framework Interpretation

NIST AI RMF 1.0 is a voluntary risk management framework.

Its functions and categories describe desired risk management outcomes.

The framework is not a prescriptive software certification standard.

The presence of an implemented technical control does not establish that an organization has satisfied a corresponding governance outcome.

Accordingly, this document distinguishes:

- Directly implemented technical controls.
- Supporting architectural documentation.
- Synthetic governance mechanisms.
- Organizational practices not implemented.
- Evidence gaps and residual risks.

### 2.1 Evidence Classification

| Classification | Meaning |
|---|---|
| Implemented | Supporting software control exists |
| Tested | Relevant automated tests exist and pass |
| Documented | Architectural or governance evidence exists |
| Simulated | Behavior uses synthetic identities, decisions, or resources |
| Partial alignment | Evidence supports part of a framework outcome |
| Organizational gap | Required enterprise practice is not implemented |
| Not assessed | No sufficient evidence has been established |

Framework alignment is not equivalent to compliance.

## 3. GOVERN Function

### 3.1 Objective

The GOVERN function establishes the organizational culture, structures, policies, processes, and accountability necessary for AI risk management.

Project 8 primarily supports GOVERN through its synthetic authorization and risk acceptance mechanisms.

### 3.2 Category Mapping

| NIST category | Category focus | Project 8 evidence | Assessment |
|---|---|---|---|
| GOVERN 1 | Policies, processes, procedures, and practices | Release policy, governance rules, architecture documentation | Partial alignment |
| GOVERN 2 | Accountability structures | Requester, approver, and risk-owner separation | Simulated; partial alignment |
| GOVERN 3 | Workforce diversity, expertise, and training | No organizational workforce program | Organizational gap |
| GOVERN 4 | Risk management culture | Explicit risk decisions and rejection of unauthorized exceptions | Partial technical alignment |
| GOVERN 5 | Engagement with relevant AI actors | No implemented stakeholder engagement process | Organizational gap |
| GOVERN 6 | Third-party and supply-chain risk policies | Component inventory, provenance, trusted releases, vulnerability evaluation | Partial technical alignment |

These are category-level mappings, not assessments of every underlying NIST subcategory.

### 3.3 Implemented Governance Controls

**Authorization enforcement**

The governance engine evaluates release-specific approval requests and enforces modeled authorization requirements.

Implementation:

`src/policy/governance.py`

Representative tests:

- `test_governance.py::test_002_unauthorized_approver`
- `test_governance.py::test_003_self_approval_rejected`
- `test_governance.py::test_004_wrong_release_id`
- `test_governance.py::test_005_wrong_manifest_digest`

**Risk acceptance**

Risk acceptance is constrained by:

- Authorized risk ownership.
- Separation of duties.
- Exact release identity.
- Exact manifest digest.
- Component-specific risk scope.
- Expiration.
- Justification.
- Technical blocking precedence.

Representative tests:

- `test_governance.py::test_010_unauthorized_risk_owner`
- `test_governance.py::test_013_expired_risk_acceptance`
- `test_governance.py::test_033_cross_component_acceptance_rejected`
- `test_governance.py::test_038_blocked_gate_cannot_be_overridden`
- `test_risk_acceptance_integration.py::test_010_valid_exact_risk_acceptance`

### 3.4 Governance Limitations

The laboratory does not establish:

- An actual enterprise AI governance committee.
- Organizationally approved AI policies.
- Authenticated employee identities.
- Formally delegated risk acceptance authority.
- Workforce training.
- Stakeholder consultation.
- Independent compliance oversight.

The implemented controls demonstrate technical governance enforcement, not complete organizational governance.

## 4. MAP Function

### 4.1 Objective

The MAP function establishes the context needed to understand AI system risks, including system characteristics, affected actors, benefits, limitations, and potential harms.

Project 8 primarily addresses the technical supply-chain portion of this context.

### 4.2 Category Mapping

| NIST category | Category focus | Project 8 evidence | Assessment |
|---|---|---|---|
| MAP 1 | Context establishment | System architecture, scope, assets, trust assumptions | Documented; partial alignment |
| MAP 2 | AI system categorization | Model, package, container, and dataset inventory types | Partial technical alignment |
| MAP 3 | AI capabilities, benefits, costs, and relevant performance context | Limited to supply-chain security architecture | Organizational and system-level gap |
| MAP 4 | Risks and benefits for affected individuals, groups, communities, organizations, and society | STRIDE threats and technical risks; broader impacts not assessed | Partial security-risk alignment |
| MAP 5 | Impacts from third-party software, data, and other resources | Dependencies, provenance, vulnerability findings, trusted releases | Partial technical alignment |

### 4.3 Supporting Evidence

**System context**

`docs/architecture/system-architecture.md`

Defines:

- Security objectives.
- Architectural components.
- Data flows.
- Trust boundaries.
- Security invariants.
- Operational limitations.

**Component identification**

`docs/architecture/component-inventory-schema.md`

`src/inventory/validator.py`

The inventory provides structured registration for:

- Models.
- Packages.
- Container images.
- Datasets.

**Threat identification**

`docs/threat-model/stride-threat-model.md`

Documents 22 architectural threat scenarios across eight trust boundaries and cross-cutting concerns.

**Residual risks**

`docs/governance/residual-risk-register.md`

Documents ten risks, provisional production-adoption ratings, treatment recommendations, and proposed ownership roles.

### 4.4 Mapping Limitations

The laboratory does not assess a deployed AI model's:

- Intended business purpose.
- Human impact.
- Fairness.
- Explainability.
- Accessibility.
- Societal consequences.
- Operational performance.
- Environmental impact.

These dimensions would require a system-specific AI impact assessment.

## 5. MEASURE Function

### 5.1 Objective

The MEASURE function uses qualitative and quantitative methods to assess AI risks, track relevant outcomes, and evaluate risk management effectiveness.

Project 8 provides its strongest direct technical evidence in this function.

### 5.2 Category Mapping

| NIST category | Category focus | Project 8 evidence | Assessment |
|---|---|---|---|
| MEASURE 1 | Identification and application of measurement methods and metrics | Security evaluation rules, deterministic decisions, test suite | Partial technical alignment |
| MEASURE 2 | Evaluation of AI systems for trustworthiness | Artifact, provenance, vulnerability, and release evaluation | Partial supply-chain alignment |
| MEASURE 3 | Tracking mechanisms for identified risks | Review-risk identifiers, decision digests, audit history | Simulated; partial alignment |
| MEASURE 4 | Feedback about measurement effectiveness | Regression results and identified evidence gaps | Partial alignment |

### 5.3 Technical Evaluation Controls

**Artifact integrity**

`src/integrity/verifier.py`

Evaluates artifact bytes against expected cryptographic digests.

**Provenance**

`src/provenance/verifier.py`

Evaluates synthetic provenance evidence against trusted policy.

**Vulnerability assessment**

`src/scanning/assessor.py`

Processes vulnerability findings, applicability, and evidence coverage.

**Release security gate**

`src/policy/release_gate.py`

Produces:

- `ELIGIBLE`
- `REVIEW`
- `BLOCKED`

**Governance consistency**

`src/policy/governance.py`

Rejects inconsistent component counts, decisions, review risks, and acceptance scopes.

### 5.4 Validation Evidence

The repository contains 13 test modules and a recorded baseline of 242 passing tests.

Relevant evidence includes:

- `tests/test_artifact_integrity.py`
- `tests/test_provenance_verifier.py`
- `tests/test_vulnerability_assessor.py`
- `tests/test_release_gate.py`
- `tests/test_governance.py`
- `tests/test_governance_consistency.py`
- `tests/test_risk_acceptance_integration.py`

The traceability matrix identifies representative tests for each security objective.

Reference:

`docs/evidence/security-control-traceability.md`

### 5.5 Measurement Limitations

The 242 passing tests demonstrate behavior under the implemented test scenarios.

They do not measure:

- Production security incident rates.
- Detection effectiveness against live adversaries.
- Real-world model reliability.
- Bias or fairness.
- Privacy risk.
- Human-AI interaction quality.
- Continuous production monitoring effectiveness.

No comprehensive operational AI trustworthiness measurement program is implemented.

## 6. MANAGE Function

### 6.1 Objective

The MANAGE function prioritizes and responds to identified risks, including risk treatment, monitoring, and decisions about whether AI systems should proceed.

Project 8 supports MANAGE through release decisions, governance authorization, risk acceptance, and rollback controls.

### 6.2 Category Mapping

| NIST category | Category focus | Project 8 evidence | Assessment |
|---|---|---|---|
| MANAGE 1 | Prioritization and response to identified risks | Release policy and residual risk register | Partial alignment |
| MANAGE 2 | Planning and implementation of risk treatment | Blocking, review, scoped acceptance, controlled deployment | Partial technical alignment |
| MANAGE 3 | Management of third-party AI risks | Component verification, provenance, vulnerability assessment | Partial technical alignment |
| MANAGE 4 | Risk treatment documentation and monitoring | Governance decisions, audit chain, rollback evidence | Simulated; partial alignment |

### 6.3 Implemented Risk Responses

**Mandatory blocking**

The release gate blocks releases that violate defined mandatory security requirements.

A blocked technical decision cannot be overridden through ordinary risk acceptance.

**Risk review**

Selected findings and incomplete security evidence require explicit review.

**Risk acceptance**

Review risks may proceed only when the governance engine validates the applicable acceptance requirements.

**Deployment control**

The deployment controller requires trusted release registration, technical evaluation, and governance authorization.

**Rollback control**

Rollback requires a new authorization and fresh technical evaluation.

Relevant implementation:

- `src/policy/release_gate.py`
- `src/policy/governance.py`
- `src/deployment/controller.py`

### 6.4 Risk Treatment Documentation

`docs/governance/residual-risk-register.md`

Provides:

- Ten residual risks.
- Provisional likelihood and impact ratings.
- Recommended mitigation.
- Proposed accountable functions.
- Production adoption considerations.

These recommendations are not recorded organizational decisions.

### 6.5 Management Limitations

The laboratory does not implement:

- Production continuous monitoring.
- Automated vulnerability intelligence updates.
- Enterprise incident management.
- Durable risk workflow integration.
- Formal risk committee escalation.
- Production recovery orchestration.
- Organization-wide AI risk reporting.

## 7. Cross-Functional Traceability

| Security objective | GOVERN | MAP | MEASURE | MANAGE |
|---|---|---|---|---|
| P8-SO01 — Component identification | Supporting | Primary | Supporting | Supporting |
| P8-SO02 — Artifact integrity | Supporting | Supporting | Primary | Primary |
| P8-SO03 — Provenance assurance | Supporting | Primary | Primary | Supporting |
| P8-SO04 — Vulnerability assessment | Supporting | Primary | Primary | Primary |
| P8-SO05 — Release policy | Primary | Supporting | Primary | Primary |
| P8-SO06 — Authorization | Primary | Supporting | Supporting | Primary |
| P8-SO07 — Rollback | Primary | Supporting | Primary | Primary |
| P8-SO08 — Auditability | Primary | Supporting | Primary | Primary |
| P8-SO09 — Governance | Primary | Primary | Supporting | Primary |

"Primary" indicates a strong conceptual relationship between the security objective and the NIST function.

It does not indicate full framework satisfaction.

## 8. Risk Governance Decision Model

The laboratory models the following decision sequence:

```text
Component registration
        |
        v
Artifact and provenance verification
        |
        v
Vulnerability assessment
        |
        v
Technical release evaluation
        |
        +---- BLOCKED ---> Release rejected
        |
        +---- REVIEW ----> Risk acceptance required
        |                        |
        |                        v
        |                 Governance validation
        |                        |
        |                  Approved / Rejected
        |
        +---- ELIGIBLE --> Governance authorization
                                 |
                                 v
                         Trusted release check
                                 |
                                 v
                         Controlled deployment
                                 |
                                 v
                         Audit evidence
```

This is a conceptual representation of the control sequence.

It is not a complete executable specification of every internal controller operation.

Rollback follows a separate authorized recovery path.

## 9. Governance Roles and Responsibilities

The following roles are modeled or proposed.

| Role | Responsibility | Implementation status |
|---|---|---|
| Release requester | Initiates a release request | Synthetic |
| Release approver | Authorizes an eligible operation | Synthetic |
| Risk owner | Accepts defined review risks | Synthetic |
| Security policy owner | Defines release security requirements | Proposed organizational role |
| AI governance owner | Oversees AI risk management | Proposed organizational role |
| Platform security owner | Protects release trust infrastructure | Proposed organizational role |
| Audit and compliance owner | Reviews evidence and accountability | Proposed organizational role |

The laboratory enforces selected separation-of-duties requirements using synthetic identities.

It does not authenticate real enterprise personnel.

## 10. Evidence Gaps

### NIST-EG-01 — Organizational Governance

No formally adopted enterprise AI governance policies or committees are demonstrated.

### NIST-EG-02 — AI System Impact Assessment

No complete assessment of affected individuals, societal impacts, fairness, or privacy is performed.

### NIST-EG-03 — Production Identity Assurance

Governance identities are synthetic.

### NIST-EG-04 — Continuous Monitoring

No production telemetry, monitoring, or operational feedback program is implemented.

### NIST-EG-05 — Durable Governance Evidence

The trust registry and audit history are maintained in memory.

### NIST-EG-06 — Independent Validation

The automated test suite has not undergone a complete independent assertion-level security review.

### NIST-EG-07 — Organizational Risk Acceptance

No actual enterprise risk acceptance authority or signed organizational decision is established.

## 11. Relationship to Other Frameworks

The NIST AI RMF mapping complements, but does not replace, other security frameworks.

**NIST SSDF:** Secure software development and software supply-chain practices.

**SLSA:** Build integrity and provenance assurance concepts.

**ISO/IEC 42001:2023:** Organizational AI management systems.

**MITRE ATLAS:** Adversarial AI threat analysis.

**STRIDE:** Threat identification across system trust boundaries.

Project 8 uses these frameworks as complementary architectural references.

No certification or formal compliance level is claimed.

## 12. Architecture-Level Assessment

### GOVERN

**Assessment:** Partial technical and documented alignment.

Strongest evidence:

- Machine-verifiable governance decisions.
- Separation-of-duties checks.
- Scoped risk acceptance.
- Explicit residual risk documentation.

Primary gap: Actual organizational authority and governance processes.

### MAP

**Assessment:** Partial supply-chain security alignment.

Strongest evidence:

- Component inventory.
- Architecture and trust boundaries.
- STRIDE threat model.
- Residual risk register.

Primary gap: Broader AI system context and impact assessment.

### MEASURE

**Assessment:** Substantial technical testing within a narrow supply-chain security scope; partial framework alignment.

Strongest evidence:

- Integrity verification.
- Provenance validation.
- Vulnerability assessment.
- Release-policy testing.
- 242 passing automated tests.

Primary gap: Operational AI trustworthiness measurement and independent validation.

### MANAGE

**Assessment:** Partial technical alignment.

Strongest evidence:

- Mandatory security blocking.
- Explicit review decisions.
- Scoped risk acceptance.
- Controlled deployment and rollback.

Primary gap: Production monitoring, organizational escalation, and durable risk management.

## 13. Recommended Next Steps

To strengthen the framework alignment:

1. Review representative security test assertions.
2. Document risk decision authority and approval escalation.
3. Establish a revision-bound evidence package.
4. Add explicit NIST AI RMF subcategory-level mapping where evidence supports it.
5. Document AI-system-specific impact assessment requirements.
6. Map relevant controls to ISO/IEC 42001.
7. Map relevant adversarial scenarios to MITRE ATLAS.
8. Reassess framework alignment after material architecture changes.

## 14. Final Assurance Statement

Project 8 demonstrates selected technical security controls and governance mechanisms relevant to NIST AI RMF 1.0.

The strongest evidence concerns supply-chain security evaluation, release policy, machine-verifiable governance, risk acceptance, and authorized rollback.

The project does not establish full NIST AI RMF implementation, enterprise governance maturity, production security assurance, or regulatory compliance.

**Framework alignment:** Partial, architecture-level.

**Implemented environment:** Synthetic laboratory.

**Automated validation:** 242 passing tests.

**Organizational compliance:** Not assessed.

**Formal certification:** Not claimed.