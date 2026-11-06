# Project 8 — ISO/IEC 42001:2023 Governance Mapping

**Project:** AI Supply Chain & Secure Deployment Security Lab  
**Document ID:** P8-GOV-ISO-001  
**Standard:** ISO/IEC 42001:2023 — Artificial Intelligence Management System  
**Status:** Architecture-level control mapping  
**Environment:** Local, offline, synthetic security laboratory  
**Validation baseline:** 242 automated tests passing  
**Certification status:** Not certified; no conformity claim

---

## 1. Executive Summary

This document maps Project 8's security architecture and governance mechanisms to selected management-system requirements and control themes of ISO/IEC 42001:2023.

The project implements a synthetic AI supply-chain security laboratory with controls for:

- Component identification and dependency validation.
- Artifact integrity verification.
- Provenance verification.
- Vulnerability assessment.
- Technical release-policy enforcement.
- Trusted release registration.
- Governance authorization.
- Scoped risk acceptance.
- Controlled deployment and rollback.
- Decision and audit evidence.

These mechanisms provide technical examples of controls that could support an organizational Artificial Intelligence Management System (AIMS).

However, Project 8 is not an operational AIMS and does not demonstrate organizational conformity with ISO/IEC 42001.

## 2. Assessment Methodology

### 2.1 Scope

The assessment examines selected relationships between:

1. ISO/IEC 42001 management-system requirements.
2. Implemented Project 8 security controls.
3. Existing architectural and governance documentation.
4. Automated validation evidence.
5. Residual risks and missing organizational capabilities.

### 2.2 Evidence Classification

| Classification | Meaning |
|---|---|
| Implemented | Relevant technical control exists in the repository |
| Tested | Supporting automated tests have passed |
| Documented | Supporting architecture or governance artifact exists |
| Simulated | Mechanism uses synthetic identities or decisions |
| Partial alignment | Evidence supports part of a standard requirement or control theme |
| Organizational gap | Required organizational process is not demonstrated |
| Not assessed | Evidence is insufficient for a meaningful assessment |

These classifications do not constitute ISO conformity determinations.

### 2.3 Interpretation Limitations

ISO/IEC 42001 contains management-system requirements and supporting annex material.

This document uses high-level clause and control-theme references rather than reproducing proprietary normative requirements.

A complete conformity assessment would require access to the authoritative standard, defined organizational AIMS scope, documented processes, implementation evidence, and independent audit activities.

## 3. Clause 4 — Context of the Organization

**Theme:** Understanding organizational context, interested parties, and the scope of the AI management system.

### Project 8 Supporting Evidence

- Defined system purpose.
- Architectural component inventory.
- Eight trust boundaries.
- Nine security objectives.
- Explicit synthetic-environment limitations.
- STRIDE threat model.
- Residual risk register.

**Relevant documents:**

- `docs/architecture/system-architecture.md`
- `docs/architecture/component-inventory-schema.md`
- `docs/threat-model/stride-threat-model.md`
- `docs/governance/residual-risk-register.md`

### Assessment

**Partial architectural alignment.**

The laboratory documents technical context and system boundaries.

It does not establish:

- An organizational AIMS scope.
- Relevant interested-party requirements.
- Enterprise AI governance boundaries.
- Organizational legal and regulatory obligations.
- A functioning management system.

### Required Enterprise Evidence

- Approved AIMS scope.
- Stakeholder analysis.
- Organizational context assessment.
- Applicable requirements register.
- Management-system process documentation.

## 4. Clause 5 — Leadership

**Theme:** Leadership commitment, AI policy, responsibilities, and authority.

### Project 8 Supporting Evidence

The governance engine models:

- Release requesters.
- Authorized approvers.
- Risk owners.
- Separation of duties.
- Release-specific authorization.
- Explicit risk acceptance.

**Implementation:**

`src/policy/governance.py`

**Representative tests:**

- `test_governance.py::test_002_unauthorized_approver`
- `test_governance.py::test_003_self_approval_rejected`
- `test_governance.py::test_010_unauthorized_risk_owner`
- `test_governance.py::test_011_requester_cannot_accept_risk`
- `test_governance.py::test_012_approver_cannot_accept_risk`

### Assessment

**Simulated technical alignment; organizational gap.**

The project demonstrates machine-verifiable authorization rules.

It does not establish actual leadership commitment, an approved AI policy, or formally delegated organizational authority.

### Required Enterprise Evidence

- Approved AI policy.
- Leadership accountability records.
- Governance committee charter.
- Documented responsibilities.
- Formal delegation of risk acceptance authority.

## 5. Clause 6 — Planning

**Theme:** AI risks, opportunities, objectives, and planned treatment.

### Project 8 Supporting Evidence

The project includes:

- Nine defined security objectives.
- Twenty-two STRIDE threat scenarios.
- Ten residual risk records.
- Provisional risk ratings.
- Recommended risk treatments.
- Security release-policy decisions.

**Relevant documents:**

- `docs/threat-model/stride-threat-model.md`
- `docs/governance/residual-risk-register.md`
- `docs/evidence/security-control-traceability.md`

### Assessment

**Partial alignment.**

The laboratory demonstrates technical security-risk identification and a provisional risk treatment methodology.

The residual risk scores are hypothetical production-adoption assessments rather than validated organizational risk measurements.

### Required Enterprise Evidence

- Organization-approved AI risk assessment methodology.
- Defined risk criteria and appetite.
- AI risk treatment plans.
- Assigned risk owners.
- Approved objectives and measurable targets.
- Documented acceptance decisions.

## 6. Clause 7 — Support

**Theme:** Resources, competence, awareness, communication, and documented information.

### Project 8 Supporting Evidence

The repository maintains:

- System architecture documentation.
- Component inventory schema documentation.
- Security-control traceability.
- Threat modeling.
- Risk assessment.
- Framework mappings.
- Automated test modules.

### Assessment

**Partial documented-information alignment.**

The repository demonstrates structured technical documentation and reproducible testing.

It does not demonstrate an organizational competence program, workforce training, formal communications, or controlled enterprise document retention.

### Required Enterprise Evidence

- Competence and training records.
- Awareness program.
- Document approval and revision controls.
- Retention schedules.
- Internal and external communication procedures.

## 7. Clause 8 — Operation

**Theme:** Operational planning, control, AI risk assessment, risk treatment, and AI system impact assessment.

### Project 8 Supporting Evidence

**Technical security evaluation**

- `src/inventory/validator.py`
- `src/integrity/verifier.py`
- `src/provenance/verifier.py`
- `src/scanning/assessor.py`
- `src/policy/release_gate.py`

**Governance and release control**

- `src/policy/governance.py`
- `src/trust/registry.py`
- `src/deployment/controller.py`

The laboratory implements:

- Evidence validation.
- Mandatory technical blocking.
- Review-required risk decisions.
- Scoped risk acceptance.
- Trusted release verification.
- Authorized deployment.
- Fresh authorization for rollback.

### Assessment

**Substantial technical implementation within a limited scope; partial standard alignment.**

The project demonstrates controlled security decisions but not complete organizational AI operations.

An AI system impact assessment covering affected individuals and societal impacts is not implemented.

### Required Enterprise Evidence

- Approved operational procedures.
- Production change management.
- AI impact assessment.
- Operational risk treatment records.
- Authenticated approval workflows.
- Continuous operational control evidence.

## 8. Clause 9 — Performance Evaluation

**Theme:** Monitoring, measurement, analysis, internal audit, and management review.

### Project 8 Supporting Evidence

The repository contains 13 automated test modules.

**Recorded validation baseline:**

242 automated tests passing.

Supporting evidence includes:

- Inventory validation tests.
- Artifact integrity tests.
- Provenance tests.
- Vulnerability assessment tests.
- Release-policy tests.
- Governance consistency tests.
- Risk acceptance integration tests.
- Deployment and rollback tests.

### Assessment

**Partial technical measurement alignment; organizational gap.**

Automated regression testing provides technical evidence.

It does not constitute an ISO/IEC 42001 internal audit or management review.

### Required Enterprise Evidence

- Monitoring and measurement program.
- Defined AIMS performance indicators.
- Internal audit plan and results.
- Management review records.
- Corrective-action tracking.
- Independent evaluation of control effectiveness.

## 9. Clause 10 — Improvement

**Theme:** Nonconformity, corrective action, and continual improvement.

### Project 8 Supporting Evidence

The development process has included:

- Identification of inconsistent technical behavior.
- Security test remediation.
- Governance consistency hardening.
- Deployment and rollback hardening.
- Architecture documentation reconciliation.
- Residual risk identification.

The current regression baseline is 242 passing tests.

### Assessment

**Partial engineering-process alignment.**

The project demonstrates iterative technical remediation.

It does not establish a formal organizational nonconformity and corrective-action management system.

### Required Enterprise Evidence

- Nonconformity register.
- Root-cause analysis.
- Corrective-action ownership.
- Effectiveness verification.
- Management review of improvements.

## 10. Annex A — AI Management Control Themes

The following are selected conceptual relationships to ISO/IEC 42001 Annex A control areas.

They are not exhaustive control-by-control conformity assessments.

| Control theme | Project 8 evidence | Assessment |
|---|---|---|
| AI policies | Technical release and governance rules | Partial |
| Internal organization | Synthetic roles and separation of duties | Simulated |
| Resources for AI systems | Component inventory and dependencies | Partial |
| AI system impact assessment | Security threat model only | Gap |
| AI system lifecycle | Release evaluation, deployment, rollback | Partial |
| Data for AI systems | Dataset registration and integrity-related controls | Partial |
| Information for interested parties | Technical architecture documentation | Partial |
| Third-party and customer relationships | Provenance, dependencies, trusted releases | Partial |

These themes support architectural discussion.

They do not establish implementation of every corresponding Annex A control.

## 11. Control-to-Standard Traceability

| Project control | ISO/IEC 42001 relationship | Evidence |
|---|---|---|
| Component inventory | Context, resources, lifecycle, third-party relationships | Schema and validator |
| Artifact integrity | Operational control, lifecycle | Integrity verifier |
| Provenance verification | Third-party relationships, lifecycle | Provenance verifier |
| Vulnerability assessment | Risk assessment, operational control | Vulnerability assessor |
| Release policy | Operational control, risk treatment | Release gate |
| Trusted release registry | Operational control, lifecycle | Trust registry |
| Governance authorization | Leadership, responsibilities, operational control | Governance engine |
| Risk acceptance | Risk treatment and accountability | Governance engine |
| Controlled rollback | Lifecycle and operational resilience | Deployment controller |
| Audit evidence | Documented information and performance evaluation | Governance and controller |
| Regression testing | Monitoring, measurement, improvement | 13 test modules |

## 12. Governance Accountability Model

The laboratory separates technical and governance decisions.

### Technical Decision

The release gate determines whether a candidate is:

- `ELIGIBLE`
- `REVIEW`
- `BLOCKED`

### Governance Decision

The governance engine evaluates:

- Approval authority.
- Requester and approver separation.
- Release identity.
- Manifest binding.
- Approval expiration.
- Required risk acceptance.
- Risk-owner authorization.

### Deployment Decision

The controller requires:

- Trusted release registration.
- Valid artifact references.
- Technical evaluation.
- Governance authorization.
- Valid operation-specific requirements.

### Organizational Limitation

These controls model technical enforcement of governance policy.

They do not establish a real enterprise AI management system.

## 13. Risk Treatment and Acceptance

The project distinguishes two different forms of risk handling.

### 13.1 Synthetic Release Risk Acceptance

The governance engine evaluates specific review risks associated with a technical release.

Acceptance is restricted by:

- Risk scope.
- Release identity.
- Manifest digest.
- Component identity.
- Authorization.
- Expiration.

Blocked technical decisions cannot be overridden through ordinary acceptance.

### 13.2 Organizational Residual Risk

The residual risk register documents broader architectural and operational risks.

These include:

- Identity authentication.
- Trust-key custody.
- Registry durability.
- Audit retention.
- Deployment atomicity.
- Vulnerability intelligence.
- Production governance.

No organizational acceptance of these risks has been established.

The two risk processes must not be conflated.

## 14. Evidence Gaps

| Gap ID | Missing evidence | Recommended action |
|---|---|---|
| ISO-EG-01 | Approved AIMS scope | Establish organizational scope |
| ISO-EG-02 | Leadership policy and commitment | Obtain approved AI policy |
| ISO-EG-03 | Formal accountability | Assign actual governance authorities |
| ISO-EG-04 | Organizational AI risk assessment | Implement approved risk methodology |
| ISO-EG-05 | AI system impact assessment | Assess affected parties and potential harms |
| ISO-EG-06 | Workforce competence | Establish training and awareness evidence |
| ISO-EG-07 | Production monitoring | Define operational measurement and telemetry |
| ISO-EG-08 | Internal audit | Establish independent audit activities |
| ISO-EG-09 | Management review | Record leadership review of AIMS performance |
| ISO-EG-10 | Corrective-action process | Establish formal improvement workflow |
| ISO-EG-11 | Durable governance evidence | Implement protected persistent records |
| ISO-EG-12 | Production identity assurance | Integrate authenticated enterprise identities |

## 15. Relationship to NIST AI RMF

Project 8 also includes:

`docs/governance/nist-ai-rmf-mapping.md`

The two mappings serve complementary purposes.

**NIST AI RMF** organizes AI risk management into GOVERN, MAP, MEASURE, and MANAGE functions.

**ISO/IEC 42001** provides requirements for establishing, implementing, maintaining, and continually improving an organizational AI management system.

Project 8 demonstrates selected technical mechanisms relevant to both.

Neither mapping establishes certification or organizational conformity.

## 16. Assurance Statement

Project 8 implements a synthetic AI supply-chain security architecture with selected controls relevant to ISO/IEC 42001 governance and operational themes.

The strongest supporting evidence concerns:

- Security evaluation.
- Release-policy enforcement.
- Machine-verifiable governance.
- Scoped risk acceptance.
- Trusted release verification.
- Authorized deployment and rollback.
- Automated technical validation.

The laboratory does not establish a complete AIMS.

**Technical implementation:** Demonstrated within synthetic scope.

**Automated validation:** 242 passing tests.

**ISO/IEC 42001 alignment:** Partial, architecture-level.

**Organizational conformity:** Not assessed.

**Certification:** Not claimed.

---

**Document status:** Initial architecture-level governance mapping.

**Next review trigger:** Material architecture change, authoritative control-level review, or production adoption assessment.