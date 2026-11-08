# AI Supply Chain & Secure Deployment Security Lab

**Security Architecture | Supply Chain Assurance | Release Governance**

## Overview

---

An implementation-focused security laboratory demonstrating the validation, integrity verification, provenance assessment, and controlled deployment of AI supply-chain components.

The project implements a local, offline security-control pipeline that evaluates component inventories, artifact integrity, provenance evidence, vulnerability findings, and release eligibility. A separate governance layer enforces authorization, scoped risk acceptance, and trusted release requirements before simulated deployment or rollback.

**Key Capabilities**
- AI component inventory and dependency validation
- SHA-256 artifact integrity and provenance verification
- Vulnerability assessment and policy-based release decisions
- Trusted release registration and governance authorization
- Risk acceptance with scope, ownership, and expiration enforcement
- Verified deployment and independently authorized rollback
- Adversarial security testing and audit evidence

**Validation:** 242 automated tests passing  
**Environment:** Python 3.11 · JSON Schema Draft 2020-12 · Synthetic artifacts  
**Deployment:** Local simulation; no production cloud infrastructure


## 2. Security Problem

AI supply-chain compromise can occur when an organization accepts untrusted component metadata, deploys modified artifacts, relies on unverifiable provenance, overlooks security findings, or permits unauthorized release transitions.

The central architectural problem is that multiple independent trust decisions are often collapsed into a single approval.

This laboratory separates those decisions.

| Security concern | Architectural response |
|---|---|
| Malformed or deceptive component manifests | Strict inventory registration |
| Dependency substitution or inconsistent dependency graphs | Cross-record dependency validation |
| Modified artifact bytes | Cryptographic integrity verification |
| Untrusted provenance claims | Separate provenance assessment |
| Vulnerable components or incomplete security evidence | Vulnerability assessment and release policy |
| Untrusted release identifiers or digests | Trusted release registry |
| Forged or inconsistent governance evidence | Machine-verifiable authorization |
| Improperly scoped risk acceptance | Exact risk, release, and manifest binding |
| Unauthorized deployment | Controlled release transition |
| Malicious or unauthorized rollback | Fresh technical and governance evaluation |
| Untraceable release decisions | Deterministic decision and audit evidence |

## 3. Architecture

The implementation consists of nine primary security responsibilities.

| Component | Responsibility |
|---|---|
| Component inventory | Validate component identity, metadata, and dependencies |
| Integrity verifier | Evaluate artifact bytes against expected digests |
| Provenance verifier | Evaluate provenance evidence under defined policy |
| Vulnerability assessor | Process structured vulnerability findings |
| Release security gate | Produce component and aggregate technical decisions |
| Trusted release registry | Establish synthetic authenticated release references |
| Governance engine | Validate release authorization and risk acceptance |
| Deployment controller | Enforce simulated release transitions |
| Audit mechanism | Record traceable deployment and rollback outcomes |

### 3.1 Architecture Diagrams

Three independently documented Mermaid diagrams illustrate the implemented security architecture.

| Diagram | Purpose |
|---|---|
| [System Security Architecture](docs/architecture/system-security-diagram.md) | Security components, evaluation layers, trust boundaries, and release control |
| [Secure Release Authorization](docs/architecture/release-authorization-diagram.md) | Technical decisions, governance approval, trusted registration, and deployment |
| [Verified Rollback and Recovery](docs/architecture/rollback-recovery-diagram.md) | Recovery trust verification, fresh authorization, snapshot integrity, and rollback |

These diagrams represent logical security responsibilities and simulated workflows, not independently deployed services or production infrastructure.

### 3.2 Trust Boundaries

The architecture defines eight principal trust boundaries:

- **TB-01:** External component to local inventory.
- **TB-02:** Artifact to integrity verifier.
- **TB-03:** Provenance evidence to trust decision.
- **TB-04:** Vulnerability findings to policy decision.
- **TB-05:** Technical evaluation to governance authorization.
- **TB-06:** Authorized release to deployment state.
- **TB-07:** Recovery request to rollback state.
- **TB-08:** Operational evidence to governance records.

Each boundary addresses a different class of untrusted input, authority transition, or integrity requirement.

See [System Architecture](docs/architecture/system-architecture.md) for detailed component descriptions, data flows, security invariants, and limitations.

## 4. Component Inventory Security

The inventory supports four component classes:

1. AI models.
2. Software packages.
3. Container images.
4. Datasets.

Registration uses JSON Schema Draft 2020-12 and a Python dependency-graph validator.

Implemented controls include:

- Mandatory field validation.
- Strict component identifiers.
- Supported component-type enforcement.
- SHA-256 digest syntax validation.
- Rejection of unexpected properties.
- Duplicate component identifier rejection.
- Missing dependency rejection.
- Direct self-dependency rejection.
- Directed dependency-cycle rejection.
- Defensive copying of accepted records.

Initial registration requires the following security states:

| Field | Required value |
|---|---|
| Inventory status | `unverified` |
| Provenance verification | `unverified` |
| License review | `unreviewed` |
| Risk acceptance | `not_assessed` |

Registration cannot independently establish artifact trust, approve a license, accept organizational risk, or authorize deployment.

**Implementation:** `src/inventory/validator.py`  
**Schema:** `policies/component-inventory.schema.json`

See [Component Inventory Schema](docs/architecture/component-inventory-schema.md).

### 4.1 Synthetic Manifest

The repository includes:

`data/synthetic/model-manifest.json`

This is an illustrative component-registration fixture containing synthetic metadata and placeholder digest values.

The manifest is not evidence of a verified production artifact, completed provenance attestation, or authorized deployment.

A syntactically valid digest is not independently evidence that corresponding artifact bytes have been verified.

## 5. Artifact Integrity and Provenance

### 5.1 Artifact Integrity

The integrity subsystem evaluates local artifact bytes against expected cryptographic digests.

The architecture distinguishes:

- A digest declared by a component manifest.
- A digest calculated from artifact bytes.
- A trusted release-bound digest reference.

A caller-controlled digest cannot independently establish release trust.

The deployment controller uses trusted release references and verifies artifact identities before permitted state transitions.

**Implementation:** `src/integrity/verifier.py`

### 5.2 Provenance

The provenance subsystem evaluates evidence concerning artifact origin and production.

Inventory metadata may declare a builder, source revision, or attestation reference, but those declarations are not independently authenticated by registration.

Provenance verification is therefore separated from component inventory validation.

**Implementation:** `src/provenance/verifier.py`

The laboratory does not claim production-grade builder identity authentication or external provenance authority.

## 6. Vulnerability Assessment and Release Policy

### 6.1 Vulnerability Assessment

The vulnerability subsystem processes structured findings associated with supply-chain components.

Assessment output contributes to release-policy evaluation.

A missing vulnerability finding is not equivalent to proof that a component is secure.

**Implementation:** `src/scanning/assessor.py`

### 6.2 Release Security Gate

The release gate produces component-level and aggregate technical decisions.

| Decision | Meaning |
|---|---|
| `ELIGIBLE` | Technical requirements permit progression to governance authorization |
| `REVIEW` | Identified risks require authorized disposition |
| `BLOCKED` | A mandatory security requirement prevents release |

A `REVIEW` decision does not automatically become an authorized deployment.

A `BLOCKED` decision cannot be bypassed through ordinary risk acceptance.

The technical result includes component decisions, evaluation counts, reasons, and applicable review risks.

**Implementation:** `src/policy/release_gate.py`

See [Secure Release Authorization](docs/architecture/release-authorization-diagram.md).

## 7. Trusted Release Registration

The laboratory uses a trusted release registry to distinguish registered release references from untrusted caller claims.

The registry models HMAC-based authentication of release identity and associated artifact information.

The deployment controller verifies release identity, manifest digest, and component artifact references against the trusted registration context.

**Implementation:** `src/trust/registry.py`

### 7.1 Trust Assumptions

The laboratory assumes that the synthetic trust authority and its cryptographic key are protected outside the modeled attacker-controlled inputs.

It does not implement:

- Enterprise certificate infrastructure.
- Hardware-backed key custody.
- Production signing services.
- Independent external trust verification.

HMAC-based release trust is a controlled laboratory mechanism, not a claim of production supply-chain attestation.

## 8. Governance and Risk Acceptance

The governance engine evaluates release authorization separately from technical security eligibility.

**Implementation:** `src/policy/governance.py`

### 8.1 Authorization Binding

Governance decisions are evaluated against the applicable:

- Release identifier.
- Manifest digest.
- Requested operation.
- Technical evaluation.
- Component-specific review risks.
- Risk ownership and authorization context.
- Risk acceptance expiration, where applicable.

### 8.2 Machine-Verifiable Risk Acceptance

Risk acceptance must satisfy the implemented authorization, scope, justification, and validity requirements.

The engine rejects inconsistent or improperly scoped acceptance.

It also checks the consistency of technical component results and aggregate release decisions.

Examples of rejected conditions include:

- Duplicate component results.
- Incorrect evaluated-component counts.
- Inconsistent aggregate decisions.
- Mismatched aggregate review risks.
- Cross-component risk substitution.
- Malformed inactive risk acceptance.
- Expired active risk acceptance.

### 8.3 Separation of Duties

The governance model separates applicable requesting and approval responsibilities.

The laboratory uses synthetic identity and authority assertions.

It does not authenticate real enterprise users or establish actual organizational delegation.

### 8.4 Governance Evidence

The governance engine produces deterministic decision digests.

These support reproducible evaluation and test evidence within the laboratory.

They are not substitutes for durable enterprise approval records.

## 9. Controlled Deployment and Rollback

**Implementation:** `src/deployment/controller.py`

### 9.1 Deployment

The controller requires a trusted release reference, technical evaluation, governance authorization, and artifact verification before changing the simulated active release.

The release process includes artifact staging and verification.

Successful deployment updates active-release state and appends an audit record.

Rejected operations must not activate the requested release.

### 9.2 Rollback

Rollback is independently authorized.

A previously successful deployment does not automatically establish permission to restore that release.

The rollback process requires:

1. Identification of the recovery release.
2. Validation of registered release trust.
3. Verification of recovery snapshot integrity and applicable path restrictions.
4. Fresh technical security evaluation.
5. A new governance request for the rollback operation.
6. Validation of applicable risk acceptance.
7. Final recovery snapshot verification.
8. An authorized active-release transition.
9. An audit record for the outcome.

Expired risk acceptance is rejected.

The controller includes checks against symlinked release directories and snapshot files.

See [Verified Rollback and Recovery](docs/architecture/rollback-recovery-diagram.md).

### 9.3 Operational Limitations

The controller simulates deployment and rollback.

It does not provide crash-atomic release transactions, concurrency-safe state changes, or production incident-response automation.

Rollback is explicitly requested rather than automatically triggered by deployment failure.

## 10. Security Validation

The laboratory includes unit, integration, and adversarial tests.

### 10.1 Test Coverage Areas

| Area | Test module |
|---|---|
| Inventory schema | `tests/test_inventory_schema.py` |
| Inventory validation | `tests/test_inventory_validator.py` |
| Artifact integrity | `tests/test_artifact_integrity.py` |
| Provenance | `tests/test_provenance_verifier.py` |
| Vulnerability assessment | `tests/test_vulnerability_assessor.py` |
| Release policy | `tests/test_release_gate.py` |
| Governance | `tests/test_governance.py` |
| Governance consistency | `tests/test_governance_consistency.py` |
| Risk acceptance integration | `tests/test_risk_acceptance_integration.py` |
| Trusted release registry | `tests/test_trust_registry.py` |
| Deployment controller | `tests/test_deployment_controller.py` |
| Deployment trust enforcement | `tests/test_deployment_trust_enforcement.py` |
| Deployment hardening | `tests/test_deployment_hardening.py` |

### 10.2 Verified Regression Baseline

**242 automated tests passed.**

Latest recorded execution in the dedicated Project 8 virtual environment:

```text
Ran 242 tests in 2.344s

OK
```

The tests exercise implemented security behavior within the synthetic laboratory.

Passing tests do not constitute formal verification, complete vulnerability coverage, or production security certification.

### 10.3 Security-Control Traceability

The project maintains a dedicated security-control traceability document:

[Security Control Traceability](docs/evidence/security-control-traceability.md)

This maps defined security objectives to implementation components and supporting validation evidence.

Test coverage is limited to the behavior actually exercised by the supplied assertions.

## 11. Reproducing the Laboratory

### 11.1 Prerequisites

- Python 3.11 or a compatible Python 3 version.
- Python `venv` and `pip`.
- The project's dependencies declared in `requirements.txt`.

The laboratory does not require a production AWS account or deployed cloud infrastructure.

### 11.2 Environment Setup

Clone the repository:

```bash
git clone https://github.com/jupiter888/ai-supply-chain-secure-deployment-lab.git
cd ai-supply-chain-secure-deployment-lab
```

If another Python virtual environment is active, deactivate it:

```bash
deactivate
```

Create a dedicated environment:

```bash
python3 -m venv .venv
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

Install the project dependencies:

```bash
python -m pip install -r requirements.txt
```

Verify the environment:

```bash
which python
python -m pip show jsonschema
```

The interpreter and installed dependency should resolve inside this project's `.venv` directory.

### 11.3 Run the Regression Suite

From the repository root:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

The recorded baseline is 242 passing tests.

The suite uses synthetic inputs and local security-control implementations.

No production credentials, cloud infrastructure, or external signing services are required for the demonstrated tests.

### 11.4 Environment Isolation

Each security portfolio project should use its own virtual environment.

Before switching projects, deactivate the current environment and activate the destination project's environment.

The `.venv/` directory is excluded from Git version control.

## 12. Repository Structure

```text
ai-supply-chain-secure-deployment-lab/
├── .gitignore
├── README.md
├── requirements.txt
├── data/
│   └── synthetic/
│       └── model-manifest.json
├── docs/
│   ├── architecture/
│   │   ├── component-inventory-schema.md
│   │   ├── system-architecture.md
│   │   ├── system-security-diagram.md
│   │   ├── release-authorization-diagram.md
│   │   └── rollback-recovery-diagram.md
│   ├── evidence/
│   │   └── security-control-traceability.md
│   ├── governance/
│   │   ├── iso-42001-mapping.md
│   │   ├── nist-ai-rmf-mapping.md
│   │   └── residual-risk-register.md
│   └── threat-model/
│       ├── mitre-atlas-mapping.md
│       └── stride-threat-model.md
├── policies/
│   └── component-inventory.schema.json
├── src/
│   ├── deployment/
│   │   └── controller.py
│   ├── integrity/
│   │   └── verifier.py
│   ├── inventory/
│   │   └── validator.py
│   ├── policy/
│   │   ├── governance.py
│   │   └── release_gate.py
│   ├── provenance/
│   │   └── verifier.py
│   ├── scanning/
│   │   └── assessor.py
│   └── trust/
│       ├── __init__.py
│       └── registry.py
└── tests/
    ├── test_artifact_integrity.py
    ├── test_deployment_controller.py
    ├── test_deployment_hardening.py
    ├── test_deployment_trust_enforcement.py
    ├── test_governance.py
    ├── test_governance_consistency.py
    ├── test_inventory_schema.py
    ├── test_inventory_validator.py
    ├── test_provenance_verifier.py
    ├── test_release_gate.py
    ├── test_risk_acceptance_integration.py
    ├── test_trust_registry.py
    └── test_vulnerability_assessor.py
```

## 13. Threat Model

The architecture defines eight trust boundaries and documents 22 STRIDE threat scenarios.

The threat model addresses selected risks involving:

- Spoofed component identities.
- Malformed or deceptive manifests.
- Dependency substitution.
- Artifact tampering.
- Untrusted digest declarations.
- Forged provenance claims.
- Incomplete vulnerability evidence.
- Release-policy bypass.
- Forged governance authorization.
- Cross-component risk substitution.
- Unauthorized risk acceptance.
- Expired approval reuse.
- Unauthorized deployment.
- Compromised rollback artifacts.
- Unauthorized recovery transitions.
- Audit-evidence manipulation.
- Concurrent release-state manipulation.

The assessment distinguishes implemented mitigations, partial controls, and unresolved security gaps.

**Threat modeling documents:**

- [STRIDE Threat Model](docs/threat-model/stride-threat-model.md)
- [MITRE ATLAS Threat Mapping](docs/threat-model/mitre-atlas-mapping.md)

The MITRE ATLAS mapping identifies selected AI-relevant adversarial scenarios without claiming comprehensive technique-level coverage.

## 14. Standards and Framework Alignment

The project uses selected concepts from established AI governance and software security frameworks.

| Framework | Relevant focus | Documentation |
|---|---|---|
| NIST AI RMF 1.0 | AI risk governance and management | [NIST AI RMF Mapping](docs/governance/nist-ai-rmf-mapping.md) |
| ISO/IEC 42001:2023 | AI management-system governance and accountability | [ISO/IEC 42001 Mapping](docs/governance/iso-42001-mapping.md) |
| MITRE ATLAS | Adversarial AI threat analysis | [MITRE ATLAS Mapping](docs/threat-model/mitre-atlas-mapping.md) |
| STRIDE | Threat identification across trust boundaries | [STRIDE Threat Model](docs/threat-model/stride-threat-model.md) |
| NIST SSDF | Secure software development and supply-chain assurance | Conceptual alignment |
| SLSA | Build provenance and artifact integrity | Conceptual alignment |
| OWASP | AI and software supply-chain security | Conceptual alignment |

These are selected architectural alignments.

The laboratory does not claim ISO certification, comprehensive NIST compliance, verified SLSA levels, or full MITRE ATLAS technique coverage.

## 15. Residual Risks and Limitations

The project intentionally limits its operational scope.

| Limitation | Security implication |
|---|---|
| Synthetic identities | No independent enterprise identity authentication |
| Synthetic HMAC trust authority | Key custody is assumed rather than operationally demonstrated |
| In-memory release registry | No durable external trust-state storage |
| In-memory audit history | No independently immutable or durable audit retention |
| Local filesystem deployment | No production cloud release orchestration |
| Non-atomic state transitions | No crash-atomic deployment guarantee |
| No concurrency isolation | Concurrent release operations are not production-hardened |
| Synthetic security findings | No claim of complete live vulnerability intelligence |
| Synthetic provenance evidence | No production builder or external attestation assurance |
| Local test suite | Security assurance is limited to implemented and exercised scenarios |

The formal residual-risk register identifies ten architectural and operational risks, including trust-authority compromise, evidence durability, concurrency, vulnerability intelligence, and synthetic governance.

See [Residual Risk Register](docs/governance/residual-risk-register.md).

The register's likelihood and impact ratings concern hypothetical production adoption. They are not measured risks from a deployed production environment.

No formal organizational risk acceptance is claimed.

## 16. Engineering and Security Principles

The laboratory demonstrates several architecture principles:

**Separate claims from evidence.** A declared artifact digest, provenance statement, or approval assertion is not independently trustworthy.

**Separate technical eligibility from governance authority.** A release passing technical checks still requires applicable authorization.

**Bind decisions to exact subjects.** Authorization and risk acceptance must correspond to the evaluated release, manifest, operation, and risk scope.

**Revalidate recovery operations.** Rollback is a security-sensitive release transition, not an unconditional restoration mechanism.

**Preserve rejection invariants.** Failed security checks must not silently change active-release state.

**Document trust assumptions.** Synthetic identities, HMAC authority, and local audit evidence are not substitutes for enterprise controls.

**Validate adversarial behavior.** Security tests must include malformed inputs, inconsistent decisions, unauthorized requests, and manipulated artifacts.

**Separate technical controls from organizational assurance.** Passing security tests does not establish compliance with an AI management-system standard.

## 17. Project Status

| Workstream | Status |
|---|---|
| Component inventory registration | Implemented |
| Dependency validation | Implemented |
| Artifact integrity verification | Implemented |
| Provenance verification | Implemented |
| Vulnerability assessment | Implemented |
| Release security policy | Implemented |
| Trusted release registration | Implemented |
| Governance authorization | Implemented |
| Risk acceptance validation | Implemented |
| Controlled simulated deployment | Implemented |
| Authorized rollback | Implemented |
| Automated regression suite | 242 tests passing |
| Architecture documentation | Complete |
| Mermaid architecture diagrams | Three documented diagrams |
| Security-control traceability | Documented |
| STRIDE threat model | Documented |
| MITRE ATLAS threat mapping | Scenario-level mapping documented |
| Residual-risk register | Documented |
| NIST AI RMF mapping | Documented |
| ISO/IEC 42001 mapping | Documented |
| Production deployment | Out of scope |

---

## Security Scope Statement

This repository is an educational and portfolio security architecture laboratory.

All identities, artifacts, vulnerabilities, release records, and deployment operations are synthetic.

The implementation demonstrates selected supply-chain security controls and governance requirements through local automated tests.

This does not claim production deployment, enterprise identity assurance, regulatory certification, or comprehensive security coverage.
