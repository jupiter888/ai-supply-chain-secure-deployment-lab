# Project 8 — MITRE ATLAS Threat Mapping

**Project:** AI Supply Chain & Secure Deployment Security Lab  
**Document ID:** P8-TM-ATLAS-001  
**Framework:** MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems  
**Status:** Architecture-level adversarial threat mapping  
**Environment:** Local, offline, synthetic security laboratory  
**Validation baseline:** 242 automated tests passing  
**Framework coverage:** Selected AI-relevant attack scenarios; not exhaustive

---

## 1. Executive Summary

This document evaluates Project 8's architecture against adversarial AI security concepts represented by MITRE ATLAS.

The project implements controls for:

- AI component inventory validation.
- Artifact integrity verification.
- Provenance verification.
- Vulnerability assessment.
- Technical release-policy enforcement.
- Trusted release registration.
- Governance authorization.
- Scoped risk acceptance.
- Controlled deployment and rollback.
- Audit evidence.

These controls are relevant to protecting AI development and deployment pipelines from malicious components, compromised artifacts, untrusted provenance, and unauthorized release activity.

However, the project is not a complete AI adversarial defense platform.

Its principal focus is software supply-chain integrity and controlled release governance.

The mapping therefore distinguishes:

1. Directly relevant AI-specific attack scenarios.
2. General supply-chain threats that can affect AI systems.
3. Conventional infrastructure and identity threats.
4. AI-specific threats not exercised by the laboratory.

## 2. Mapping Methodology

### 2.1 Source Evidence

This assessment uses:

- `docs/architecture/system-architecture.md`
- `docs/architecture/component-inventory-schema.md`
- `docs/threat-model/stride-threat-model.md`
- `docs/evidence/security-control-traceability.md`
- `docs/governance/residual-risk-register.md`
- `docs/governance/nist-ai-rmf-mapping.md`
- `docs/governance/iso-42001-mapping.md`

### 2.2 Evidence Classification

| Classification | Definition |
|---|---|
| Directly relevant | The attack scenario concerns an AI-specific asset or process |
| Supporting | The control protects infrastructure or supply-chain dependencies used by AI systems |
| General security | The attack is not uniquely associated with AI |
| Implemented | Relevant mitigation exists in the laboratory |
| Tested | Relevant automated test evidence exists |
| Architectural only | The threat is documented without demonstrated mitigation |
| Out of scope | The threat is not represented by the implemented laboratory |

### 2.3 Framework Identifier Policy

This document does not assign definitive MITRE ATLAS technique identifiers.

A formal technique-level mapping requires verification against the current authoritative ATLAS technique catalog.

This avoids incorrectly attributing conventional supply-chain threats to AI-specific techniques.

The current document provides scenario-level alignment suitable for subsequent technique verification.

## 3. AI Assets and Attack Surfaces

| Asset | Attack surface | Potential adversarial objective |
|---|---|---|
| AI model artifact | Artifact storage and release pipeline | Substitute or modify model bytes |
| Model metadata | Component inventory | Misrepresent model identity or dependencies |
| Training or inference dataset | Dataset registration | Introduce untrusted data assets |
| Model provenance | Attestation inputs | Misrepresent builder, source, or artifact origin |
| Software dependencies | Package and container inventory | Introduce malicious dependencies |
| Vulnerability evidence | Assessment inputs | Conceal security weaknesses |
| Release authorization | Governance requests | Obtain unauthorized approval |
| Deployment state | Release controller | Activate an untrusted release |
| Recovery artifacts | Rollback snapshots | Restore compromised components |

The laboratory validates selected metadata, integrity, provenance, and authorization properties.

It does not execute model training or inference.

## 4. ATLAS-Relevant Threat Scenarios

### ATLAS-P8-01 — Malicious Model Artifact Substitution

**Related STRIDE threats:** P8-T04, P8-T05, P8-T14

**AI relevance:** Directly relevant when the substituted artifact is an AI model.

**Attack scenario:**

An attacker replaces an intended model artifact with unauthorized bytes and attempts to make the replacement appear legitimate through modified metadata or digest claims.

**Potential impact:**

- Unauthorized model deployment.
- Compromised model behavior.
- Loss of artifact provenance.
- Introduction of malicious model functionality.

**Implemented mitigations:**

- SHA-256 artifact verification.
- Separation of declared and trusted digests.
- Trusted release registration.
- Manifest and artifact binding.
- Release-policy enforcement.

**Evidence:**

- `test_artifact_integrity.py::test_004_modified_artifact_rejected`
- `test_artifact_integrity.py::test_017_untrusted_digest_not_used_as_reference`
- `test_deployment_trust_enforcement.py::test_002_matching_attacker_digest_rejected`
- `test_trust_registry.py::test_004_artifact_digest_substitution_rejected`

**Validation interpretation:**

The tests demonstrate selected artifact-substitution defenses.

They do not demonstrate detection of malicious behavior within an otherwise trusted model artifact.

**Residual risk:**

A malicious model introduced through a compromised trusted authority may still satisfy cryptographic integrity checks.

### ATLAS-P8-02 — Compromised Model Provenance

**Related STRIDE threats:** P8-T07, P8-T08

**AI relevance:** Directly relevant when provenance concerns AI models or their development artifacts.

**Attack scenario:**

An attacker attempts to associate an unauthorized model with a trusted builder, source, revision, or signing authority.

**Potential impact:**

- False model origin claims.
- Unauthorized model promotion.
- Compromised release trust decisions.

**Implemented mitigations:**

- Synthetic provenance signature verification.
- Trusted signing-key selection.
- Subject and digest binding.
- Builder and source policy validation.

**Evidence:**

- `test_provenance_verifier.py::test_006_forged_signature`
- `test_provenance_verifier.py::test_010_wrong_artifact_digest`
- `test_provenance_verifier.py::test_012_unauthorized_builder_with_valid_hmac`
- `test_provenance_verifier.py::test_021_valid_hmac_cannot_override_digest_policy`

**Residual risk:**

Production builder authentication and signing-key custody are not implemented.

### ATLAS-P8-03 — Malicious AI Dependency Introduction

**Related STRIDE threats:** P8-T01, P8-T03, P8-T09

**AI relevance:** Supporting AI supply-chain attack scenario.

**Attack scenario:**

An attacker introduces a malicious or vulnerable dependency into an AI application, model-serving environment, or supporting software package.

**Potential impact:**

- Compromise of the model-serving environment.
- Unauthorized code execution.
- Model artifact exposure.
- Compromise of downstream release processes.

**Implemented mitigations:**

- Component inventory validation.
- Dependency relationship validation.
- Vulnerability assessment.
- Release-policy blocking.

**Evidence:**

- `test_inventory_validator.py::test_004_missing_dependency`
- `test_inventory_validator.py::test_006_two_component_cycle`
- `test_vulnerability_assessor.py::test_002_critical_affected_denies`
- `test_release_gate.py::test_015_dependency_vulnerability_blocks_release`

**Validation interpretation:**

The laboratory demonstrates dependency consistency and selected vulnerability-policy enforcement.

It does not execute malicious dependencies or perform behavioral malware analysis.

**Residual risk:**

A malicious dependency without a recognized vulnerability finding may not be detected.

### ATLAS-P8-04 — Untrusted AI Dataset Registration

**Related STRIDE threats:** P8-T01, P8-T02

**AI relevance:** Directly relevant to AI data supply-chain governance.

**Attack scenario:**

An attacker submits a dataset component with misleading metadata or unauthorized verification-state claims.

**Potential impact:**

- Incorrect dataset trust classification.
- Unauthorized data-source promotion.
- Potential introduction of untrusted training or evaluation data.

**Implemented mitigations:**

- Strict component registration schema.
- Dataset component-type support.
- Rejection of forged security-state declarations.
- Dependency validation.

**Evidence:**

- `test_inventory_schema.py::test_007_forged_provenance_verification`
- `test_inventory_schema.py::test_009_forged_risk_acceptance`
- `test_inventory_validator.py::test_009_forged_inventory_verification`

**Validation interpretation:**

The tests demonstrate metadata validation and unauthorized state rejection.

They do not demonstrate detection of malicious dataset content.

**Residual risk:**

Data poisoning, labeling attacks, and dataset-level semantic manipulation are outside the implemented scope.

### ATLAS-P8-05 — Manipulated Security Evidence

**Related STRIDE threats:** P8-T09, P8-T10, P8-T13

**AI relevance:** Supporting attack against AI release governance.

**Attack scenario:**

An attacker submits incomplete or inconsistent vulnerability evidence to influence the technical release decision.

**Potential impact:**

- Incorrect security eligibility.
- Unreviewed vulnerabilities.
- Unauthorized release progression.

**Implemented mitigations:**

- Scan-completeness checks.
- Component coverage validation.
- Structured finding validation.
- Mandatory blocking.
- Governance consistency validation.

**Evidence:**

- `test_vulnerability_assessor.py::test_008_incomplete_scan_requires_review`
- `test_release_gate.py::test_010_missing_component_evidence_blocked`
- `test_governance_consistency.py::test_007_blocked_component_must_block_release`

**Residual risk:**

The laboratory does not independently authenticate production vulnerability scanner output.

### ATLAS-P8-06 — Unauthorized AI Model Deployment

**Related STRIDE threats:** P8-T11, P8-T14

**AI relevance:** Directly relevant when the release contains an AI model.

**Attack scenario:**

An attacker attempts to activate a model release without valid technical eligibility, trusted registration, or governance authorization.

**Potential impact:**

- Unauthorized model activation.
- Compromised AI service behavior.
- Bypass of release security requirements.

**Implemented mitigations:**

- Trusted release verification.
- Technical security evaluation.
- Governance authorization.
- Separation of duties.
- Controlled deployment.

**Evidence:**

- `test_deployment_controller.py::test_004_unauthorized_approver_blocked`
- `test_deployment_controller.py::test_005_self_approval_blocked`
- `test_deployment_trust_enforcement.py::test_001_unregistered_release_rejected`
- `test_deployment_controller.py::test_016_no_activation_after_rejection`

**Residual risk:**

The controller uses synthetic identities and does not deploy to a production AI-serving platform.

### ATLAS-P8-07 — Compromised Model Recovery

**Related STRIDE threats:** P8-T16, P8-T17, P8-T18

**AI relevance:** Supporting AI deployment lifecycle attack scenario.

**Attack scenario:**

An attacker attempts to restore an unauthorized or tampered model release through rollback.

**Potential impact:**

- Reintroduction of compromised model artifacts.
- Unauthorized recovery state.
- Bypass of current governance requirements.

**Implemented mitigations:**

- Trusted recovery-release verification.
- Snapshot integrity validation.
- Fresh technical evaluation.
- New rollback authorization.
- Expired exception rejection.

**Evidence:**

- `test_deployment_controller.py::test_012_tampered_rollback_snapshot_blocked`
- `test_deployment_hardening.py::test_003_rollback_requires_fresh_authorization`
- `test_deployment_hardening.py::test_004_expired_exception_not_implicitly_reusable`

**Residual risk:**

Production recovery orchestration and crash-atomic state transitions are not implemented.

## 5. General Security Threats Supporting AI Attacks

Several Project 8 threats are important to AI system security but are not uniquely AI-specific.

| STRIDE threat | General security concern | AI security consequence |
|---|---|---|
| P8-T05 | Digest substitution | Malicious model artifact promotion |
| P8-T11 | Approval impersonation | Unauthorized model release |
| P8-T12 | Risk acceptance substitution | Improper security exception |
| P8-T15 | Filesystem reference manipulation | Artifact or snapshot redirection |
| P8-T19 | Governance evidence manipulation | Misrepresented release authorization |
| P8-T20 | Audit evidence modification | Reduced incident accountability |
| P8-T22 | Concurrent state manipulation | Inconsistent model release state |

These threats may also be analyzed using:

- MITRE ATT&CK.
- STRIDE.
- NIST SSDF.
- Software supply-chain security practices.

They should not automatically be assigned AI-specific ATLAS technique identifiers.

## 6. AI-Specific Threats Outside Current Scope

### 6.1 Training Data Poisoning

**Status:** Not implemented.

The laboratory validates dataset registration metadata but does not inspect training data content or model training outcomes.

Potential future controls:

- Dataset provenance.
- Data quality validation.
- Poisoning detection.
- Training lineage.
- Dataset version integrity.

### 6.2 Model Poisoning and Backdoors

**Status:** Not implemented.

Artifact integrity verifies bytes relative to trusted references but does not detect malicious model behavior.

Potential future controls:

- Model behavioral evaluation.
- Backdoor testing.
- Independent model assessment.
- Model lineage verification.

### 6.3 Adversarial Examples

**Status:** Out of scope.

The laboratory does not execute inference or evaluate adversarial inputs against a model.

### 6.4 Model Extraction

**Status:** Out of scope.

The laboratory does not expose a model inference API or test extraction resistance.

### 6.5 Prompt Injection

**Status:** Out of scope.

The laboratory does not implement a generative AI prompt-processing workflow.

### 6.6 Sensitive Training Data Exposure

**Status:** Out of scope.

The laboratory does not process real training data or evaluate model memorization.

### 6.7 AI Agent Tool Abuse

**Status:** Out of scope.

The laboratory does not implement an autonomous AI agent or agent tool-execution workflow.

These threats may be addressed by separate portfolio projects.

## 7. Defense-in-Depth Mapping

| Security layer | Implemented defense | Primary adversarial concern |
|---|---|---|
| Component registration | Schema and dependency validation | Misleading or malformed component records |
| Artifact integrity | Cryptographic digest verification | Artifact substitution |
| Provenance | Synthetic attestation verification | Forged origin claims |
| Vulnerability assessment | Severity, applicability, and coverage evaluation | Concealed security findings |
| Release policy | Mandatory blocking and review | Unauthorized technical eligibility |
| Trusted registration | Authenticated release references | Unregistered artifact promotion |
| Governance | Authorization and risk acceptance | Approval and exception abuse |
| Deployment | Controlled activation | Unauthorized release transition |
| Rollback | Fresh authorization and snapshot verification | Compromised recovery |
| Audit evidence | Decision digests and audit chaining | Decision repudiation |

## 8. Adversarial Validation Evidence

The repository contains 13 automated test modules and a recorded baseline of 242 passing tests.

The suite includes selected adversarial scenarios involving:

- Modified artifacts.
- Forged digests.
- Forged attestations.
- Unknown signing keys.
- Unauthorized builders.
- Missing vulnerability evidence.
- Critical vulnerability blocking.
- Unregistered releases.
- Unauthorized approvals.
- Cross-release risk acceptance.
- Cross-component risk substitution.
- Tampered rollback snapshots.
- Expired governance exceptions.
- Symlinked release directories.

The tests support claims about the implemented control behavior.

They do not constitute comprehensive adversarial AI red-team testing.

## 9. Residual Risks

The principal residual risks are documented in:

`docs/governance/residual-risk-register.md`

Of particular relevance to AI supply-chain attacks:

- RR-02 — Trust-authority key compromise.
- RR-05 — Concurrent artifact modification.
- RR-07 — Incomplete vulnerability intelligence.
- RR-08 — Compromised provenance authority.
- RR-09 — Incomplete adversarial coverage.
- RR-10 — Synthetic organizational governance.

The current laboratory does not formally accept these risks.

## 10. Framework Coverage Assessment

### Direct AI Security Relevance

The architecture provides controls relevant to:

- AI model artifact substitution.
- AI model provenance.
- AI dataset registration.
- AI model release authorization.
- AI model recovery integrity.

### Supporting Security Relevance

The architecture also provides controls for:

- Software dependency integrity.
- Vulnerability policy enforcement.
- Governance authorization.
- Audit evidence.
- Release-state protection.

### Not Demonstrated

The laboratory does not demonstrate:

- Training data poisoning detection.
- Model backdoor detection.
- Adversarial example robustness.
- Model extraction prevention.
- Prompt injection defense.
- Model memorization assessment.
- AI agent security controls.
- Production AI runtime monitoring.

## 11. Recommended Next Steps

To strengthen the ATLAS mapping:

1. Verify relevant technique identifiers against the authoritative MITRE ATLAS catalog.
2. Review representative adversarial test assertions.
3. Document attack preconditions and attacker-controlled inputs.
4. Add explicit detection and prevention distinctions.
5. Identify potential multi-stage AI supply-chain attack paths.
6. Bind final evidence to a repository revision.
7. Review the mapping after changes to the implemented architecture.

## 12. Assurance Statement

Project 8 implements selected security controls relevant to protecting AI supply-chain and deployment processes.

The strongest demonstrated capabilities concern artifact integrity, provenance verification, release policy, governance authorization, trusted release registration, and controlled recovery.

The project does not provide comprehensive coverage of MITRE ATLAS techniques.

**ATLAS relationship:** Selected scenario-level alignment.

**Technique-level mapping:** Not yet verified.

**Implemented environment:** Synthetic laboratory.

**Automated validation:** 242 passing tests.

**Production security assurance:** Not claimed.

---

**Document status:** Initial MITRE ATLAS scenario mapping.

**Next review trigger:** Technique-catalog verification, material architecture change, or additional adversarial validation.