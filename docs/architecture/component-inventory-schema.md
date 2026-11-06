# Project 8 — AI Component Inventory Schema

**Document status:** Implemented registration contract — regression validated  
**Project:** AI Supply Chain and Secure Deployment  
**Security objective:** P8-SO01 — Component Identification  
**Primary trust boundary:** TB-01 — External Component to Local Inventory  
**Related trust boundaries:** TB-02, TB-03, TB-08

**Schema:** `policies/component-inventory.schema.json`  
**Validator:** `src/inventory/validator.py`  
**Schema version:** `1.0.0`  
**JSON Schema dialect:** Draft 2020-12

---

## 1. Purpose

This document specifies the implemented registration contract for synthetic AI supply-chain components.

The inventory supports four component classes:

1. AI models.
2. Software packages.
3. Container images.
4. Datasets.

The registration process establishes validated component records and verifies dependency-graph consistency.

It does not establish artifact integrity, authenticated provenance, vulnerability clearance, license approval, organizational risk acceptance, or deployment authorization.

The inventory is one component of the broader Project 8 security architecture.

## 2. Design Principles

### 2.1 Fail-Closed Validation

Malformed component records are rejected.

The implementation requires:

- All mandatory fields.
- Supported field types and enumerated values.
- Valid component identifiers.
- Correct SHA-256 digest syntax.
- Rejection of unexpected object properties.
- Valid dependency references.
- An acyclic dependency graph.
- Registration-only security states.

Required fields are not silently synthesized.

The validator raises `InventoryValidationError` when a registration invariant fails.

### 2.2 Separation of Claims and Verified Facts

Component records contain declared metadata.

Examples include:

- Expected artifact digests.
- Claimed publishers.
- Claimed builders.
- Claimed source revisions.
- Attestation references.
- License identifiers.

Successful schema validation establishes that these declarations satisfy the registration contract.

It does not establish their authenticity or security.

Trusted artifact, provenance, and release decisions belong to separate security subsystems.

### 2.3 Component Identity

Each component has a unique `component_id` within the validated inventory.

The validator rejects duplicate identifiers.

The schema requires a version field, allowing the inventory to represent explicitly versioned components.

The registration contract does not itself provide persistent version history or an auditable component-revision service.

Changes to an approved component identity require appropriate controls outside registration.

### 2.4 No Implicit Deployment Authorization

A valid inventory record is not a deployment approval.

Inventory validation is separate from:

- Artifact integrity verification.
- Provenance verification.
- Vulnerability assessment.
- Technical release policy.
- Trusted release registration.
- Governance authorization.
- Deployment and rollback.

No inventory field independently authorizes a release transition.

## 3. Schema Version

The implemented registration schema uses:

`1.0.0`

The schema declares:

`https://json-schema.org/draft/2020-12/schema`

The Python validator uses `jsonschema.Draft202012Validator`.

The schema is loaded from:

`policies/component-inventory.schema.json`

The validator checks the schema's validity during initialization.

The registration schema requires the component record's `schema_version` to equal `1.0.0`.

Other versions are rejected by this contract.

Future schema versions require explicit implementation and validation changes.

## 4. Canonical Inventory Record

Every component record requires the following 13 top-level fields.

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | string | Yes | Registration schema version |
| `component_id` | string | Yes | Unique component identifier |
| `component_type` | string | Yes | Component class |
| `name` | string | Yes | Human-readable component name |
| `version` | string | Yes | Component version |
| `owner` | string | Yes | Declared accountable owner |
| `source` | object | Yes | Declared component origin |
| `artifact` | object | Yes | Artifact identity and digest declaration |
| `provenance` | object | Yes | Declared production metadata |
| `license` | object | Yes | License metadata |
| `dependencies` | array | Yes | Referenced component identifiers |
| `governance` | object | Yes | Component classification and risk ownership |
| `inventory_status` | string | Yes | Initial registration status |

All required fields must be present.

Unexpected top-level properties are rejected through `additionalProperties: false`.

The nested `source`, `artifact`, `provenance`, `license`, and `governance` objects also reject unexpected properties.

The registration schema does not contain an approval field capable of authorizing deployment.

## 5. Component Types

The schema permits exactly four values:

- `model`
- `package`
- `container`
- `dataset`

### 5.1 Model

Represents a versioned AI model artifact.

Relevant threats include:

- Model substitution.
- Unauthorized weight modification.
- Malicious model packaging.
- Unverified model provenance.
- Licensing restrictions.

Registration identifies the model artifact but does not establish model safety or authenticity.

### 5.2 Package

Represents a versioned software dependency.

Relevant threats include:

- Dependency confusion.
- Vulnerable package versions.
- Package substitution.
- Compromised distribution artifacts.
- Transitive dependency exposure.

Inventory registration does not perform vulnerability scanning.

### 5.3 Container

Represents a versioned container image artifact.

Relevant threats include:

- Mutable image tags.
- Vulnerable base images.
- Unauthorized image substitution.
- Compromised build provenance.
- Excessive runtime privileges.

A container tag is not independently sufficient to establish immutable artifact identity.

### 5.4 Dataset

Represents a versioned dataset or controlled data artifact.

Relevant threats include:

- Dataset poisoning.
- Unauthorized modification.
- Unverified collection origin.
- Sensitive information exposure.
- Licensing and usage restrictions.

Registration does not perform data-content safety assessment.

## 6. Component Identity

### 6.1 Component Identifier

The `component_id` must:

- Contain between 3 and 64 characters.
- Begin with a lowercase ASCII letter.
- Contain only lowercase ASCII letters, numbers, and hyphens.
- Be unique within the submitted inventory.

The implemented pattern is:

`^[a-z][a-z0-9-]*$`

Example:

`model-research-assistant-v1`

The pattern permits trailing and consecutive hyphens; these are not separately prohibited by the current schema.

### 6.2 Name

The `name` field is a human-readable label.

Requirements:

- String type.
- Length between 1 and 160 characters.
- Contains at least one non-whitespace character.

The name is not a security identifier.

### 6.3 Version

The `version` field must:

- Be a string.
- Contain between 1 and 128 characters.
- Include at least one non-whitespace character.

Semantic versioning is not required.

Version conventions may differ between models, packages, containers, and datasets.

### 6.4 Owner

The `owner` field must:

- Be a string.
- Contain between 1 and 160 characters.
- Include at least one non-whitespace character.

The field records a declared owner.

It does not independently authenticate an organizational identity.

## 7. Source Metadata

The `source` object requires:

| Field | Type | Description |
|---|---|---|
| `source_type` | string | Declared origin category |
| `uri` | string | Declared source locator |
| `publisher` | string | Claimed publisher |

Permitted source types:

- `registry`
- `repository`
- `internal`
- `generated`

The `uri` field must be a nonempty string of no more than 2048 characters and contain at least one non-whitespace character.

The schema does not independently verify that the locator is a syntactically valid URL or that its destination exists.

The `publisher` field is a nonblank string of no more than 160 characters.

No arbitrary remote content is retrieved by the inventory validator.

Source metadata remains a declaration until evaluated by an appropriate trusted workflow.

## 8. Artifact Identity

The `artifact` object requires:

| Field | Type | Description |
|---|---|---|
| `filename` | string | Declared artifact filename |
| `media_type` | string | Declared media type |
| `digest_algorithm` | string | Supported digest algorithm |
| `expected_digest` | string | Declared artifact digest |
| `size_bytes` | integer | Declared artifact size |

### 8.1 Filename

The filename must:

- Be between 1 and 255 characters.
- Not contain `/` or `\`.

The schema treats this field as a filename rather than a filesystem path.

Additional filesystem safety checks belong to artifact-handling and deployment controls.

### 8.2 Media Type

The `media_type` field must match the schema's restricted `type/subtype` pattern.

This is structural validation, not content-type verification.

### 8.3 Digest Algorithm

The only supported registration digest algorithm is:

`sha256`

### 8.4 Expected Digest

The expected digest must match:

`^[0-9a-f]{64}$`

This requires exactly 64 lowercase hexadecimal characters.

The digest is a declaration until artifact bytes are independently evaluated against an appropriately trusted reference.

### 8.5 Artifact Size

The `size_bytes` field must be a nonnegative integer.

The inventory validator does not independently measure artifact size.

### 8.6 Security Boundary

A valid digest declaration does not establish:

- Artifact authenticity.
- Trusted provenance.
- Malware-free status.
- Vulnerability-free status.
- Deployment authorization.

These determinations require separate controls.

## 9. Provenance Metadata

The `provenance` object requires:

| Field | Type | Description |
|---|---|---|
| `claimed_builder` | string | Declared builder or producer |
| `claimed_source_revision` | string | Declared source revision |
| `attestation_reference` | string or null | Reference to supporting evidence |
| `verification_status` | string | Registration verification state |

Builder and source-revision values must be nonblank strings with lengths between 1 and 160 characters.

An attestation reference may be `null` or a nonblank string of no more than 2048 characters.

### 9.1 Registration State

The schema permits exactly:

`unverified`

A submitted record claiming `verified` or `rejected` provenance status fails registration validation.

### 9.2 Trusted Provenance Workflow

Provenance verification is implemented separately in:

`src/provenance/verifier.py`

The inventory schema does not authenticate builder identities, validate external attestation authorities, or update registration records to a trusted provenance state.

A provenance verification result must not be inferred from an inventory field.

## 10. License Metadata

The `license` object requires:

| Field | Type | Description |
|---|---|---|
| `identifier` | string | Declared license identifier |
| `review_status` | string | Initial license review state |

The license identifier must be a nonblank string between 1 and 160 characters.

The registration schema requires:

`review_status = "unreviewed"`

It rejects `approved`, `restricted`, or other supplied review states.

A license identifier is not proof of licensing compliance.

License approval and restriction decisions require an independently authorized workflow outside the registration validator.

The laboratory does not claim implementation of a complete enterprise license-review system.

## 11. Dependencies

The `dependencies` field is an array of component identifiers.

The schema enforces:

- Valid identifier syntax for every dependency.
- Unique array entries.
- A maximum of 1000 direct dependencies per component.

The Python validator additionally enforces:

- Every referenced dependency exists in the submitted inventory.
- A component does not directly depend on itself.
- The dependency graph contains no directed cycles.

### 11.1 Duplicate Component IDs

The validator rejects multiple records using the same `component_id`.

### 11.2 Missing Dependencies

A dependency reference must resolve to another registered component in the submitted inventory.

Missing references cause validation failure.

### 11.3 Self-Dependencies

A component cannot reference itself as a direct dependency.

### 11.4 Cycle Detection

The validator performs iterative depth-first traversal.

It maintains visited and active traversal states to detect dependency cycles.

The iterative approach avoids recursion-limit failures associated with recursive graph traversal on deep dependency graphs.

### 11.5 Defensive Copying

Accepted records are deep-copied before being returned in the validated inventory.

This prevents subsequent mutation of the original submitted records from directly modifying the returned inventory.

It does not establish persistent or cryptographically protected inventory storage.

## 12. Governance Metadata

The `governance` object requires:

| Field | Type | Description |
|---|---|---|
| `risk_owner` | string | Declared component risk owner |
| `criticality` | string | Component criticality |
| `data_classification` | string | Information classification |
| `risk_acceptance_status` | string | Initial risk assessment state |

### 12.1 Risk Owner

The `risk_owner` field must be a nonblank string between 1 and 160 characters.

It records a declared accountable owner.

It does not authenticate the owner or establish release-approval authority.

### 12.2 Criticality

Permitted values:

- `low`
- `medium`
- `high`
- `critical`

### 12.3 Data Classification

Permitted values:

- `public`
- `internal`
- `confidential`
- `restricted`

### 12.4 Risk Acceptance Status

The registration schema requires:

`not_assessed`

It rejects caller-supplied `accepted` or `rejected` states.

### 12.5 Release-Level Governance Boundary

Release-level risk acceptance is evaluated separately by:

`src/policy/governance.py`

That engine validates applicable authorization requirements, including release and manifest binding, review-risk scope, risk ownership, justification, expiration, and separation of duties.

The inventory's `risk_acceptance_status` field cannot independently authorize a deployment or rollback.

## 13. Inventory Status

The registration schema requires:

`inventory_status = "unverified"`

The schema rejects records that claim `verified` or `rejected` inventory status at registration.

A valid record is accepted into the validated inventory while remaining unverified.

The validator does not implement a trusted inventory-state transition service.

Any subsequent state transition would require separately implemented authority, validation, and audit controls.

## 14. Validation Layers

The implemented inventory validation consists of three logical layers.

### Layer 1 — Structural Validation

Performed using JSON Schema Draft 2020-12.

Checks include:

- Required fields.
- Supported types.
- Enumerated values.
- String constraints.
- Identifier patterns.
- SHA-256 digest syntax.
- Unexpected properties.
- Array uniqueness.
- Direct dependency-count limits.

### Layer 2 — Semantic and Graph Validation

Performed by the Python validator.

Checks include:

- Duplicate component identifiers.
- Missing dependency references.
- Direct self-dependencies.
- Dependency cycles.

### Layer 3 — Registration Security-State Validation

Enforced by the registration schema.

Required states are:

| Field | Required value |
|---|---|
| `inventory_status` | `unverified` |
| `provenance.verification_status` | `unverified` |
| `license.review_status` | `unreviewed` |
| `governance.risk_acceptance_status` | `not_assessed` |

The validator accepts records only when the applicable schema and graph checks succeed.

### 14.1 Error Handling

Invalid records raise `InventoryValidationError`.

Schema failures identify the record index, failing field location, and the selected schema-validation error.

Graph failures report the applicable duplicate identity, missing dependency, self-dependency, or cycle condition.

### 14.2 Validation Output

Successful validation returns a dictionary keyed by component identifier.

Each accepted component record is defensively copied.

The output is a validated registration inventory, not an authorized release manifest.

## 15. Security Invariants

| ID | Invariant | Enforcement |
|---|---|---|
| INV-INV01 | Invalid records are rejected | JSON Schema validation |
| INV-INV02 | Unknown fields cannot silently alter registration behavior | `additionalProperties: false` |
| INV-INV03 | Component identifiers cannot be duplicated | Python validator |
| INV-INV04 | Registration cannot establish verified provenance | Schema constant |
| INV-INV05 | Registration cannot approve a license | Schema constant |
| INV-INV06 | Registration cannot accept organizational risk | Schema constant |
| INV-INV07 | Registration cannot authorize deployment | Separation of security responsibilities |
| INV-INV08 | Dependencies must reference registered component identities | Python validator |
| INV-INV09 | Declared digests are not independently verified integrity evidence | Architectural trust boundary |
| INV-INV10 | Trusted security-state transitions require separate controls | Registration-only contract |

The invariants describe implemented registration rules and architectural boundaries.

They do not imply that every downstream trust workflow is implemented within the inventory subsystem.

## 16. Adversarial Validation

The inventory implementation has dedicated automated test modules:

- `tests/test_inventory_schema.py`
- `tests/test_inventory_validator.py`

The project-wide regression suite has passed 242 tests.

### 16.1 Registration Security Scenarios

| Test ID | Scenario | Expected result |
|---|---|---|
| P8-INV-A01 | Missing required field | Reject |
| P8-INV-A02 | Unknown component type | Reject |
| P8-INV-A03 | Invalid SHA-256 digest | Reject |
| P8-INV-A04 | Duplicate component identifier | Reject |
| P8-INV-A05 | Self-referencing dependency | Reject |
| P8-INV-A06 | Nonexistent dependency | Reject |
| P8-INV-A07 | Caller claims verified provenance | Reject |
| P8-INV-A08 | Caller claims approved license | Reject |
| P8-INV-A09 | Caller claims accepted risk | Reject |
| P8-INV-A10 | Unknown manifest field | Reject |
| P8-INV-A11 | Dependency cycle | Reject |
| P8-INV-A12 | Valid unverified component | Accept registration only |

These scenarios define the inventory's expected security behavior.

The reviewed schema and validator implement the relevant rejection mechanisms.

The exact mapping of each scenario ID to individual test assertions has not been independently reconciled in this document.

### 16.2 Regression Command

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

**Recorded result:** 242 tests passed.

A passing regression suite establishes successful execution of the implemented test cases at the recorded checkpoint.

It does not establish complete supply-chain security assurance.

## 17. Framework Alignment

### NIST AI RMF 1.0

The inventory supports component identification, risk ownership, supply-chain transparency, and risk-management inputs.

### ISO/IEC 42001:2023

The registration contract supports documented AI component information, ownership declarations, classification, and separation of governance responsibilities.

### NIST SSDF

The inventory supports software component identification and supply-chain assurance practices.

### SLSA

The artifact and provenance metadata provide inputs relevant to build provenance and artifact integrity.

Registration alone does not establish a verified SLSA provenance level.

### STRIDE

The inventory's validation rules address selected threats involving spoofed component identities, malformed metadata, unauthorized security-state claims, and dependency manipulation.

### Alignment Limitations

These are architectural mappings.

The implementation does not claim organizational compliance, certification, or satisfaction of every requirement within the referenced frameworks.

## 18. Implementation Status and Boundaries

### 18.1 Implemented Artifacts

| Artifact | Location | Status |
|---|---|---|
| Registration JSON Schema | `policies/component-inventory.schema.json` | Implemented |
| Python inventory validator | `src/inventory/validator.py` | Implemented |
| Schema tests | `tests/test_inventory_schema.py` | Present |
| Inventory validator tests | `tests/test_inventory_validator.py` | Present |

### 18.2 Implemented Controls

The inventory subsystem implements:

1. Strict JSON Schema Draft 2020-12 validation.
2. Required-field and enumerated-value enforcement.
3. Initial registration security-state restrictions.
4. Duplicate component ID rejection.
5. Dependency existence validation.
6. Self-dependency rejection.
7. Directed dependency-cycle detection.
8. Defensive copying of accepted records.
9. Explicit separation of registration from release authorization.

### 18.3 Out of Scope for Inventory Registration

The inventory validator does not perform:

- Artifact integrity verification.
- Authenticated provenance verification.
- Vulnerability assessment.
- License approval.
- Trusted risk acceptance.
- Release authorization.
- Deployment or rollback.
- Persistent inventory-state transitions.
- Production identity authentication.

These responsibilities belong to separate implemented modules or remain outside the laboratory's defined scope.

### 18.4 Residual Limitations

The registration contract validates the structure and consistency of submitted component records.

It does not independently establish the truthfulness of supplied component metadata.

The schema does not enforce a trusted component acquisition process or authenticate external publishers.

The inventory is not a production software bill of materials service or enterprise asset-management system.

---

**Implementation status:** Registration schema and validator implemented.

**Validation baseline:** Project-wide regression suite — 242 tests passing.

**Security assurance boundary:** Structural, semantic, graph, and registration-state validation only.

**Production readiness:** Not claimed.