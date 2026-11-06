# Project 8 — Secure Release Authorization

**Environment:** Local, offline, synthetic security laboratory  
**Scope:** Technical release evaluation and governance authorization  
**Validation:** 242 automated tests passing

## Authorization Sequence

```mermaid
sequenceDiagram
    autonumber

    actor Requester
    participant Inventory as Inventory Validator
    participant Evidence as Integrity / Provenance / Vulnerability
    participant Gate as Release Security Gate
    participant Governance as Governance Engine
    participant Registry as Trust Registry
    participant Controller as Deployment Controller
    participant Audit as Audit Records

    Requester->>Inventory: Submit component records
    Inventory->>Inventory: Validate schema and dependencies

    alt Invalid inventory
        Inventory-->>Requester: Reject registration
    else Valid inventory
        Inventory-->>Requester: Validated component inventory

        Requester->>Evidence: Supply artifacts and security evidence
        Evidence->>Evidence: Evaluate integrity, provenance, findings
        Evidence-->>Gate: Structured technical results

        Gate->>Gate: Evaluate component and aggregate policy

        alt BLOCKED
            Gate-->>Requester: Release blocked
            Note over Gate,Controller: Ordinary risk acceptance cannot override BLOCKED
        else REVIEW
            Gate-->>Governance: Review-required technical decision
            Requester->>Governance: Submit scoped authorization and risk acceptance
            Governance->>Governance: Validate roles, scope, binding, expiry

            alt Governance rejected
                Governance-->>Requester: Authorization denied
            else Governance authorized
                Governance-->>Controller: Authorized review disposition
            end
        else ELIGIBLE
            Gate-->>Governance: Eligible technical decision
            Requester->>Governance: Submit release authorization
            Governance->>Governance: Validate approval and separation of duties

            alt Governance rejected
                Governance-->>Requester: Authorization denied
            else Governance authorized
                Governance-->>Controller: Authorized release decision
            end
        end

        opt Authorized release proceeds to controller
            Controller->>Registry: Verify trusted release reference
            Registry-->>Controller: Release trust result

            Controller->>Controller: Revalidate required security evidence

            alt Trust or validation failure
                Controller-->>Requester: Deployment rejected
            else All mandatory checks pass
                Controller->>Controller: Stage and verify local artifacts
                Controller->>Controller: Update simulated active release
                Controller->>Audit: Append chained audit record
                Controller-->>Requester: Deployment result
            end
        end
    end
```

## Release Security Invariants

1. **Mandatory blocking:** A `BLOCKED` technical decision cannot be overridden through ordinary risk acceptance.
2. **Explicit review:** A `REVIEW` decision requires valid risk disposition and applicable authorization.
3. **Independent governance:** An `ELIGIBLE` decision does not independently authorize deployment.
4. **Trusted identity:** The release must satisfy trusted registration requirements.
5. **Artifact verification:** Applicable artifact references and bytes must be verified.
6. **Rejection safety:** Rejected operations must not activate the requested release.

## Implementation and Evidence

**Implementation:**

- `src/policy/release_gate.py`
- `src/policy/governance.py`
- `src/trust/registry.py`
- `src/deployment/controller.py`

**Relevant tests:**

- `tests/test_release_gate.py`
- `tests/test_governance.py`
- `tests/test_governance_consistency.py`
- `tests/test_risk_acceptance_integration.py`
- `tests/test_trust_registry.py`
- `tests/test_deployment_controller.py`
- `tests/test_deployment_trust_enforcement.py`

The diagram describes logical authorization requirements, not network communications between independently deployed services.

**Limitations:** Synthetic identities, local trust authority, simulated release transitions, and no production approval infrastructure.