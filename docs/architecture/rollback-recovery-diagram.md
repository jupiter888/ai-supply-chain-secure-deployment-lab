# Project 8 — Verified Rollback and Recovery

**Environment:** Local, offline, synthetic security laboratory  
**Scope:** Trusted recovery release verification and rollback authorization  
**Validation:** 242 automated tests passing

## Recovery Sequence

```mermaid
sequenceDiagram
    autonumber

    actor Requester
    participant Controller as Deployment Controller
    participant Registry as Trust Registry
    participant Snapshot as Recovery Snapshot
    participant Gate as Technical Security Evaluation
    participant Governance as Governance Engine
    participant Active as Active Release State
    participant Audit as Audit Records

    Requester->>Controller: Request rollback to prior release

    Controller->>Registry: Validate recovery release identity and trust
    Registry-->>Controller: Trusted release verification result

    alt Untrusted recovery release
        Controller-->>Requester: Reject rollback
    else Trusted recovery release
        Controller->>Snapshot: Validate snapshot and artifact references
        Snapshot-->>Controller: Snapshot verification result

        alt Invalid or tampered snapshot
            Controller-->>Requester: Reject rollback
        else Snapshot verified
            Controller->>Gate: Re-evaluate technical security requirements
            Gate-->>Controller: BLOCKED / REVIEW / ELIGIBLE

            alt BLOCKED
                Controller-->>Requester: Reject rollback
            else REVIEW or ELIGIBLE
                Controller->>Governance: Evaluate new rollback authorization
                Governance->>Governance: Validate operation, roles, risk scope, expiry

                alt Invalid authorization or expired acceptance
                    Governance-->>Controller: Authorization rejected
                    Controller-->>Requester: Reject rollback
                else Authorized
                    Governance-->>Controller: Valid rollback authorization
                    Controller->>Snapshot: Reverify recovery snapshot
                    Snapshot-->>Controller: Final verification result

                    alt Final verification fails
                        Controller-->>Requester: Reject rollback
                    else Final verification succeeds
                        Controller->>Active: Activate verified recovery release
                        Controller->>Audit: Append chained rollback record
                        Controller-->>Requester: Rollback result
                    end
                end
            end
        end
    end
```

## Recovery Security Invariants

1. **Fresh authorization:** Previous deployment approval does not automatically authorize rollback.
2. **Trusted recovery target:** The target must match an accepted trusted release reference.
3. **Snapshot integrity:** Recovery artifacts must pass applicable integrity and path checks.
4. **Fresh technical evaluation:** Rollback requires current security evaluation.
5. **Expiration enforcement:** Expired risk acceptance cannot be reused.
6. **Rejection safety:** Failed rollback authorization must not activate the requested recovery release.

## Implementation and Evidence

**Implementation:** `src/deployment/controller.py`

**Relevant tests:**

- `tests/test_deployment_controller.py`
- `tests/test_deployment_hardening.py`
- `tests/test_deployment_trust_enforcement.py`
- `tests/test_risk_acceptance_integration.py`

## Operational Limitations

The laboratory does not implement:

- Automatic health-triggered rollback.
- Production cloud orchestration.
- Crash-atomic release transactions.
- Concurrency-safe state transitions.
- Durable external audit storage.
- Production signing-key custody.

Rollback is a simulated, explicitly requested operation subject to independent security authorization.