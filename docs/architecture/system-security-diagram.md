# Project 8 — System Security Architecture

**Environment:** Local, offline, synthetic security laboratory  
**Scope:** AI supply-chain evaluation, governance, and simulated deployment  
**Validation:** 242 automated tests passing

## Architecture Diagram

```mermaid
flowchart TB
    subgraph INPUT["UNTRUSTED SUPPLY-CHAIN INPUTS"]
        MAN["Component Manifest"]
        ART["Artifact Bytes"]
        PROV["Provenance Evidence"]
        VULN["Vulnerability Findings"]
    end

    subgraph EVAL["TECHNICAL SECURITY EVALUATION"]
        INV["Inventory Validator"]
        INT["Artifact Integrity Verifier"]
        PV["Provenance Verifier"]
        VA["Vulnerability Assessor"]
        GATE{"Release Security Gate"}
    end

    subgraph TRUST["TRUSTED RELEASE REFERENCES"]
        REG["Synthetic HMAC Trust Registry"]
    end

    subgraph GOV["GOVERNANCE AUTHORIZATION"]
        REQ["Release / Rollback Request"]
        AUTH["Governance Engine"]
        RISK["Scoped Risk Acceptance"]
    end

    subgraph EXEC["SIMULATED RELEASE CONTROL"]
        CTRL["Deployment Controller"]
        STAGE["Local Artifact Staging"]
        ACTIVE["Active Release State"]
        SNAP["Recovery Snapshot"]
        AUDIT["In-Memory Chained Audit Records"]
    end

    MAN -->|"TB-01: registration"| INV
    ART -->|"TB-02: artifact integrity"| INT
    PROV -->|"TB-03: provenance"| PV
    VULN -->|"TB-04: assessment"| VA

    INV --> GATE
    INT --> GATE
    PV --> GATE
    VA --> GATE

    GATE -->|"TB-05: technical decision"| AUTH
    REQ --> AUTH
    RISK --> AUTH

    REG -->|"Trusted release binding"| CTRL
    AUTH -->|"Authorized operation"| CTRL
    GATE -->|"Technical decision"| CTRL
    ART -->|"Artifact verification"| CTRL

    CTRL -->|"TB-06: deploy"| STAGE
    STAGE --> ACTIVE
    CTRL -->|"TB-07: recovery"| SNAP
    SNAP --> ACTIVE

    CTRL -->|"TB-08: evidence"| AUDIT
    AUTH -->|"Decision digest"| AUDIT

    classDef untrusted fill:#252525,stroke:#ef7777,color:#ffffff
    classDef security fill:#111b24,stroke:#79c7f2,color:#ffffff
    classDef governance fill:#19231e,stroke:#9bddb0,color:#ffffff
    classDef execution fill:#202020,stroke:#dedede,color:#ffffff

    class MAN,ART,PROV,VULN untrusted
    class INV,INT,PV,VA,GATE,REG security
    class REQ,AUTH,RISK governance
    class CTRL,STAGE,ACTIVE,SNAP,AUDIT execution
```

## Trust Boundaries

| Boundary | Description |
|---|---|
| TB-01 | External component records enter inventory validation |
| TB-02 | Artifact bytes and digest claims enter integrity verification |
| TB-03 | Provenance assertions enter provenance evaluation |
| TB-04 | Vulnerability findings enter technical policy evaluation |
| TB-05 | Technical security decisions enter governance authorization |
| TB-06 | Authorized release requests enter deployment control |
| TB-07 | Recovery requests enter rollback processing |
| TB-08 | Operational outcomes contribute to audit evidence |

## Security Interpretation

The architecture separates technical evaluation, governance authorization, and deployment authority.

A caller-supplied artifact digest or manifest does not independently establish release trust. The synthetic trust registry provides authenticated release references that are verified during deployment operations.

The diagram groups related security responsibilities logically; it does not imply that every component is an independently deployed service.

**Implementation:** `src/inventory/`, `src/integrity/`, `src/provenance/`, `src/scanning/`, `src/policy/`, `src/trust/`, and `src/deployment/`.

**Limitations:** No production cloud infrastructure, enterprise identity authentication, external signing authority, or durable audit storage.