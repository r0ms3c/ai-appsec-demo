---
name: stride-threat-model
description: Perform a STRIDE threat model on a component, feature, or the full application. Use when the user asks for threat modeling, attack surface analysis, or security design review.
allowed-tools: Read
---

# STRIDE Threat Modeling Skill

Perform a structured STRIDE threat model. If no specific component is given, model the full VulnBank API.

## Step 1: System decomposition
Read the relevant source files, then identify components, entry points, assets, and trust boundaries.

## Step 2: Data flow diagram (text)
Draw the flow as numbered steps marking trust boundaries explicitly:
```
[Client] → [HTTP Request] → [FastAPI Router]
                         --- TRUST BOUNDARY ---
                         [Auth Check] → [Business Logic] → [SQLite DB]
```

## Step 3: STRIDE analysis
For each trust boundary and entry point analyze:
- **S** — Spoofing: can an attacker impersonate a user or service?
- **T** — Tampering: can data be modified without authorization?
- **R** — Repudiation: can actions be denied? Is audit logging present?
- **I** — Information Disclosure: can unauthorized data be accessed?
- **D** — Denial of Service: can availability be degraded?
- **E** — Elevation of Privilege: is there a path from low to high privilege?

## Step 4: Threat table
| ID | Component | STRIDE | Threat | Likelihood | Impact | Risk | Control |

## Step 5: Attack chains
Top 3 realistic multi-step attack scenarios with preconditions and impact.

## Step 6: Mitigations
For each CRITICAL/HIGH threat: control, effort level, design change required?

## Step 7: Residual risk
What risks remain after mitigations and what monitoring should detect exploitation?
