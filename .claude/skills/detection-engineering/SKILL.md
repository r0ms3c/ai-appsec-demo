---
name: detection-engineering
description: Generate Sigma rules, detection logic, alerting thresholds, and SOC playbooks for vulnerabilities in this app. Use when the user asks for detection rules, Sigma, alerts, monitoring, or incident detection.
allowed-tools: Read
---

# Detection Engineering Skill

Generate deployable detection content for VulnBank API vulnerabilities.

## Step 1: Detection targets
For each HIGH/CRITICAL vulnerability define attacker behavior, log source, and suspicious pattern vs normal traffic.

## Step 2: Sigma rules
Generate YAML Sigma rules for: SQL injection, brute force, JWT tampering, path traversal, SSRF.

Each rule must include:
- title, id (UUID), status, description
- logsource (category + product)
- detection block with condition
- falsepositives list
- level (low/medium/high/critical)
- tags (attack.tactic + attack.TXXXX)

## Step 3: Application-level detection code
Python functions embeddable in the app for real-time detection of each attack class.

## Step 4: Alerting thresholds
| Detection | Threshold | Window | Response Action |

## Step 5: SOC analyst playbooks
5-step response for each alert:
1. Alert fires — first look
2. Triage — FP or TP?
3. Scope — how wide?
4. Contain — immediate action
5. Remediate — root cause fix

## Step 6: Detection gaps
What attacks leave no trace? What logging must be added? What baseline is needed?

## Step 7: Logging improvements
Structured security event logging code to embed in each sensitive endpoint.
