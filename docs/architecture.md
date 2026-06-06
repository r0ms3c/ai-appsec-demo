# Architecture: AI-Powered AppSec Platform

## Overview

A DevSecOps pipeline where Claude Code acts as an intelligent security layer
across the full development lifecycle — from writing code to CI/CD.

## Vulnerable app modules

| Module | Vulnerabilities | OWASP |
|--------|----------------|-------|
| main.py | Hardcoded secrets, SSRF, debug mode, verbose errors | A02, A05, A10 |
| auth.py | MD5 passwords, JWT none algorithm, no rate limiting | A02, A07, A08 |
| db.py | SQL injection in all queries, credentials in source | A03, A02 |
| admin.py | IDOR, broken access control, mass assignment | A01, A05 |
| files.py | Path traversal, unrestricted upload, directory listing | A01, A03 |

## Claude Code layer

| Type | Name | Tools | Purpose |
|------|------|-------|---------|
| Skill | /security-audit | Read, Bash | Full OWASP Top 10 analysis |
| Skill | /stride-threat-model | Read | STRIDE methodology |
| Skill | /red-team-simulation | Read, Bash | Attacker-perspective analysis |
| Skill | /detection-engineering | Read | Sigma rules + SOC playbooks |
| Skill | /api-security-review | Read, Bash | REST-specific security review |
| Agent | appsec-reviewer | Read only | OWASP code audit |
| Agent | red-teamer | Read only | Attack scenario generator |
| Agent | threat-modeler | Read only | STRIDE + data flow analyst |
| Agent | detection-engineer | Read only | Sigma rules + playbook writer |
| Hook | secrets-scanner | PreToolUse | Blocks writes containing secrets |
| Hook | audit-logger | PostToolUse | Logs all bash commands |

## Design principles

- **Hooks enforce policy** — secrets-scanner blocks writes architecturally; cannot be bypassed
- **Read-only agents** — all analysis agents scoped to Read; cannot modify files
- **Open-source tooling** — Semgrep OSS, Bandit, pip-audit; no accounts required
- **Manual CI trigger** — full demo control; workflow_dispatch only

## Security layers

```
Developer writes code
        ↓
[Hook: secrets-scanner] — blocks secrets before they hit disk
        ↓
[Agents: parallel review] — appsec + red-teamer analyze simultaneously
        ↓
[Hook: audit-logger] — every bash command logged with risk classification
        ↓
[CI: GitHub Actions] — manual trigger runs Bandit + Semgrep + pip-audit
```
