---
name: security-audit
description: Perform a comprehensive security audit of the codebase or a specific module. Use when the user asks for a security review, vulnerability scan, security assessment, or OWASP analysis of any part of the app.
allowed-tools: Read, Bash
---

# Security Audit Skill

You are performing a structured security audit. Work systematically through
every OWASP Top 10 2021 category against the target code.

## Step 1: Scope

Identify what you're auditing. If not specified, audit the entire `app/` directory.
State explicitly:
- Files in scope
- Files out of scope and why
- What vulnerability classes apply to this code type

## Step 2: Automated scan (if tools available)

Run available scanners on the target. Use these Windows-compatible commands:

```
# Bandit — Python SAST (install: pip install bandit)
bandit -r app/ -f txt

# Semgrep — pattern-based (install: pip install semgrep)
semgrep --config=p/python --config=p/owasp-top-ten app/ --text

# Dependency CVE scan (install: pip install pip-audit)
pip-audit -r app/requirements.txt
```

If a tool is not installed, skip it and note it as missing.
Summarize tool output before proceeding to manual review.

## Step 3: Manual review by OWASP category

For each category, state: ✅ Not found | ⚠️ Potential | 🔴 Confirmed

### A01 — Broken Access Control
- Are authorization checks present on every protected route?
- Is authorization checked at the resource level (not just route)?
- IDOR: are object references validated against the requesting user?
- Are admin functions properly gated?

### A02 — Cryptographic Failures
- Are secrets hardcoded in source?
- Are passwords stored with strong hashing (bcrypt/argon2)?
- Is sensitive data encrypted in transit and at rest?
- Are deprecated algorithms used (MD5, SHA1, DES)?

### A03 — Injection
- SQL: are all queries parameterized?
- Command: is user input passed to shell commands?
- Are ORM features used correctly?

### A05 — Security Misconfiguration
- Is debug mode enabled?
- Do error messages expose internals?
- Are default credentials in use?

### A06 — Vulnerable and Outdated Components
- Are dependencies pinned to known-vulnerable versions?
- Are there CVEs in the dependency tree?

### A07 — Auth and Session Failures
- Is there rate limiting on authentication endpoints?
- Are session tokens cryptographically secure?
- Do tokens expire?

### A08 — Software and Data Integrity Failures
- JWT: is algorithm pinned server-side?
- Is deserialization of untrusted data used?

### A10 — SSRF
- Does the app make outbound HTTP calls based on user input?
- Are internal network ranges blocked?

## Step 4: Finding table

Present all findings:

| # | Severity | OWASP | CWE | File | Line | Title |
|---|---|---|---|---|---|---|
| 1 | CRITICAL | A03 | CWE-89 | db.py | 47 | SQL Injection in /data/account |

## Step 5: Proof of concept

For every HIGH and CRITICAL finding, provide:
```
Attack: [HTTP request or payload]
Expected result: [what the attacker gets]
Impact: [what they can do with it]
```

## Step 6: Remediation priority

List top 5 fixes ordered by risk, with estimated effort.

## Step 7: Summary

Total findings by severity. Overall risk rating. Recommended next action.
