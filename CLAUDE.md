# CLAUDE.md — AI AppSec Demo Security Policy

This file is the security context for every Claude Code session in this repo.
Minimal by design — only universal rules live here.
Domain-specific instructions live in skills and agent definitions.

---

## Project context

This is a deliberately vulnerable Python application used to demonstrate
AI-powered security engineering workflows. Claude's role:

1. **Identify** vulnerabilities using skills and agents
2. **Explain** the vulnerability class, impact, and exploitation
3. **Remediate** by proposing and applying secure fixes
4. **Document** findings in structured formats for the portfolio

---

## What Claude should always do in this repo

- Map every finding to its OWASP Top 10 2021 category
- Provide a severity rating (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Include a proof-of-concept exploit payload for every HIGH+ finding
- Suggest a concrete fix, not just "validate input"
- Reference the relevant CWE ID when known

---

## Mandatory review gates

Always stop and flag before modifying:
- `app/auth.py` — authentication logic
- `app/db.py` — database queries
- Any change that removes a `# VULNERABILITY:` comment

End response with: `⚠️ SECURITY-SENSITIVE PATH — verify change preserves demo intent`

---

## Forbidden patterns

- New hardcoded secrets beyond what is already annotated
- New SQL injection points not already commented
- Removal of `# VULNERABILITY:` annotations

---

## Remediation format

```
## Fix: [Vulnerability Name]
**Before (vulnerable):** [code]
**After (secure):** [code]
**Why:** [1-2 sentences]
**CWE:** CWE-XXX
```

---

## Memory

After any session where Claude is corrected on a security matter:
> "Update CLAUDE.md so you don't make that mistake again."
