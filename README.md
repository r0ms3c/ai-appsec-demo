# AI-Powered AppSec Platform

> A modular DevSecOps demo showing how Claude Code acts as an intelligent security layer across the full development lifecycle — not just a code assistant.

[![Security Review](https://img.shields.io/badge/Security%20Review-Manual%20Trigger-blue?logo=github-actions)](/.github/workflows/security-review.yml)
[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](app/requirements.txt)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red)](docs/architecture.md)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skills%20%7C%20Agents%20%7C%20Hooks-orange)](https://code.claude.com)

---

## What this is

Most engineers use AI coding assistants like autocomplete with extra steps. This project demonstrates a different approach: **Claude Code as a security engineering system** — with domain-specific agents, enforced policies, and automated workflows wired into CI/CD.

Built around a deliberately vulnerable Python API (VulnBank), the platform demonstrates:

- 🔍 **Automated OWASP Top 10 auditing** via skills that encode real security runbooks
- 🤖 **Specialized subagents** scoped to read-only analysis (appsec reviewer, red teamer, threat modeler, detection engineer)
- 🔒 **Architectural enforcement via hooks** — secrets never reach disk, SAST gates block HIGH findings pre-commit
- 🔗 **MCP integrations** — Semgrep OSS, Bandit, OSV Scanner wired directly into Claude's tooling
- ⚙️ **GitHub Actions pipeline** — same security review runs in CI on manual trigger

---

## Quick start

```bash
git clone https://github.com/yourusername/ai-appsec-demo
cd ai-appsec-demo

# Start the vulnerable app
cd app && pip install -r requirements.txt && python main.py

# Open Claude Code in repo root (separate terminal)
cd .. && claude
```

Then try:
```
/security-audit          # Full OWASP audit of the app
/stride-threat-model     # STRIDE threat model
/red-team-simulation     # Attacker-perspective analysis
/detection-engineering   # Generate Sigma detection rules
```

---

## Repository structure

```
ai-appsec-demo/
├── app/                        # Vulnerable Python API (FastAPI)
│   ├── main.py                 #   SSRF, secrets in code, debug mode
│   ├── auth.py                 #   Broken auth, JWT "none" algorithm, MD5 passwords
│   ├── db.py                   #   SQL injection (all queries)
│   ├── admin.py                #   IDOR, mass assignment, broken access control
│   └── files.py                #   Path traversal, unrestricted upload
│
├── .claude/
│   ├── skills/                 # Slash commands encoding security runbooks
│   │   ├── security-audit/     #   /security-audit — full OWASP analysis
│   │   ├── stride-threat-model/#   /stride-threat-model — STRIDE methodology
│   │   ├── red-team-simulation/#   /red-team-simulation — attacker perspective
│   │   ├── detection-engineering/# /detection-engineering — Sigma rules + playbooks
│   │   └── api-security-review/#   /api-security-review — REST-specific review
│   ├── agents/                 # Specialized read-only Claude agents
│   │   ├── appsec-reviewer.md  #   OWASP-focused code audit agent
│   │   ├── red-teamer.md       #   Attack scenario generator
│   │   ├── threat-modeler.md   #   STRIDE + data flow analyst
│   │   └── detection-engineer.md # Sigma rules + SOC playbook writer
│   ├── mcp.json                # Semgrep + Bandit + OSV Scanner integration
│   └── settings.json           # Hook configuration
│
├── .github/workflows/
│   └── security-review.yml     # Manual trigger CI/CD pipeline
│
├── docs/
│   ├── architecture.md         # System design + component breakdown
│   └── demo-walkthrough.md     # Step-by-step demo script
│
└── examples/
    └── attack-scenarios.md     # Red team output examples
```

---

## The vulnerable app

VulnBank is a fictional banking REST API with intentional vulnerabilities across every OWASP Top 10 2021 category. Every vulnerability is:
- Annotated with `# VULNERABILITY:` comments explaining the flaw
- Mapped to its OWASP category and a realistic attack payload
- Designed to be findable by Claude's skills and agents

| Module | Vulnerabilities |
|--------|----------------|
| `main.py` | Hardcoded secrets, SSRF, verbose error handler, debug mode |
| `auth.py` | MD5 passwords, JWT "none" algorithm, no rate limiting, predictable reset tokens |
| `db.py` | SQL injection in every query, credentials in source |
| `admin.py` | IDOR, broken access control, mass assignment, unauthenticated debug endpoint |
| `files.py` | Path traversal, unrestricted file upload, directory listing |

> ⚠️ **Never deploy this application.** It is intentionally insecure.

---

## Claude Code setup breakdown

### Skills — encoding runbooks as slash commands

Skills live in `.claude/skills/<name>/SKILL.md`. Each has a `description` field that tells Claude when to auto-invoke it, and detailed instructions that load on demand (no context window cost until used).

```yaml
---
name: security-audit
description: Perform a comprehensive security audit. Use when the user asks for a security review, vulnerability scan, or OWASP analysis.
allowed-tools: Read, Bash
---
# Instructions follow...
```

### Agents — specialized, scoped, parallel

All four agents are `tools: Read` only — they cannot modify files. This is intentional: analysis agents should never have write access to the code they're reviewing.

```yaml
---
name: appsec-reviewer
tools: Read
color: red
---
```

Invoke in parallel for multi-perspective PR review:
```
Review auth.py using subagents — run appsec-reviewer and red-teamer in parallel
```

### Hooks — enforcement that can't be bypassed

The key distinction from CLAUDE.md instructions: **a hook that blocks a tool call cannot be reasoned around.**

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Write|Edit|MultiEdit",
      "hooks": [{ "type": "command", "command": "python3 .claude/hooks/secrets-scanner.py" }]
    }]
  }
}
```

### MCP — open-source tooling, no accounts required

Semgrep OSS, Bandit, and OSV Scanner are wired as MCP servers. The architecture is designed to swap in commercial tools (Snyk, Wiz) at the MCP layer without changing skills or agents.

---

## CI/CD pipeline

The GitHub Actions workflow runs on **manual trigger** (`workflow_dispatch`), with selectable parameters:

- **Target:** specific file or full `app/`
- **Review type:** full-audit | sast-only | dependency-check
- **Severity threshold:** low | medium | high | critical

Manual trigger is deliberate: it gives full control during live demos and avoids automatic scans that would catch every vulnerability on every push (defeating the educational purpose).

---

## Key design decisions

**Why read-only agents?** Agents that can't write files can't accidentally corrupt what they're analyzing. A security reviewer should analyze and report — never modify.

**Why hooks over CLAUDE.md for enforcement?** CLAUDE.md is context. Claude may follow it. Hooks are architecture. Claude cannot bypass them. Security-critical behavior (no secrets in source, SAST gate on commit) belongs in hooks.

**Why open-source tooling?** Anyone can clone and run this immediately. No accounts, no billing, no configuration. The MCP architecture makes it trivial to swap in commercial tools later.

**Why manual CI trigger?** Demo control. During a live presentation, you trigger the scan intentionally and walk through the results. An automatic trigger that fires on every push would normalize the vulnerabilities rather than demonstrating their detection.

---

## Learning path

New to this repo? Work through the sections in order:

1. **[Architecture](docs/architecture.md)** — understand the system design
2. **[Demo walkthrough](docs/demo-walkthrough.md)** — run each demo section
3. **[Attack scenarios](examples/attack-scenarios.md)** — see what the red-teamer generates
4. **Explore the app** — read the vulnerability annotations in `app/`
5. **Run the skills** — try each `/skill-name` in Claude Code against the app

---

## Tech stack

- **App:** Python 3.11, FastAPI, SQLite
- **SAST:** Semgrep OSS, Bandit
- **Dependency scan:** pip-audit, OSV Scanner
- **AI layer:** Claude Code with skills, agents, hooks, and MCP
- **CI/CD:** GitHub Actions (manual trigger)

---

## About

Built as a learning project and portfolio piece demonstrating how Claude Code fits into a professional security engineering workflow. Every design decision reflects real security engineering judgment — not AI hype.

Feedback and connections welcome on [LinkedIn](#).

---

*⚠️ This repository contains intentionally vulnerable code for educational purposes. Never deploy the application in any real environment.*
