# Demo Walkthrough

Step-by-step script for demonstrating the platform live.
Each section is a self-contained demo you can run independently.

---

## Setup (once)

```bash
cd app/
pip install -r requirements.txt
python main.py &   # starts on http://localhost:8000
```

Open Claude Code in the repo root:
```bash
claude
```

---

## Demo 1: Automated Security Audit (3 minutes)

**What it shows:** Claude reads the entire codebase and maps vulnerabilities to OWASP.

In Claude Code:
```
/security-audit
```

**What to highlight:**
- Claude reads all 5 app modules automatically
- Findings are mapped to OWASP Top 10 + CWE IDs
- Each finding includes a proof-of-concept payload
- Severity ratings drive prioritization

**Expected output:** 15–20 findings across all OWASP categories.

---

## Demo 2: STRIDE Threat Model (4 minutes)

**What it shows:** Claude produces a full threat model from source code alone.

```
/stride-threat-model
```

**What to highlight:**
- Trust boundary identification (client → API → DB)
- STRIDE categories applied to each component
- Attack chain narratives (multi-step exploitation)
- Mitigation recommendations tied to specific threats

---

## Demo 3: Red Team Simulation (3 minutes)

**What it shows:** Claude switches to attacker perspective and generates working exploit code.

```
/red-team-simulation
```

**What to highlight:**
- Complete kill chain from unauthenticated to full compromise
- Working Python exploit scripts (don't run live — show the code)
- SSRF → AWS metadata exfil scenario
- SQL injection → credential dump chain

---

## Demo 4: Live Hook Enforcement (2 minutes)

**What it shows:** Claude's hooks block bad changes architecturally — not via instructions.

Ask Claude to add a "feature":
```
Add a debug logging statement that logs the JWT secret for troubleshooting
```

**What to highlight:**
- The `secrets-scanner` hook fires before the file is written
- Claude receives the finding and corrects course automatically
- The secret never touches the filesystem
- This is architecture-level enforcement, not prompt-level

---

## Demo 5: Subagent Parallel Review (3 minutes)

**What it shows:** Multiple specialized agents reviewing simultaneously.

```
Review auth.py and db.py using subagents — run appsec-reviewer and red-teamer in parallel
```

**What to highlight:**
- Two agents with different perspectives run on the same code
- appsec-reviewer focuses on defenses and fixes
- red-teamer focuses on exploitation paths
- Both return to the main session with their findings
- Context isolation — neither agent sees the other's work mid-session

---

## Demo 6: Detection Engineering (3 minutes)

**What it shows:** Claude generates deployable Sigma rules from vulnerabilities.

```
/detection-engineering
```

**What to highlight:**
- Sigma rules for each attack class (SQLi, brute force, path traversal, SSRF)
- Application-level detection code that can be embedded immediately
- SOC analyst playbooks with 5-step response procedures
- Detection gap analysis — what isn't covered and why

---

## Demo 7: GitHub Actions CI/CD (2 minutes)

**What it shows:** The same security review runs in CI on manual trigger.

Go to GitHub → Actions → "AI Security Review" → Run workflow

Select:
- Target: `app/`
- Review type: `full-audit`
- Severity threshold: `medium`

**What to highlight:**
- Manual trigger = demo control + no surprise CI costs
- Bandit + Semgrep run in parallel jobs
- Results appear in GitHub Actions summary
- Artifacts (JSON results) available for download
- Same tools as local, same findings — consistency across environments

---

## Talking points for each demo

**On Claude Code vs chatbot:**
> "Most people use Claude like autocomplete with extra steps. This setup uses it as a security system — skills encode the runbooks, agents enforce read-only analysis, hooks enforce policy architecturally. The difference is that Claude can't be talked out of blocking a secret write — the hook doesn't understand excuses."

**On the vulnerable app:**
> "Every vulnerability is annotated with its OWASP category and a comment explaining the attack. This is intentional — the app is a teaching artifact as much as a scan target. The SQL injection in db.py isn't subtle; it's there so Claude can find it reliably and explain it clearly."

**On open-source tooling:**
> "Everything here runs without an account. Semgrep OSS, bandit, pip-audit, osv-scanner — all free. The architecture is designed to swap in Snyk or other commercial tools at the MCP layer without changing anything else."

**On the portfolio angle:**
> "This repo demonstrates security engineering judgment, not just tool usage. The skill definitions encode real runbooks. The agent scopes reflect real threat modeling. The hook design reflects real policy-as-code thinking."
