# API Security Review — VulnBank API

**Date:** 2026-06-06
**Reviewer:** r0ms3c + Claude Code
**Branch:** `main`

---

## Step 1: Endpoint Inventory

| Method | Path | Auth Required | Input Parameters | Returns |
|---|---|---|---|---|
| POST | `/auth/login` | None | `username` (body), `password` (body) | `access_token`, `token_type` |
| POST | `/auth/forgot-password` | None | `username` (query) | `reset_token`, hint string |
| POST | `/auth/reset-password` | None | `username`, `token`, `new_password` (all query) | success message |
| GET | `/auth/me` | Bearer JWT | — | JWT payload |
| GET | `/data/account` | Bearer JWT | `owner` (query) | account rows |
| GET | `/data/search` | Bearer JWT | `note` (query) | transaction rows |
| POST | `/data/transfer` | Bearer JWT | `from_account`, `to_account`, `amount`, `note` (body) | success message |
| GET | `/admin/user/{user_id}` | Bearer JWT | `user_id` (path) | user record + password hash |
| PUT | `/admin/user/{user_id}` | Bearer JWT | `user_id` (path), `username`, `role`, `password` (body) | updated user record |
| DELETE | `/admin/user/{user_id}` | `X-Admin-Key` header | `user_id` (path) | success message |
| GET | `/admin/panel` | Bearer JWT (role=admin) | — | full USERS_DB |
| GET | `/admin/debug/tokens` | **None** | — | signed JWTs for every user |
| GET | `/files/download` | Bearer JWT | `filename` (query) | file content |
| POST | `/files/upload` | Bearer JWT | `file` (multipart) | path, filename, size |
| GET | `/files/list` | Bearer JWT | — | all files from all users |
| DELETE | `/files/delete` | Bearer JWT | `filename` (query) | success message |
| GET | `/fetch` | **None** | `url` (query) | HTTP response body from target |
| GET | `/health` | **None** | — | status, SECRET_KEY, all env vars |
| GET | `/` | None | — | welcome message |

**Unauthenticated endpoints of concern:** `/auth/forgot-password`, `/auth/reset-password`, `/admin/debug/tokens`, `/fetch`, `/health`

---

## Step 2: Authentication Review

### JWT Implementation (`auth.py`)

| Check | Status | Detail |
|---|---|---|
| Algorithm pinned server-side | **FAIL** | `algorithms=None` — accepts any alg the token declares, including `"none"` (`auth.py:113`) |
| Expiry enforced | **FAIL** | No `exp` claim in issued tokens (`auth.py:87-91`); `verify_exp: False` in decode (`auth.py:114`) |
| Secret strength | **FAIL** | `JWT_SECRET = "secret"` — 6 characters, trivially brute-forceable offline (`auth.py:22`) |
| Secret from environment | **FAIL** | Hardcoded in source; duplicated as `SECRET_KEY = "super_secret_key_123"` in `main.py:35` |
| Signature verification | **FAIL** | `alg=none` header bypasses HMAC entirely — no signature is checked |
| Token revocation | **FAIL** | No blocklist, no session store; tokens are unrevocable once issued |
| Secure transmission | **UNKNOWN** | No TLS enforcement in code; uvicorn launched without SSL config |

### Password Storage

| Check | Status | Detail |
|---|---|---|
| Algorithm | **FAIL** | MD5 — a general-purpose hash with no work factor (`auth.py:29, 81, 162`) |
| Salting | **FAIL** | No per-user salt; identical passwords produce identical hashes |
| Admin hash | **FAIL** | `md5("admin123")` = `0192023a7bbd73250516f069df18b500` — cracks instantly via rainbow table |

### Rate Limiting on Auth Endpoints

| Endpoint | Rate Limit | Status |
|---|---|---|
| `POST /auth/login` | Dead code — threshold `> 1000`, body is `pass` (`auth.py:71-72`) | **FAIL** |
| `POST /auth/forgot-password` | None | **FAIL** |
| `POST /auth/reset-password` | None | **FAIL** |
| All other endpoints | None | **FAIL** |

### Token Forge / Steal Vectors

1. **`alg=none` forgery** — `jwt.decode(algorithms=None)` accepts unsigned tokens with any payload (`auth.py:110-113`)
2. **Offline brute-force** — secret `"secret"` cracks in milliseconds with hashcat against any captured token
3. **`GET /admin/debug/tokens`** — returns valid, properly signed JWTs for every user with zero authentication
4. **`GET /health`** — returns `SECRET_KEY` to any unauthenticated caller; allows offline token signing
5. **Path traversal** — `GET /files/download?filename=../../app/auth.py` reads source; exposes `JWT_SECRET`
6. **Predictable reset token** — `MD5(username + floor(unix_ts/60))` brute-forced in < 60s per target account

---

## Step 3: Authorization Matrix

| Endpoint | Unauth | User | Admin | Issue |
|---|---|---|---|---|
| `POST /auth/login` | ✅ Open | ✅ Open | ✅ Open | — |
| `POST /auth/forgot-password` | ✅ Open | ✅ Open | ✅ Open | Reset token returned in response |
| `POST /auth/reset-password` | ✅ Open | ✅ Open | ✅ Open | Predictable token; no complexity check |
| `GET /auth/me` | 401 | ✅ Own data | ✅ Own data | — |
| `GET /data/account` | 401 | 🔴 ANY owner | 🔴 ANY owner | No ownership check; SQL injectable |
| `GET /data/search` | 401 | 🔴 ALL transactions | 🔴 ALL transactions | No ownership filter; SQL injectable |
| `POST /data/transfer` | 401 | 🔴 ANY account | 🔴 ANY account | No ownership check on `from_account` |
| `GET /admin/user/{id}` | 401 | 🔴 ANY user + hash | ✅ Intended | IDOR — no ownership check |
| `PUT /admin/user/{id}` | 401 | 🔴 ANY user + role | ✅ Intended | IDOR + mass assignment |
| `DELETE /admin/user/{id}` | 🔴 Static key | 🔴 Static key | 🔴 Static key | Hardcoded key in source |
| `GET /admin/panel` | 401 | 🔴 JWT forgeable | ✅ Intended | `alg=none` + mass assignment bypass |
| `GET /admin/debug/tokens` | 🔴 Full access | 🔴 Full access | 🔴 Full access | No auth — returns admin JWT |
| `GET /files/download` | 401 | 🔴 ANY file + traversal | 🔴 ANY file | No ownership; path traversal |
| `POST /files/upload` | 401 | 🔴 Unrestricted write | 🔴 Unrestricted write | No type/size check; path traversal |
| `GET /files/list` | 401 | 🔴 ALL users' files | 🔴 ALL users' files | No owner filter |
| `DELETE /files/delete` | 401 | 🔴 ANY file | 🔴 ANY file | No ownership check |
| `GET /fetch` | 🔴 SSRF | 🔴 SSRF | 🔴 SSRF | No auth; no URL validation |
| `GET /health` | 🔴 Dumps secrets | 🔴 Dumps secrets | 🔴 Dumps secrets | No auth; SECRET_KEY + all env vars |
| `GET /` | ✅ Open | ✅ Open | ✅ Open | — |

**Legend:** ✅ Correct behavior | 🔴 Authorization violation

**Summary:** 14 of 19 endpoints have authorization violations. Every data-access endpoint fails the ownership check. Two endpoints (`/admin/debug/tokens`, `/fetch`) are fully open with no authentication and return critical data or enable SSRF.

---

## Step 4: Input Validation Audit

| Endpoint | Parameter | Type Validated | Length Validated | Dangerous Context | Status |
|---|---|---|---|---|---|
| `POST /auth/login` | `username` | ✅ str (Pydantic) | ❌ None | Dict lookup | ⚠️ No length limit |
| `POST /auth/login` | `password` | ✅ str (Pydantic) | ❌ None | MD5 input | ⚠️ No length limit |
| `POST /auth/forgot-password` | `username` | ✅ str (query) | ❌ None | Dict lookup + MD5 | ⚠️ No length limit |
| `POST /auth/reset-password` | `token` | ✅ str (query) | ❌ None | MD5 comparison | ⚠️ No length limit |
| `POST /auth/reset-password` | `new_password` | ✅ str (query) | ❌ None | MD5 storage | ⚠️ No complexity check |
| `GET /data/account` | `owner` | ✅ str (query) | ❌ None | 🔴 SQL f-string | **CRITICAL — SQLi** |
| `GET /data/search` | `note` | ✅ str (query) | ❌ None | 🔴 SQL LIKE f-string | **CRITICAL — SQLi** |
| `POST /data/transfer` | `from_account` | ✅ int (Pydantic) | N/A | 🔴 SQL f-string | **CRITICAL — SQLi** |
| `POST /data/transfer` | `to_account` | ✅ int (Pydantic) | N/A | 🔴 SQL f-string | **CRITICAL — SQLi** |
| `POST /data/transfer` | `amount` | ✅ float (Pydantic) | N/A | 🔴 SQL f-string | **CRITICAL — SQLi** |
| `POST /data/transfer` | `note` | ✅ str (Pydantic) | ❌ None | 🔴 SQL f-string | **CRITICAL — SQLi** |
| `GET /admin/user/{user_id}` | `user_id` | ✅ int (path) | N/A | Dict lookup | ⚠️ IDOR |
| `PUT /admin/user/{user_id}` | `user_id` | ✅ int (path) | N/A | Dict lookup | ⚠️ IDOR |
| `PUT /admin/user/{user_id}` | `role` | ✅ str (Optional) | ❌ None | Direct role assignment | 🔴 **Mass assignment** |
| `PUT /admin/user/{user_id}` | `password` | ✅ str (Optional) | ❌ None | MD5 storage | ⚠️ No complexity |
| `DELETE /admin/user/{user_id}` | `user_id` | ✅ int (path) | N/A | Dict lookup | ⚠️ No auth |
| `GET /files/download` | `filename` | ✅ str (query) | ❌ None | 🔴 `os.path.join` → FS | **CRITICAL — Path traversal** |
| `POST /files/upload` | `file.filename` | ❌ None | ❌ None | 🔴 `os.path.join` → FS | **CRITICAL — Path traversal + unrestricted upload** |
| `DELETE /files/delete` | `filename` | ✅ str (query) | ❌ None | 🔴 `os.path.join` → FS | **CRITICAL — Path traversal** |
| `GET /fetch` | `url` | ✅ str (query) | ❌ None | 🔴 `requests.get(url)` | **CRITICAL — SSRF** |

**Key finding:** Pydantic validates types at the model boundary, but zero parameters are validated for length, content, or allowlist before being passed into dangerous contexts (SQL, filesystem, network). Type safety is present; semantic safety is absent everywhere.

---

## Step 5: API-Specific Vulnerabilities

### Mass Assignment

**Location:** `PUT /admin/user/{user_id}` (`admin.py:67-91`)

```python
class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None       # user should NEVER be able to set this
    password: Optional[str] = None
```

The `role` field is writable by any authenticated user, including on their own account. A user submitting `{"role": "admin"}` promotes themselves to admin in a single request. No server-side validation strips or rejects the `role` field for non-admin callers.

**Exploit:**
```http
PUT /admin/user/2
Authorization: Bearer <alice_jwt>
Content-Type: application/json

{"role": "admin"}
```

**Response:**
```json
{"message": "User alice updated", "new_data": {"role": "admin", ...}}
```

---

### BOLA / IDOR

Four distinct IDOR vulnerabilities, all stemming from the same root cause — no ownership assertion after authentication:

| Endpoint | Object | Missing Check |
|---|---|---|
| `GET /admin/user/{user_id}` | User record | `current_user["id"] != user_id AND role != "admin"` |
| `PUT /admin/user/{user_id}` | User record | Same as above |
| `POST /data/transfer` | Bank account | `account.owner == current_user["sub"]` |
| `DELETE /files/delete` | Uploaded file | File owner tracking entirely absent |

The `/admin/user/{user_id}` IDOR is particularly severe because the response includes `password_hash` — exposing MD5 hashes that crack instantly via rainbow tables.

**Exploit:**
```http
GET /admin/user/1
Authorization: Bearer <alice_jwt>

→ {"id":1,"username":"admin","role":"admin","password_hash":"0192023a7bbd73250516f069df18b500"}
```

---

### Excessive Data Exposure

| Endpoint | Exposed Fields | Should Return |
|---|---|---|
| `GET /admin/user/{user_id}` | `id`, `username`, `role`, **`password_hash`** | `id`, `username`, `role` |
| `GET /admin/panel` | Full `USERS_DB` including all **`password_hash`** values | Sanitized user list without hashes |
| `GET /auth/forgot-password` | **`reset_token`**, **`hint` (algorithm disclosure)** | Nothing — send token via email only |
| `GET /health` | **`secret_key`**, **`dict(os.environ)`** | `{"status":"ok"}` |
| HTTP 500 responses | **`traceback`**, **`internal_path`**, **`db_password`** | `{"error":"Internal server error"}` |
| `GET /files/download` (404) | **Full server file path** in error detail | Generic 404 message |
| `GET /files/list` | **Server-side `path`** for every file | Filename and size only |
| `GET /data/account` (404) | **Raw SQL query string** | Generic not-found message |
| `GET /data/search` (error) | **Raw SQL query string** | Generic error message |
| `POST /files/upload` | **`path`** (server filesystem path) | Filename and size only |

---

### Missing Rate Limits

Every endpoint in the application has no rate limiting. The highest-impact absences:

| Endpoint | Attack Enabled | Risk |
|---|---|---|
| `POST /auth/login` | Unlimited password brute-force | CRITICAL |
| `POST /auth/forgot-password` | Account enumeration + reset token timing attack | HIGH |
| `POST /auth/reset-password` | Brute-force of predictable 32-bit MD5 token space | HIGH |
| `GET /fetch` | SSRF amplification / DDoS using server as proxy | HIGH |
| `GET /data/account` | SQL injection probing with no detection or throttle | HIGH |
| `GET /admin/debug/tokens` | Repeated unauthenticated token generation | HIGH |

> The dead rate-limiting code in `auth.py:69-72` is a particularly misleading false safeguard — the threshold is set to `> 1000` and the body is `pass`, so it never blocks anything regardless of attempt count.

---

## Step 6: Error Handling

### Global Exception Handler (`main.py:55-67`)

```python
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "traceback": traceback.format_exc(),   # full Python stack trace
            "internal_path": os.getcwd(),           # server working directory
            "db_password": DB_PASSWORD,             # literal database password
        }
    )
```

Every unhandled exception returns four sensitive values in a public HTTP response. An attacker who triggers any 500 error — via SQL injection, a malformed request, or any application bug — receives the database password for free alongside the full stack trace.

### Per-Endpoint Error Exposure

| Location | Error Content Exposed | Severity |
|---|---|---|
| `main.py:59-66` | `traceback`, `os.getcwd()`, `DB_PASSWORD` | CRITICAL |
| `db.py:93-95` | Raw SQL query: `f"No account found. Query was: {query}"` | HIGH |
| `db.py:117` | `{"error": str(e), "query": query}` — DB error + raw SQL string | HIGH |
| `files.py:44-47` | `f"File not found: {file_path}"` — full server filesystem path | MEDIUM |
| `auth.py:117-118` | `f"Invalid token: {e}"` — JWT library error message | LOW |

### FastAPI Debug Mode

`debug=True` in `main.py:43` enables the Starlette interactive debugger in development mode. This serves HTML error pages with full stack traces and allows frame inspection via browser — a complete source code disclosure mechanism available to any caller who triggers an error.

---

## Step 7: HTTP Security Headers

FastAPI does not set security headers by default. None of the following are configured in the application:

| Header | Status | Impact of Absence |
|---|---|---|
| `Content-Security-Policy` | ❌ Missing | XSS payloads execute on `/docs` and `/redoc` Swagger pages |
| `X-Content-Type-Options: nosniff` | ❌ Missing | Browser MIME-sniffs uploaded files — uploaded HTML/JS served as scripts; enables stored XSS via file upload |
| `X-Frame-Options: DENY` | ❌ Missing | API responses and Swagger UI can be framed; enables clickjacking |
| `Strict-Transport-Security` | ❌ Missing | Clients not forced to HTTPS; Bearer tokens transmitted over plain HTTP are interceptable |
| `Cache-Control: no-store` | ❌ Missing | Auth tokens and sensitive responses cached by proxies and browsers |
| `Referrer-Policy` | ❌ Missing | Bearer tokens passed as URL parameters leak via `Referer` header to third parties |
| `Permissions-Policy` | ❌ Missing | Browser features unrestricted on API documentation pages |

**Most critical missing header:** `X-Content-Type-Options: nosniff` — without it, the unrestricted file upload vulnerability (`files.py:60-84`) becomes a stored XSS vector when uploaded HTML or SVG files are served inline.

**Swagger UI:** FastAPI auto-generates `/docs` and `/redoc` with no authentication. The full interactive API schema — every endpoint, parameter, model, and example — is publicly accessible to any visitor.

---

## Step 8: Remediation Summary

| # | Endpoint | Issue | Severity | Fix |
|---|---|---|---|---|
| 1 | All auth | JWT `alg=none` accepted — full auth bypass | CRITICAL | `algorithms=["HS256"]` in `jwt.decode()`; upgrade to `PyJWT>=2.4.0` |
| 2 | `GET /admin/debug/tokens` | No auth — returns signed JWTs for all users | CRITICAL | Remove endpoint entirely |
| 3 | `GET /data/account` | SQL injection via `owner` f-string | CRITICAL | `db.execute("... WHERE owner = ?", (owner,))` |
| 4 | `GET /data/search` | SQL injection via `note` LIKE clause | CRITICAL | `db.execute("... LIKE ?", (f"%{note}%",))` |
| 5 | `POST /data/transfer` | SQL injection on 3 fields + no ownership check | CRITICAL | Parameterize all fields; assert `account.owner == current_user["sub"]` |
| 6 | `GET /fetch` | SSRF — arbitrary outbound HTTP, unauthenticated | CRITICAL | Require auth; allowlist `https` only; block RFC-1918 + `169.254/16` |
| 7 | `GET /files/download` | Path traversal — arbitrary file read | CRITICAL | `Path(UPLOAD_DIR).resolve() / Path(fn).name` + prefix assert |
| 8 | `GET /health` | Returns `SECRET_KEY` + all env vars with no auth | CRITICAL | Return `{"status":"ok","version":"1.0.0"}` only |
| 9 | Global 500 handler | Returns `DB_PASSWORD`, traceback, `os.getcwd()` | CRITICAL | `{"error":"Internal server error"}`; log details server-side only |
| 10 | `GET /admin/user/{id}` | IDOR — any user reads any user's password hash | HIGH | Ownership + role check; strip `password_hash` from response |
| 11 | `PUT /admin/user/{id}` | IDOR + mass assignment — any user sets own role=admin | HIGH | Ownership check; remove `role` from `UpdateUserRequest` |
| 12 | `POST /data/transfer` | No ownership check on source account | HIGH | Assert `from_account.owner == current_user["sub"]` before debit |
| 13 | `GET /admin/panel` | Role bypassed via JWT forgery; exposes all password hashes | HIGH | Fix JWT (item 1); strip `password_hash` from response |
| 14 | `POST /auth/login` | No rate limiting — unlimited brute force | HIGH | `slowapi`: 5 attempts/min/IP with exponential backoff |
| 15 | `POST /auth/login` | MD5 unsalted password hashing | HIGH | `bcrypt.hashpw(pw.encode(), bcrypt.gensalt())` |
| 16 | All token issuance | JWT tokens never expire | HIGH | `exp: now + timedelta(hours=1)`; remove `verify_exp: False` |
| 17 | All token issuance | JWT secret `"secret"` — brute-forceable offline | HIGH | `os.environ["JWT_SECRET"]` with 256-bit random value |
| 18 | `POST /files/upload` | Unrestricted type/size; path traversal via filename | HIGH | Extension allowlist; `MAX_UPLOAD_SIZE`; server-generated random filename |
| 19 | `POST /auth/forgot-password` | Reset token in response body + algorithm disclosed | HIGH | Send token out-of-band (email); remove `hint` field |
| 20 | `POST /auth/forgot-password` | Predictable reset token — `MD5(user+minute)` | HIGH | `secrets.token_urlsafe(32)`; single-use; 15-min server-side TTL |
| 21 | `DELETE /admin/user/{id}` | Static hardcoded admin key in source | MEDIUM | Remove static key; require admin-role JWT |
| 22 | `DELETE /files/delete` | No ownership check; path traversal | MEDIUM | Track `owner` on upload; assert ownership; path containment |
| 23 | `GET /files/list` | Lists all users' files; exposes server paths | MEDIUM | Filter by `current_user["sub"]`; remove `path` from response |
| 24 | `GET /data/account` (404) | Raw SQL query string in error body | MEDIUM | Generic: `"No account found"` |
| 25 | All endpoints | No rate limiting on any endpoint | MEDIUM | Global `slowapi` middleware |
| 26 | `POST /auth/login` | Timing attack enables username enumeration | MEDIUM | `hmac.compare_digest()` for all hash comparisons |
| 27 | All endpoints | No HTTP security headers | MEDIUM | Add middleware: `X-Content-Type-Options`, `Cache-Control: no-store`, `X-Frame-Options` |
| 28 | `GET /docs`, `GET /redoc` | Public Swagger UI advertises all endpoints unauthenticated | LOW | Gate behind auth or restrict to internal network only |
| 29 | `main.py:112` | Server binds `0.0.0.0` | LOW | Bind `127.0.0.1`; expose via authenticated reverse proxy |
| 30 | `POST /auth/reset-password` | No password complexity requirements | LOW | Enforce minimum 12 characters + character class requirements |

---

## Secure Code Reference

### JWT Algorithm Pinning
```python
# Before (auth.py:110-114) — vulnerable
payload = jwt.decode(token, JWT_SECRET, algorithms=None, options={"verify_exp": False})

# After — secure
payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

### SQL Injection — Parameterized Queries
```python
# Before (db.py:87) — vulnerable
query = f"SELECT * FROM accounts WHERE owner = '{owner}'"
result = db.execute(query).fetchall()

# After — secure
result = db.execute("SELECT * FROM accounts WHERE owner = ?", (owner,)).fetchall()
```

### Path Traversal — Filename Containment
```python
# Before (files.py:41) — vulnerable
file_path = os.path.join(UPLOAD_DIR, filename)

# After — secure
from pathlib import Path
safe_path = (Path(UPLOAD_DIR).resolve() / Path(filename).name).resolve()
if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
    raise HTTPException(status_code=400, detail="Invalid filename")
file_path = safe_path
```

### SSRF — URL Validation
```python
# Before (main.py:84) — vulnerable
response = requests.get(url, timeout=5)

# After — secure
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

### Mass Assignment — Strip Privileged Fields
```python
# Before (admin.py:67-70) — vulnerable
class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None       # writable by anyone
    password: Optional[str] = None

# After — secure
class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    # role is not exposed here; use a separate admin-only endpoint

class AdminUpdateUserRequest(UpdateUserRequest):
    role: Optional[str] = None       # only reachable via admin route
```

### Error Handler — Remove Internal Exposure
```python
# Before (main.py:55-67) — vulnerable
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    return JSONResponse(status_code=500, content={
        "error": str(exc),
        "traceback": traceback.format_exc(),
        "internal_path": os.getcwd(),
        "db_password": DB_PASSWORD,
    })

# After — secure
import logging
logger = logging.getLogger(__name__)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

### Password Hashing — Replace MD5 with bcrypt
```python
# Before (auth.py:81) — vulnerable
password_hash = hashlib.md5(password.encode()).hexdigest()

# After — secure
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Verification
def verify_password(plain: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plain.encode(), stored_hash.encode())
```

### Security Headers Middleware
```python
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

---

*Generated by Claude Code api-security-review skill — VulnBank is a deliberately vulnerable demo application. Do not deploy in any real environment.*
