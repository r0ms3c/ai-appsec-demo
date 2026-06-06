---
name: api-security-review
description: Security review focused on API design, REST security, authentication, and input handling. Use when the user asks for API review, REST security, endpoint security, or authentication design review.
allowed-tools: Read, Bash
---

# API Security Review Skill

## Step 1: Endpoint inventory
Build complete table: Method | Path | Auth Required | Input Parameters | Returns

## Step 2: Authentication review
- JWT: algorithm pinned server-side? expiry enforced? secret strength?
- Rate limiting on auth endpoints?
- Token forge/steal vectors?

## Step 3: Authorization matrix
| Endpoint | Unauthenticated | User | Admin | Notes |
Highlight every cell where lower privilege accesses higher privilege resource.

## Step 4: Input validation audit
For every parameter: type validated? length validated? used in dangerous context (SQL, shell, path, template)?

## Step 5: API-specific vulnerabilities
- Mass assignment: can users set fields they shouldn't (role, id)?
- BOLA/IDOR: object IDs validated against ownership?
- Excessive data exposure: response returns more than needed?
- Missing rate limits: which endpoints have none?

## Step 6: Error handling
Do errors expose: stack traces? internal paths? DB schema? dependency versions?

## Step 7: HTTP security headers
Check for missing: CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Cache-Control on sensitive endpoints.

## Step 8: Remediation summary
| Endpoint | Issue | Severity | Fix |
