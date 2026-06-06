---
name: red-team-simulation
description: Simulate attacker perspective and generate attack scenarios, exploit chains, and penetration testing payloads. Use when the user asks for red team analysis, attack simulation, exploit generation, or penetration testing.
allowed-tools: Read, Bash
---

# Red Team Simulation Skill

Think like an attacker. Generate complete attack chains from zero access to maximum impact.

## Phase 1: Reconnaissance
Enumerate all endpoints, parameters, and attack surface from source code.

## Phase 2: Authentication attacks
- Credential stuffing payloads
- JWT none algorithm attack (forge token with alg:none, empty signature)
- Weak secret brute force (secret, password, 123456, jwt_secret)
- Token expiry bypass

## Phase 3: Injection attacks
For each injectable endpoint provide working Python exploit code:
1. Detection payload (causes error or behavioral difference)
2. Data extraction payload
3. UNION-based dump payload (accesses other tables)

## Phase 4: Access control attacks
IDOR enumeration across all user IDs, mass assignment privilege escalation,
broken function level authorization abuse.

## Phase 5: File system attacks
Path traversal payloads (../../etc/passwd, ../../app/auth.py),
webshell upload, directory listing abuse.

## Phase 6: SSRF
AWS metadata endpoint (169.254.169.254), internal service probing
(localhost:6379 Redis, localhost:5432 PostgreSQL).

## Phase 7: Kill chain narrative
Complete step-by-step from unauthenticated to full compromise.
Each step: endpoint + payload + expected result + what was gained.

## Phase 8: Impact assessment
Business, regulatory (GDPR, PCI-DSS), and reputational impact per attack.
