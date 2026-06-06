"""
VulnBank API - Intentionally Vulnerable Application
====================================================
WARNING: This application contains intentional security vulnerabilities
for educational and demonstration purposes ONLY.

DO NOT deploy this in any real environment.

Vulnerabilities demonstrated (mapped to OWASP Top 10 2021):
  A01 - Broken Access Control    → admin.py, auth.py
  A02 - Cryptographic Failures   → auth.py (weak JWT, plaintext passwords)
  A03 - Injection                → db.py (SQL injection)
  A05 - Security Misconfiguration→ this file (debug mode, verbose errors)
  A06 - Vulnerable Components    → requirements.txt (outdated deps)
  A07 - Auth Failures            → auth.py (no rate limiting, weak tokens)
  A08 - Integrity Failures       → auth.py (JWT none algorithm)
  A10 - SSRF                     → this file (/fetch endpoint)
"""

import os
import requests
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from auth import router as auth_router, get_current_user
from db import router as db_router
from admin import router as admin_router
from files import router as files_router

# ============================================================
# VULNERABILITY: A02 - Hardcoded secrets in source code
# VULNERABILITY: A05 - Debug mode enabled in production
# ============================================================
SECRET_KEY = "super_secret_key_123"           # hardcoded JWT secret
DB_PASSWORD = "admin123"                       # hardcoded DB password
INTERNAL_API_KEY = "sk-internal-prod-abc123"   # exposed internal key
DEBUG = True                                   # never True in production

app = FastAPI(
    title="VulnBank API",
    description="A deliberately vulnerable banking API for security demos",
    debug=DEBUG,  # VULNERABILITY: exposes stack traces in responses
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(db_router,   prefix="/data", tags=["data"])
app.include_router(admin_router,prefix="/admin",tags=["admin"])
app.include_router(files_router,prefix="/files",tags=["files"])


# ============================================================
# VULNERABILITY: A05 - Verbose error handler leaks internals
# ============================================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # INSECURE: returns full stack trace and internal paths to client
    import traceback
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "traceback": traceback.format_exc(),   # never expose this
            "internal_path": os.getcwd(),           # leaks server path
            "db_password": DB_PASSWORD,             # catastrophic leak
        }
    )


# ============================================================
# VULNERABILITY: A10 - Server-Side Request Forgery (SSRF)
# No validation of user-supplied URL — attacker can reach
# internal services: metadata APIs, localhost, private IPs
# ============================================================
@app.get("/fetch")
async def fetch_url(url: str):
    """Fetch content from a URL — SSRF vulnerable."""
    # INSECURE: no URL validation, allowlist, or private IP blocking
    # Attacker payloads:
    #   /fetch?url=http://169.254.169.254/latest/meta-data/  (AWS metadata)
    #   /fetch?url=http://localhost:6379  (internal Redis)
    #   /fetch?url=file:///etc/passwd
    try:
        response = requests.get(url, timeout=5)
        return {"status": response.status_code, "body": response.text[:2000]}
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# VULNERABILITY: A05 - Health endpoint leaks system info
# ============================================================
@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "debug": DEBUG,
        "secret_key": SECRET_KEY,          # INSECURE: exposed in health check
        "environment": dict(os.environ),   # INSECURE: dumps all env vars
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    return {"message": "VulnBank API — see /docs for endpoints"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",   # VULNERABILITY: binds to all interfaces
        port=8000,
        reload=DEBUG,
    )
