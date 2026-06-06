"""
auth.py — Broken Authentication Module
=======================================
Vulnerabilities:
  A02 - Plaintext password storage, weak JWT secret
  A07 - No rate limiting, no account lockout, weak token validation
  A08 - JWT "none" algorithm accepted, no signature verification
"""

import jwt
import hashlib
import time
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

# ============================================================
# VULNERABILITY: A02 - Hardcoded weak secret + plaintext passwords
# ============================================================
JWT_SECRET = "secret"   # trivially brute-forceable
JWT_ALGORITHM = "HS256"

# VULNERABILITY: passwords stored as unsalted MD5
# Real fix: use bcrypt/argon2 with per-user salt
USERS_DB = {
    "admin": {
        "password_hash": hashlib.md5(b"admin123").hexdigest(),  # MD5, no salt
        "role": "admin",
        "id": 1,
    },
    "alice": {
        "password_hash": hashlib.md5(b"password").hexdigest(),
        "role": "user",
        "id": 2,
    },
    "bob": {
        "password_hash": hashlib.md5(b"123456").hexdigest(),
        "role": "user",
        "id": 3,
    },
}

# Track login attempts — but never enforced (see login endpoint)
login_attempts: dict[str, list] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRequest(BaseModel):
    token: str


# ============================================================
# VULNERABILITY: A07 - No rate limiting on login endpoint
# Attacker can brute-force credentials indefinitely
# ============================================================
@router.post("/login")
async def login(request: Request, body: LoginRequest):
    username = body.username
    password = body.password

    # Rate limiting check exists but is never enforced
    client_ip = request.client.host
    attempts = login_attempts.get(client_ip, [])
    # INSECURE: this block is dead code — rate limit never applied
    if len(attempts) > 1000:  # threshold is absurdly high
        pass  # should raise HTTPException but doesn't

    if username not in USERS_DB:
        # VULNERABILITY: timing attack — reveals valid usernames
        # via response time difference
        return {"error": "invalid credentials"}

    user = USERS_DB[username]
    # VULNERABILITY: unsalted MD5 comparison
    password_hash = hashlib.md5(password.encode()).hexdigest()

    if user["password_hash"] != password_hash:
        return {"error": "invalid credentials"}

    # VULNERABILITY: A07 - token never expires (no exp claim)
    token = jwt.encode(
        {"sub": username, "role": user["role"], "id": user["id"]},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    return {"access_token": token, "token_type": "bearer"}


# ============================================================
# VULNERABILITY: A08 - JWT "none" algorithm attack
# Attacker can forge tokens by stripping the signature and
# setting algorithm to "none" — accepted without verification
# ============================================================
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ")[1]

    try:
        # INSECURE: algorithms=None allows attacker to specify alg in header
        # including "none" which bypasses signature verification entirely
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=None,        # should be: algorithms=["HS256"]
            options={"verify_exp": False}  # INSECURE: skips expiry check
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


# ============================================================
# VULNERABILITY: A08 - Password reset uses predictable token
# Token is just MD5(username + timestamp truncated to minute)
# Attacker can predict token within a 60-second window
# ============================================================
@router.post("/forgot-password")
async def forgot_password(username: str):
    if username not in USERS_DB:
        return {"message": "If that user exists, a reset link was sent"}

    # INSECURE: predictable reset token
    timestamp = int(time.time() / 60)  # changes every minute
    reset_token = hashlib.md5(f"{username}{timestamp}".encode()).hexdigest()

    # In a real app this would email the token
    # INSECURE: returning the token directly in the response
    return {
        "message": "Reset token generated",
        "reset_token": reset_token,   # never return this in a real app
        "hint": f"token = md5(username + unix_minute)",  # leaks algorithm
    }


# ============================================================
# VULNERABILITY: A07 - Password reset doesn't invalidate old token
# and accepts any token within the current or previous minute
# ============================================================
@router.post("/reset-password")
async def reset_password(username: str, token: str, new_password: str):
    timestamp = int(time.time() / 60)

    valid_tokens = [
        hashlib.md5(f"{username}{timestamp}".encode()).hexdigest(),
        hashlib.md5(f"{username}{timestamp - 1}".encode()).hexdigest(),
    ]

    if token not in valid_tokens:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    # VULNERABILITY: no password complexity requirements
    # VULNERABILITY: MD5 hash, no salt
    USERS_DB[username]["password_hash"] = hashlib.md5(new_password.encode()).hexdigest()

    return {"message": "Password updated"}


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user
