"""
admin.py — Admin and User Management Module
=============================================
Vulnerabilities:
  A01 - IDOR: access other users' data via predictable IDs
  A01 - Broken Access Control: role check client-side only
  A05 - Admin functions exposed without proper authorization
"""

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import jwt

from auth import get_current_user, USERS_DB, JWT_SECRET

router = APIRouter()


# ============================================================
# VULNERABILITY: A01 - IDOR (Insecure Direct Object Reference)
# Users can access ANY user profile by changing the user_id
# No check that the requesting user owns or has rights to the resource
#
# Attack: GET /admin/user/1  (as bob, gets alice's data)
#         GET /admin/user/3  (as alice, gets admin's data)
# ============================================================
@router.get("/user/{user_id}")
async def get_user_profile(user_id: int, current_user: dict = Depends(get_current_user)):
    # INSECURE: never checks if current_user.id == user_id
    # Real fix: if current_user["id"] != user_id and current_user["role"] != "admin": raise 403
    for username, data in USERS_DB.items():
        if data["id"] == user_id:
            return {
                "id": data["id"],
                "username": username,
                "role": data["role"],
                "password_hash": data["password_hash"],  # INSECURE: exposes hash
            }
    raise HTTPException(status_code=404, detail="User not found")


# ============================================================
# VULNERABILITY: A01 - Role check done client-side via token claim
# Attacker forges JWT with "role": "admin" to access admin panel
# (works because JWT "none" algorithm is accepted in auth.py)
# ============================================================
@router.get("/panel")
async def admin_panel(current_user: dict = Depends(get_current_user)):
    role = current_user.get("role", "user")

    # INSECURE: trusts role claim from JWT without server-side verification
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    # Returns all users including password hashes
    return {
        "users": USERS_DB,      # INSECURE: exposes all password hashes
        "message": "Welcome to the admin panel",
    }


# ============================================================
# VULNERABILITY: A01 - Mass assignment
# User can update any field including their own role
# ============================================================
class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None       # user should NEVER be able to set this
    password: Optional[str] = None


@router.put("/user/{user_id}")
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    current_user: dict = Depends(get_current_user),
):
    # VULNERABILITY: A01 - no ownership check
    # Any user can update any other user's profile
    for username, data in USERS_DB.items():
        if data["id"] == user_id:
            # VULNERABILITY: mass assignment — role can be set by user
            if body.role:
                data["role"] = body.role    # privilege escalation
            if body.password:
                import hashlib
                data["password_hash"] = hashlib.md5(body.password.encode()).hexdigest()
            return {"message": f"User {username} updated", "new_data": data}

    raise HTTPException(status_code=404, detail="User not found")


# ============================================================
# VULNERABILITY: A01 - Sensitive admin action with no auth
# The delete endpoint checks for an "X-Admin-Key" header but
# the key is hardcoded and the same for all environments
# ============================================================
ADMIN_KEY = "admin-key-do-not-share"  # hardcoded, in source control

@router.delete("/user/{user_id}")
async def delete_user(user_id: int, x_admin_key: Optional[str] = Header(None)):
    # INSECURE: static key, no audit logging, no second factor
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    for username, data in list(USERS_DB.items()):
        if data["id"] == user_id:
            del USERS_DB[username]
            return {"message": f"User {username} deleted"}

    raise HTTPException(status_code=404, detail="User not found")


# ============================================================
# VULNERABILITY: A01 - Broken Function Level Authorization
# Debug endpoint left enabled in production, no auth required
# ============================================================
@router.get("/debug/tokens")
async def debug_tokens():
    """Generate tokens for all users — no auth required."""
    # INSECURE: no authentication, generates valid tokens for every user
    tokens = {}
    for username, data in USERS_DB.items():
        token = jwt.encode(
            {"sub": username, "role": data["role"], "id": data["id"]},
            JWT_SECRET,
            algorithm="HS256",
        )
        tokens[username] = token
    return tokens
