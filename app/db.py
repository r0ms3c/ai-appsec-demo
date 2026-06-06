"""
db.py — Database Access Module
================================
Vulnerabilities:
  A03 - SQL Injection via string formatting in all queries
  A02 - Connection string with credentials in source
  A05 - Error messages expose DB schema to clients
"""

import sqlite3
import os
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from auth import get_current_user

router = APIRouter()

# ============================================================
# VULNERABILITY: A02 - Database credentials hardcoded in source
# Real fix: load from environment variables or secrets manager
# ============================================================
DB_HOST = "localhost"
DB_USER = "app_user"
DB_PASS = "db_password_123"     # hardcoded credential
DB_NAME = "vulnbank"
DB_PATH = "vulnbank.db"         # SQLite for demo


def get_db():
    """Get database connection — creates schema if not exists."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Seed schema
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            owner TEXT NOT NULL,
            balance REAL DEFAULT 0,
            account_type TEXT DEFAULT 'checking'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            from_account INTEGER,
            to_account INTEGER,
            amount REAL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS internal_notes (
            id INTEGER PRIMARY KEY,
            content TEXT  -- contains sensitive internal data
        )
    """)

    # Seed data
    conn.execute("INSERT OR IGNORE INTO accounts VALUES (1, 'alice', 10000.00, 'checking')")
    conn.execute("INSERT OR IGNORE INTO accounts VALUES (2, 'bob',    5000.00, 'savings')")
    conn.execute("INSERT OR IGNORE INTO accounts VALUES (3, 'admin', 99999.00, 'checking')")
    conn.execute("INSERT OR IGNORE INTO internal_notes VALUES (1, 'AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE')")
    conn.execute("INSERT OR IGNORE INTO internal_notes VALUES (2, 'Admin password: P@ssw0rd!')")
    conn.commit()
    return conn


# ============================================================
# VULNERABILITY: A03 - SQL Injection
# User input is directly interpolated into SQL strings
#
# Attack examples:
#   /data/account?owner=' OR '1'='1        → returns ALL accounts
#   /data/account?owner=' UNION SELECT id,content,0,'x' FROM internal_notes--
#                                          → dumps internal_notes table
# ============================================================
@router.get("/account")
async def get_account(owner: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        # INSECURE: f-string interpolation directly into SQL
        # Real fix: db.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))
        query = f"SELECT * FROM accounts WHERE owner = '{owner}'"
        result = db.execute(query).fetchall()

        if not result:
            # VULNERABILITY: A05 - exposes the raw SQL query in error
            raise HTTPException(
                status_code=404,
                detail=f"No account found. Query was: {query}"  # leaks SQL structure
            )

        return [dict(row) for row in result]

    except sqlite3.Error as e:
        # VULNERABILITY: A05 - raw DB error exposed to client
        raise HTTPException(status_code=500, detail=f"Database error: {e}, query={query}")


# ============================================================
# VULNERABILITY: A03 - Second-order SQL injection in search
# ============================================================
@router.get("/search")
async def search_transactions(note: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    # INSECURE: note is user-controlled and injected into LIKE clause
    # Attack: ?note=x' UNION SELECT 1,content,3,4,5,6 FROM internal_notes--
    query = f"SELECT * FROM transactions WHERE note LIKE '%{note}%'"
    try:
        results = db.execute(query).fetchall()
        return [dict(row) for row in results]
    except sqlite3.Error as e:
        return {"error": str(e), "query": query}  # exposes query in response


# ============================================================
# VULNERABILITY: A03 - SQL Injection in transfer endpoint
# A01 - No ownership check before transferring funds
# ============================================================
class TransferRequest(BaseModel):
    from_account: int
    to_account: int
    amount: float
    note: Optional[str] = ""


@router.post("/transfer")
async def transfer(body: TransferRequest, current_user: dict = Depends(get_current_user)):
    db = get_db()

    # VULNERABILITY: A01 - no check that from_account belongs to current_user
    # Any authenticated user can drain any account
    from_bal = db.execute(
        f"SELECT balance FROM accounts WHERE id = {body.from_account}"  # SQLi
    ).fetchone()

    if not from_bal or from_bal["balance"] < body.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # VULNERABILITY: A03 - note field is injected into SQL unsanitized
    note = body.note
    db.execute(
        f"INSERT INTO transactions (from_account, to_account, amount, note) "
        f"VALUES ({body.from_account}, {body.to_account}, {body.amount}, '{note}')"
    )
    db.execute(f"UPDATE accounts SET balance = balance - {body.amount} WHERE id = {body.from_account}")
    db.execute(f"UPDATE accounts SET balance = balance + {body.amount} WHERE id = {body.to_account}")
    db.commit()

    return {"message": "Transfer complete"}
