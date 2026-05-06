from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from flask import g, request
from passlib.hash import pbkdf2_sha256


DATABASE = os.environ.get("BANK_DEMO_DATABASE", "bank.db")
JWT_SECRET = os.environ.get(
    "BANK_DEMO_JWT_SECRET",
    "dev-only-jwt-secret-change-me-before-deploying",
)

# This hash is only used when an email is not found. Verifying against it makes
# missing-user and wrong-password paths do similar PBKDF2 work, reducing timing
# clues that could otherwise help user enumeration.
DUMMY_PASSWORD_HASH = pbkdf2_sha256.hash("not-the-real-password")


def _connect():
    con = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    return con


def get_user_with_credentials(email: str, password: str):
    # Basic input checks avoid pointless database work and keep login behavior
    # consistent. The returned error is still generic in app.py.
    if not email or not password:
        pbkdf2_sha256.verify(password or "", DUMMY_PASSWORD_HASH)
        return None

    with _connect() as con:
        cur = con.execute(
            # Bound parameters keep attacker-controlled email text out of the
            # SQL syntax, which is the key SQL Injection defense here.
            "SELECT email, name, password FROM users WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()

    password_hash = row["password"] if row else DUMMY_PASSWORD_HASH
    if not pbkdf2_sha256.verify(password, password_hash):
        return None
    if row is None:
        return None
    return {"email": row["email"], "name": row["name"], "token": create_token(row["email"])}


def logged_in() -> bool:
    token = request.cookies.get("auth_token")
    try:
        # JWT signature and expiration are verified before trusting the subject.
        # The email is then stored in Flask's request-local g object.
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        g.user = data["sub"]
        return True
    except (jwt.InvalidTokenError, KeyError, TypeError):
        return False


def create_token(email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": email, "iat": now, "exp": now + timedelta(minutes=60)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
