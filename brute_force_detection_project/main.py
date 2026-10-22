#!/usr/bin/env python3
"""Brute-Force Attack Detection System (educational, local-only demo)."""
import argparse
import hashlib
import hmac
import os
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).with_name("security.db")
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_SECONDS = 60
PBKDF2_ITERATIONS = 310_000


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, candidate = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, hash_hex)


def initialize_database():
    with connect_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL
        );
        """)


def log_event(username: str, event_type: str, details: str):
    with connect_db() as conn:
        conn.execute(
            "INSERT INTO security_events(username, event_type, details) VALUES (?, ?, ?)",
            (username, event_type, details),
        )


def register_user(username: str, password: str):
    username = username.strip()
    if len(username) < 3:
        print("Username must contain at least 3 characters.")
        return
    if len(password) < 8:
        print("Password must contain at least 8 characters.")
        return
    salt, digest = hash_password(password)
    try:
        with connect_db() as conn:
            conn.execute(
                "INSERT INTO users(username, salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, digest),
            )
        log_event(username, "REGISTER", "Account created")
        print(f"Account created for '{username}'.")
    except sqlite3.IntegrityError:
        print("That username already exists.")


def login_user(username: str, password: str):
    username = username.strip()
    with connect_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user is None:
        log_event(username or "(blank)", "LOGIN_FAILED", "Unknown username")
        print("Login failed: invalid username or password.")
        return

    now = time.time()
    if user["locked_until"] > now:
        remaining = int(user["locked_until"] - now + 0.999)
        log_event(username, "LOGIN_BLOCKED", f"Account locked; {remaining}s remain")
        print(f"Account temporarily locked. Try again in {remaining} seconds.")
        return

    # If the lockout has expired, start a fresh attempt counter.
    if user["locked_until"] and user["locked_until"] <= now:
        with connect_db() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?",
                (username,),
            )
        user = dict(user)
        user["failed_attempts"] = 0

    if verify_password(password, user["salt"], user["password_hash"]):
        with connect_db() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?",
                (username,),
            )
        log_event(username, "LOGIN_SUCCESS", "Successful authentication")
        print(f"Login successful. Welcome, {username}!")
        return

    attempts = int(user["failed_attempts"]) + 1
    if attempts >= MAX_FAILED_ATTEMPTS:
        locked_until = now + LOCKOUT_SECONDS
        with connect_db() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                (attempts, locked_until, username),
            )
        log_event(username, "ACCOUNT_LOCKED", f"{attempts} failed attempts; lockout {LOCKOUT_SECONDS}s")
        print(f"Login failed. {MAX_FAILED_ATTEMPTS} failed attempts reached.")
        print(f"Account locked for {LOCKOUT_SECONDS} seconds.")
    else:
        with connect_db() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?",
                (attempts, username),
            )
        remaining = MAX_FAILED_ATTEMPTS - attempts
        log_event(username, "LOGIN_FAILED", f"Incorrect password; {attempts} failed attempt(s)")
        print(f"Login failed: invalid username or password. {remaining} attempt(s) left before lockout.")


def show_events(limit: int):
    with connect_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, username, event_type, details "
            "FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    if not rows:
        print("No security events recorded yet.")
        return
    print("\nID | Timestamp           | Username | Event             | Details")
    print("-" * 90)
    for row in rows:
        print(f'{row["id"]} | {row["timestamp"]} | {row["username"]} | {row["event_type"]} | {row["details"]}')


def main():
    parser = argparse.ArgumentParser(description="Local brute-force detection demo")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Initialize the SQLite database")
    reg = sub.add_parser("register", help="Create a local demo account")
    reg.add_argument("username")
    reg.add_argument("--password", help="Password (omit to be prompted securely)")
    login = sub.add_parser("login", help="Try to sign in")
    login.add_argument("username")
    login.add_argument("--password", help="Password (omit to be prompted securely)")
    events = sub.add_parser("events", help="Display recent security events")
    events.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    initialize_database()
    if args.command == "init":
        print(f"Database ready: {DB_PATH}")
    elif args.command == "register":
        import getpass
        password = args.password if args.password is not None else getpass.getpass("Choose password: ")
        register_user(args.username, password)
    elif args.command == "login":
        import getpass
        password = args.password if args.password is not None else getpass.getpass("Password: ")
        login_user(args.username, password)
    elif args.command == "events":
        show_events(max(1, min(args.limit, 200)))


if __name__ == "__main__":
    main()
