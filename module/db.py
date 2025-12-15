from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from api_common import new_id, now_ts
from constants import ROLE_ADMIN, ROLE_USER, USER_STATUS_ACTIVE
from security import normalize_email, password_hash


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          email TEXT NOT NULL,
          email_norm TEXT NOT NULL UNIQUE,
          email_verified_at INTEGER,
          password_hash TEXT,
          status TEXT NOT NULL,
          display_name TEXT NOT NULL,
          locale TEXT,
          timezone TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          last_login_at INTEGER,
          deleted_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS user_roles (
          user_id TEXT NOT NULL,
          role_name TEXT NOT NULL,
          assigned_by_user_id TEXT,
          assigned_at INTEGER NOT NULL,
          PRIMARY KEY (user_id, role_name),
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY,
          token_hash TEXT NOT NULL UNIQUE,
          user_id TEXT NOT NULL,
          csrf_token TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          revoked_at INTEGER,
          ip TEXT,
          user_agent TEXT,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS email_verification_tokens (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          requested_from_ip TEXT,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          action TEXT NOT NULL,
          actor_user_id TEXT,
          target_user_id TEXT,
          ip TEXT,
          created_at INTEGER NOT NULL,
          metadata_json TEXT
        );

        CREATE TABLE IF NOT EXISTS dev_outbox (
          id TEXT PRIMARY KEY,
          to_email TEXT NOT NULL,
          subject TEXT NOT NULL,
          body TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        """
    )
    conn.commit()


def audit_log(
    conn: sqlite3.Connection,
    *,
    action: str,
    actor_user_id: str | None,
    target_user_id: str | None,
    ip: str | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        "INSERT INTO audit_logs (id, action, actor_user_id, target_user_id, ip, created_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id(), action, actor_user_id, target_user_id, ip, now_ts(), json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=False)),
    )


def user_roles(conn: sqlite3.Connection, user_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name ASC",
        (user_id,),
    ).fetchall()
    return [r["role_name"] for r in rows]


def has_role(conn: sqlite3.Connection, user_id: str, role: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM user_roles WHERE user_id = ? AND role_name = ?",
        (user_id, role),
    ).fetchone()
    return row is not None


def send_dev_email(conn: sqlite3.Connection, *, to_email: str, subject: str, body: str) -> None:
    conn.execute(
        "INSERT INTO dev_outbox (id, to_email, subject, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), to_email, subject, body, now_ts()),
    )


def seed_admin_if_empty(conn: sqlite3.Connection) -> tuple[str, str] | None:
    any_user = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if any_user:
        return None

    admin_email = "admin@example.com"
    admin_password = secrets.token_urlsafe(10)
    user_id = new_id()
    ts = now_ts()

    conn.execute(
        "INSERT INTO users (id, email, email_norm, email_verified_at, password_hash, status, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            admin_email,
            normalize_email(admin_email),
            ts,
            password_hash(admin_password),
            USER_STATUS_ACTIVE,
            "Admin",
            ts,
            ts,
        ),
    )
    conn.execute(
        "INSERT INTO user_roles (user_id, role_name, assigned_by_user_id, assigned_at) VALUES (?, ?, ?, ?)",
        (user_id, ROLE_ADMIN, None, ts),
    )
    conn.execute(
        "INSERT INTO user_roles (user_id, role_name, assigned_by_user_id, assigned_at) VALUES (?, ?, ?, ?)",
        (user_id, ROLE_USER, None, ts),
    )

    send_dev_email(
        conn,
        to_email=admin_email,
        subject="UMS demo admin credentials",
        body=f"Admin account created:\n\nEmail: {admin_email}\nPassword: {admin_password}\n\nLogin: http://localhost:8000/login\n",
    )
    conn.commit()
    return admin_email, admin_password
