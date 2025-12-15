from __future__ import annotations

import secrets
import sqlite3
from http import HTTPStatus
from api_common import ApiError, iso_ts, new_id, now_ts, parse_json_body
from constants import (
    COOKIE_CSRF,
    COOKIE_SESSION,
    ROLE_USER,
    USER_STATUS_ACTIVE,
    USER_STATUS_DELETED,
    USER_STATUS_DISABLED,
    USER_STATUS_PENDING,
)
from db import audit_log, send_dev_email, user_roles
from security import is_valid_email, normalize_email, password_hash, password_verify, sha256_hex


def _base_url(handler) -> str:
    host = handler.headers.get("host") or "localhost:8000"
    return f"http://{host}"


def signup(handler, conn: sqlite3.Connection) -> None:
    data = parse_json_body(handler)
    email = str(data.get("email") or "").strip()
    password = str(data.get("password") or "")
    profile = data.get("profile") if isinstance(data.get("profile"), dict) else {}
    display_name = str((profile or {}).get("displayName") or "").strip() or "User"

    if not is_valid_email(email):
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Invalid email")
    if len(password) < 8:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Password must be at least 8 characters")

    email_norm = normalize_email(email)
    ts = now_ts()
    user = conn.execute("SELECT * FROM users WHERE email_norm = ?", (email_norm,)).fetchone()

    if user is None:
        user_id = new_id()
        conn.execute(
            "INSERT INTO users (id, email, email_norm, email_verified_at, password_hash, status, display_name, created_at, updated_at) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)",
            (user_id, email, email_norm, password_hash(password), USER_STATUS_PENDING, display_name, ts, ts),
        )
        conn.execute(
            "INSERT INTO user_roles (user_id, role_name, assigned_by_user_id, assigned_at) VALUES (?, ?, NULL, ?)",
            (user_id, ROLE_USER, ts),
        )
        conn.commit()
    else:
        user_id = user["id"]

    user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Unable to create user")

    if user_row["email_verified_at"] is None and user_row["status"] not in (USER_STATUS_DISABLED, USER_STATUS_DELETED):
        raw_token = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)",
            (new_id(), user_id, sha256_hex(raw_token), ts, ts + 24 * 3600),
        )
        verify_link = f"{_base_url(handler)}/verify-email?token={raw_token}"
        send_dev_email(
            conn,
            to_email=email,
            subject="Verify your email",
            body=f"Your verification code:\n\n{raw_token}\n\nOr open:\n{verify_link}\n",
        )
        audit_log(conn, action="EMAIL_VERIFICATION_SENT", actor_user_id=None, target_user_id=user_id, ip=handler.client_address[0])
        conn.commit()

    handler.send_json(HTTPStatus.ACCEPTED, {"status": user_row["status"]})


def verify_email(handler, conn: sqlite3.Connection) -> None:
    data = parse_json_body(handler)
    token = str(data.get("token") or "").strip()
    if not token:
        raise ApiError(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "Token required")

    token_hash = sha256_hex(token)
    ts = now_ts()
    row = conn.execute(
        """
        SELECT t.*, u.status
        FROM email_verification_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ?
        """,
        (token_hash, ts),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.BAD_REQUEST, "INVALID_TOKEN", "Invalid or expired token")

    user_id = row["user_id"]
    conn.execute("UPDATE email_verification_tokens SET used_at = ? WHERE id = ?", (ts, row["id"]))
    conn.execute(
        "UPDATE users SET email_verified_at = ?, status = ?, updated_at = ? WHERE id = ? AND status != ?",
        (ts, USER_STATUS_ACTIVE, ts, user_id, USER_STATUS_DISABLED),
    )
    audit_log(conn, action="EMAIL_VERIFIED", actor_user_id=None, target_user_id=user_id, ip=handler.client_address[0])
    conn.commit()
    handler.send_json(HTTPStatus.OK, {"status": USER_STATUS_ACTIVE})


def login(handler, conn: sqlite3.Connection) -> None:
    data = parse_json_body(handler)
    identifier = str(data.get("identifier") or "").strip()
    password = str(data.get("password") or "")
    remember = bool(data.get("rememberMe"))

    user = conn.execute("SELECT * FROM users WHERE email_norm = ?", (normalize_email(identifier),)).fetchone()
    if not user:
        raise ApiError(HTTPStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid credentials")
    if user["status"] == USER_STATUS_DISABLED:
        raise ApiError(HTTPStatus.FORBIDDEN, "ACCOUNT_DISABLED", "Account disabled")
    if user["status"] == USER_STATUS_DELETED:
        raise ApiError(HTTPStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid credentials")
    if user["email_verified_at"] is None:
        raise ApiError(HTTPStatus.FORBIDDEN, "EMAIL_NOT_VERIFIED", "Email not verified. Check the dev outbox.")
    stored = user["password_hash"] or ""
    if not stored or not password_verify(password, stored):
        raise ApiError(HTTPStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid credentials")

    ts = now_ts()
    session_id = new_id()
    token_raw = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    max_age = 14 * 24 * 3600 if remember else 24 * 3600
    expires_at = ts + max_age

    conn.execute(
        "INSERT INTO sessions (id, token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
        (
            session_id,
            sha256_hex(token_raw),
            user["id"],
            csrf_token,
            ts,
            ts,
            expires_at,
            handler.client_address[0],
            handler.headers.get("user-agent"),
        ),
    )
    conn.execute("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?", (ts, ts, user["id"]))
    audit_log(conn, action="LOGIN_SUCCESS", actor_user_id=user["id"], target_user_id=user["id"], ip=handler.client_address[0])
    conn.commit()

    roles = user_roles(conn, user["id"])
    handler.send_json(
        HTTPStatus.OK,
        {
            "user": {"id": user["id"], "email": user["email"], "status": user["status"], "roles": roles},
            "session": {"id": session_id, "expiresAt": iso_ts(expires_at)},
        },
        set_cookies=[
            {"name": COOKIE_SESSION, "value": token_raw, "http_only": True, "max_age": max_age},
            {"name": COOKIE_CSRF, "value": csrf_token, "http_only": False, "max_age": max_age},
        ],
    )


def logout(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    ts = now_ts()
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (ts, session["id"]))
    audit_log(conn, action="LOGOUT", actor_user_id=session["user_id"], target_user_id=session["user_id"], ip=handler.client_address[0])
    conn.commit()
    handler.send_no_content(clear_cookies=[COOKIE_SESSION, COOKIE_CSRF])


def logout_all(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    ts = now_ts()
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (ts, session["user_id"]))
    audit_log(conn, action="LOGOUT_ALL", actor_user_id=session["user_id"], target_user_id=session["user_id"], ip=handler.client_address[0])
    conn.commit()
    handler.send_no_content(clear_cookies=[COOKIE_SESSION, COOKIE_CSRF])


def forgot_password(handler, conn: sqlite3.Connection) -> None:
    data = parse_json_body(handler)
    identifier = str(data.get("identifier") or "").strip()
    ts = now_ts()
    user = conn.execute("SELECT * FROM users WHERE email_norm = ?", (normalize_email(identifier),)).fetchone()
    if user and user["status"] not in (USER_STATUS_DISABLED, USER_STATUS_DELETED):
        raw_token = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, created_at, expires_at, used_at, requested_from_ip) VALUES (?, ?, ?, ?, ?, NULL, ?)",
            (new_id(), user["id"], sha256_hex(raw_token), ts, ts + 3600, handler.client_address[0]),
        )
        reset_link = f"{_base_url(handler)}/reset-password?token={raw_token}"
        send_dev_email(
            conn,
            to_email=user["email"],
            subject="Password reset",
            body=f"Your password reset code:\n\n{raw_token}\n\nOr open:\n{reset_link}\n",
        )
        audit_log(conn, action="PASSWORD_RESET_REQUESTED", actor_user_id=None, target_user_id=user["id"], ip=handler.client_address[0])
        conn.commit()
    handler.send_json(HTTPStatus.ACCEPTED, {"status": "OK"})


def reset_password(handler, conn: sqlite3.Connection) -> None:
    data = parse_json_body(handler)
    token = str(data.get("token") or "").strip()
    new_password = str(data.get("newPassword") or "")
    if len(new_password) < 8:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Password must be at least 8 characters")

    ts = now_ts()
    row = conn.execute(
        "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (sha256_hex(token), ts),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.BAD_REQUEST, "INVALID_TOKEN", "Invalid or expired token")

    user_id = row["user_id"]
    conn.execute("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?", (ts, row["id"]))
    conn.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (password_hash(new_password), ts, user_id))
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (ts, user_id))
    audit_log(conn, action="PASSWORD_RESET_COMPLETED", actor_user_id=None, target_user_id=user_id, ip=handler.client_address[0])
    conn.commit()
    handler.send_json(HTTPStatus.OK, {"status": "PASSWORD_UPDATED"})
