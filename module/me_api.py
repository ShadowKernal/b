from __future__ import annotations

import sqlite3
from http import HTTPStatus

from api_common import ApiError, iso_ts, now_ts, parse_json_body
from constants import COOKIE_CSRF, COOKIE_SESSION, USER_STATUS_DELETED
from db import audit_log, user_roles
from security import normalize_email, password_hash, password_verify


def get_me(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user:
        raise ApiError(HTTPStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Not authenticated")
    roles = user_roles(conn, user["id"])
    handler.send_json(
        HTTPStatus.OK,
        {
            "user": {
                "id": user["id"],
                "email": user["email"],
                "emailVerified": user["email_verified_at"] is not None,
                "status": user["status"],
                "roles": roles,
                "profile": {"displayName": user["display_name"]},
                "createdAt": iso_ts(user["created_at"]),
                "lastLoginAt": iso_ts(user["last_login_at"]) if user["last_login_at"] else None,
            }
        },
    )


def update_me(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    data = parse_json_body(handler)
    profile = data.get("profile") if isinstance(data.get("profile"), dict) else {}
    display_name = str((profile or {}).get("displayName") or "").strip()
    if not display_name:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Display name required")
    ts = now_ts()
    conn.execute("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?", (display_name, ts, session["user_id"]))
    conn.commit()
    get_me(handler, conn, session)


def change_password(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    data = parse_json_body(handler)
    current_password = str(data.get("currentPassword") or "")
    new_password = str(data.get("newPassword") or "")
    if len(new_password) < 8:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Password must be at least 8 characters")
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user or not user["password_hash"] or not password_verify(current_password, user["password_hash"]):
        raise ApiError(HTTPStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid current password")
    ts = now_ts()
    conn.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (password_hash(new_password), ts, user["id"]))
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL",
        (ts, user["id"], session["id"]),
    )
    audit_log(conn, action="PASSWORD_CHANGED", actor_user_id=user["id"], target_user_id=user["id"], ip=handler.client_address[0])
    conn.commit()
    handler.send_json(HTTPStatus.OK, {"status": "PASSWORD_UPDATED"})


def list_sessions(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    rows = conn.execute(
        """
        SELECT id, created_at, last_seen_at, expires_at, ip, user_agent
        FROM sessions
        WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
        ORDER BY last_seen_at DESC
        """,
        (session["user_id"], now_ts()),
    ).fetchall()
    items = [
        {
            "id": r["id"],
            "createdAt": iso_ts(r["created_at"]),
            "lastSeenAt": iso_ts(r["last_seen_at"]),
            "expiresAt": iso_ts(r["expires_at"]),
            "ip": r["ip"],
            "userAgent": r["user_agent"],
        }
        for r in rows
    ]
    handler.send_json(HTTPStatus.OK, {"items": items})


def revoke_session(handler, conn: sqlite3.Connection, session: sqlite3.Row, session_id: str) -> None:
    ts = now_ts()
    row = conn.execute(
        "SELECT id FROM sessions WHERE id = ? AND user_id = ?",
        (session_id, session["user_id"]),
    ).fetchone()
    if not row:
        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Session not found")
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (ts, session_id))
    conn.commit()
    handler.send_no_content()


def delete_account(handler, conn: sqlite3.Connection, session: sqlite3.Row) -> None:
    data = parse_json_body(handler)
    confirmation = str(data.get("confirmation") or "").strip()
    if confirmation != "DELETE":
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Confirmation required (type DELETE)")
    ts = now_ts()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user:
        raise ApiError(HTTPStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Not authenticated")

    anon_email = f"deleted+{user['id']}@local"
    conn.execute(
        """
        UPDATE users
        SET status = ?, deleted_at = ?, updated_at = ?, email = ?, email_norm = ?, email_verified_at = NULL, password_hash = NULL, display_name = ?
        WHERE id = ?
        """,
        (USER_STATUS_DELETED, ts, ts, anon_email, normalize_email(anon_email), "Deleted User", user["id"]),
    )
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (ts, user["id"]))
    audit_log(conn, action="ACCOUNT_DELETED", actor_user_id=user["id"], target_user_id=user["id"], ip=handler.client_address[0])
    conn.commit()
    handler.send_json(HTTPStatus.OK, {"status": "DEACTIVATED"}, clear_cookies=[COOKIE_SESSION, COOKIE_CSRF])
