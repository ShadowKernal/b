from __future__ import annotations

import json
import sqlite3
from http import HTTPStatus
from typing import Any

from api_common import ApiError, iso_ts, now_ts, parse_json_body
from constants import USER_STATUS_ACTIVE, USER_STATUS_DELETED, USER_STATUS_DISABLED, USER_STATUS_PENDING
from db import audit_log, user_roles


def list_users(handler, conn: sqlite3.Connection, q: dict[str, list[str]]) -> None:
    limit = 50
    cursor = 0
    if "limit" in q:
        try:
            limit = max(1, min(100, int(q["limit"][0])))
        except Exception:
            limit = 50
    if "cursor" in q:
        try:
            cursor = max(0, int(q["cursor"][0]))
        except Exception:
            cursor = 0

    status = (q.get("status") or [""])[0].strip()
    search = (q.get("q") or [""])[0].strip().lower()

    where = []
    params: list[Any] = []
    if status:
        where.append("status = ?")
        params.append(status)
    if search:
        where.append("email_norm LIKE ?")
        params.append(f"%{search}%")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(
        f"SELECT id, email, status, created_at, last_login_at FROM users {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (*params, limit, cursor),
    ).fetchall()

    items = []
    for r in rows:
        roles = user_roles(conn, r["id"])
        items.append(
            {
                "id": r["id"],
                "email": r["email"],
                "status": r["status"],
                "roles": roles,
                "createdAt": iso_ts(r["created_at"]),
                "lastLoginAt": iso_ts(r["last_login_at"]) if r["last_login_at"] else None,
            }
        )

    next_cursor = cursor + len(items) if len(items) == limit else None
    handler.send_json(
        HTTPStatus.OK,
        {"items": items, "pageInfo": {"nextCursor": next_cursor, "hasNextPage": next_cursor is not None}},
    )


def get_user(handler, conn: sqlite3.Connection, user_id: str) -> None:
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "User not found")
    roles = user_roles(conn, user_id)
    handler.send_json(
        HTTPStatus.OK,
        {
            "user": {
                "id": user["id"],
                "email": user["email"],
                "status": user["status"],
                "roles": roles,
                "profile": {"displayName": user["display_name"]},
                "createdAt": iso_ts(user["created_at"]),
                "lastLoginAt": iso_ts(user["last_login_at"]) if user["last_login_at"] else None,
            }
        },
    )


def update_user(handler, conn: sqlite3.Connection, session: sqlite3.Row, user_id: str) -> None:
    data = parse_json_body(handler)
    profile = data.get("profile") if isinstance(data.get("profile"), dict) else {}
    display_name = str((profile or {}).get("displayName") or "").strip()
    if not display_name:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_FAILED", "Display name required")
    ts = now_ts()
    cur = conn.execute("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?", (display_name, ts, user_id))
    if cur.rowcount == 0:
        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "User not found")
    audit_log(
        conn,
        action="ADMIN_USER_UPDATED",
        actor_user_id=session["user_id"],
        target_user_id=user_id,
        ip=handler.client_address[0],
        metadata={"fields": ["display_name"]},
    )
    conn.commit()
    get_user(handler, conn, user_id)


def disable_user(handler, conn: sqlite3.Connection, session: sqlite3.Row, user_id: str) -> None:
    data = parse_json_body(handler)
    reason = str(data.get("reason") or "").strip() or "admin action"
    ts = now_ts()
    cur = conn.execute(
        "UPDATE users SET status = ?, updated_at = ? WHERE id = ? AND status != ?",
        (USER_STATUS_DISABLED, ts, user_id, USER_STATUS_DELETED),
    )
    if cur.rowcount == 0:
        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "User not found")
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (ts, user_id))
    audit_log(
        conn,
        action="USER_DISABLED",
        actor_user_id=session["user_id"],
        target_user_id=user_id,
        ip=handler.client_address[0],
        metadata={"reason": reason},
    )
    conn.commit()
    handler.send_json(HTTPStatus.OK, {"status": USER_STATUS_DISABLED})


def enable_user(handler, conn: sqlite3.Connection, session: sqlite3.Row, user_id: str) -> None:
    ts = now_ts()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "User not found")
    if user["status"] == USER_STATUS_DELETED:
        raise ApiError(HTTPStatus.CONFLICT, "CONFLICT", "Cannot enable deleted user")
    new_status = USER_STATUS_ACTIVE if user["email_verified_at"] is not None else USER_STATUS_PENDING
    conn.execute("UPDATE users SET status = ?, updated_at = ? WHERE id = ?", (new_status, ts, user_id))
    audit_log(conn, action="USER_ENABLED", actor_user_id=session["user_id"], target_user_id=user_id, ip=handler.client_address[0])
    conn.commit()
    handler.send_json(HTTPStatus.OK, {"status": new_status})


def revoke_sessions(handler, conn: sqlite3.Connection, session: sqlite3.Row, user_id: str) -> None:
    user = conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "User not found")
    ts = now_ts()
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (ts, user_id))
    audit_log(conn, action="SESSIONS_REVOKED", actor_user_id=session["user_id"], target_user_id=user_id, ip=handler.client_address[0])
    conn.commit()
    handler.send_no_content()


def list_audit_logs(handler, conn: sqlite3.Connection, q: dict[str, list[str]]) -> None:
    limit = 50
    cursor = 0
    if "limit" in q:
        try:
            limit = max(1, min(200, int(q["limit"][0])))
        except Exception:
            limit = 50
    if "cursor" in q:
        try:
            cursor = max(0, int(q["cursor"][0]))
        except Exception:
            cursor = 0

    rows = conn.execute(
        "SELECT id, action, actor_user_id, target_user_id, ip, created_at, metadata_json FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, cursor),
    ).fetchall()
    items = []
    for r in rows:
        try:
            meta = json.loads(r["metadata_json"] or "{}")
        except Exception:
            meta = {}
        items.append(
            {
                "id": r["id"],
                "action": r["action"],
                "actorUserId": r["actor_user_id"],
                "targetUserId": r["target_user_id"],
                "ip": r["ip"],
                "createdAt": iso_ts(r["created_at"]),
                "metadata": meta,
            }
        )
    next_cursor = cursor + len(items) if len(items) == limit else None
    handler.send_json(
        HTTPStatus.OK,
        {"items": items, "pageInfo": {"nextCursor": next_cursor, "hasNextPage": next_cursor is not None}},
    )
