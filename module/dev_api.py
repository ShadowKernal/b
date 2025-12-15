from __future__ import annotations

import sqlite3
from http import HTTPStatus
from typing import Any

from api_common import iso_ts


def get_outbox(handler, conn: sqlite3.Connection, q: dict[str, list[str]]) -> None:
    limit = 20
    if "limit" in q:
        try:
            limit = max(1, min(100, int(q["limit"][0])))
        except Exception:
            limit = 20

    rows = conn.execute(
        "SELECT to_email, subject, body, created_at FROM dev_outbox ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    items: list[dict[str, Any]] = [
        {"to": r["to_email"], "subject": r["subject"], "body": r["body"], "createdAt": iso_ts(r["created_at"])}
        for r in rows
    ]
    handler.send_json(HTTPStatus.OK, {"items": items})

