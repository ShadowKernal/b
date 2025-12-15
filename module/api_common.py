from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from typing import Any


def now_ts() -> int:
    return int(time.time())


def iso_ts(ts: int | None) -> str | None:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def new_id() -> str:
    return str(uuid.uuid4())


@dataclass
class ApiError(Exception):
    status: int
    code: str
    message: str


def parse_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("content-length") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data
    except Exception:
        raise ApiError(HTTPStatus.BAD_REQUEST, "INVALID_JSON", "Invalid JSON body")


def parse_cookies(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    header = handler.headers.get("cookie")
    if not header:
        return {}
    cookie = SimpleCookie()
    cookie.load(header)
    out: dict[str, str] = {}
    for key, morsel in cookie.items():
        out[key] = morsel.value
    return out


def set_cookie(
    handler: BaseHTTPRequestHandler,
    name: str,
    value: str,
    *,
    http_only: bool,
    max_age: int | None,
    path: str = "/",
    same_site: str = "Lax",
    secure: bool = False,
) -> None:
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]["path"] = path
    cookie[name]["samesite"] = same_site
    if max_age is not None:
        cookie[name]["max-age"] = str(max_age)
    if http_only:
        cookie[name]["httponly"] = True
    if secure:
        cookie[name]["secure"] = True
    handler.send_header("Set-Cookie", cookie.output(header="").strip())


def clear_cookie(handler: BaseHTTPRequestHandler, name: str) -> None:
    set_cookie(handler, name, "", http_only=True, max_age=0)

