from __future__ import annotations

import mimetypes
import sqlite3
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import admin_api
import auth_api
import db
import dev_api
import me_api
from api_common import ApiError, clear_cookie, json_bytes, now_ts, parse_cookies, set_cookie
from constants import (
    COOKIE_CSRF,
    COOKIE_SESSION,
    ROLE_ADMIN,
    ROLE_SUPER_ADMIN,
    USER_STATUS_DELETED,
    USER_STATUS_DISABLED,
)
from security import sha256_hex


APP_DIR = Path(__file__).resolve().parent
PAGES_DIR = APP_DIR / "pages"
STATIC_DIR = APP_DIR / "static"


class UmsHandler(BaseHTTPRequestHandler):
    server_version = "UMS-Demo/1.0"

    @property
    def db_path(self) -> Path:
        return self.server.db_path  # type: ignore[attr-defined]

    @property
    def cookie_secure(self) -> bool:
        return self.server.cookie_secure  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path.startswith("/v1/"):
                self._handle_api(parsed)
                return
            self._handle_pages_or_static(parsed.path)
        except ApiError as e:
            self.send_json(int(e.status), {"error": {"code": e.code, "message": e.message}})
        except Exception as e:
            self.send_json(
                int(HTTPStatus.INTERNAL_SERVER_ERROR),
                {"error": {"code": "INTERNAL_ERROR", "message": "Internal server error"}},
            )
            self.log_error("Unhandled error: %r", e)

    def send_json(
        self,
        status: int,
        payload: Any,
        *,
        set_cookies: list[dict[str, Any]] | None = None,
        clear_cookies: list[str] | None = None,
    ) -> None:
        raw = json_bytes(payload)
        self.send_response(status)
        if set_cookies:
            for spec in set_cookies:
                set_cookie(self, secure=self.cookie_secure, **spec)
        if clear_cookies:
            for name in clear_cookies:
                clear_cookie(self, name)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_no_content(
        self,
        *,
        set_cookies: list[dict[str, Any]] | None = None,
        clear_cookies: list[str] | None = None,
    ) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        if set_cookies:
            for spec in set_cookies:
                set_cookie(self, secure=self.cookie_secure, **spec)
        if clear_cookies:
            for name in clear_cookies:
                clear_cookie(self, name)
        self.end_headers()

    def _send_file(self, file_path: Path) -> None:
        content = file_path.read_bytes()
        content_type, _ = mimetypes.guess_type(str(file_path))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()

    def _handle_pages_or_static(self, path: str) -> None:
        if path == "/":
            self._redirect("/login")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            file_path = (STATIC_DIR / rel).resolve()
            if STATIC_DIR.resolve() not in file_path.parents or not file_path.exists() or not file_path.is_file():
                raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Not found")
            self._send_file(file_path)
            return

        page_map = {
            "/login": "login.html",
            "/signup": "signup.html",
            "/forgot-password": "forgot-password.html",
            "/reset-password": "reset-password.html",
            "/verify-email": "verify-email.html",
            "/account": "account.html",
            "/admin/users": "admin-users.html",
            "/dev/outbox": "outbox.html",
        }
        if path in page_map:
            self._send_file((PAGES_DIR / page_map[path]).resolve())
            return

        raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Not found")

    def _get_current_session(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        cookies = parse_cookies(self)
        token = cookies.get(COOKIE_SESSION)
        if not token:
            return None
        token_hash = sha256_hex(token)
        row = conn.execute(
            """
            SELECT s.*, u.status
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        ts = now_ts()
        if row["revoked_at"] is not None or row["expires_at"] <= ts:
            return None
        if row["status"] in (USER_STATUS_DISABLED, USER_STATUS_DELETED):
            return None
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (ts, row["id"]))
        return row

    def require_session(self, conn: sqlite3.Connection) -> sqlite3.Row:
        session = self._get_current_session(conn)
        if not session:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Not authenticated")
        return session

    def require_csrf(self, session: sqlite3.Row) -> None:
        cookies = parse_cookies(self)
        csrf_cookie = cookies.get(COOKIE_CSRF) or ""
        csrf_header = self.headers.get("x-csrf-token") or ""
        if not csrf_cookie or not csrf_header:
            raise ApiError(HTTPStatus.FORBIDDEN, "CSRF_REQUIRED", "CSRF token required")
        if csrf_cookie != csrf_header or csrf_cookie != session["csrf_token"]:
            raise ApiError(HTTPStatus.FORBIDDEN, "CSRF_INVALID", "CSRF token invalid")

    def _handle_api(self, parsed) -> None:
        method = self.command.upper()
        path = parsed.path
        q = parse_qs(parsed.query)

        with db.connect(self.db_path) as conn:
            if path == "/v1/auth/signup" and method == "POST":
                auth_api.signup(self, conn)
                return
            if path == "/v1/auth/verify-email" and method == "POST":
                auth_api.verify_email(self, conn)
                return
            if path == "/v1/auth/login" and method == "POST":
                auth_api.login(self, conn)
                return
            if path == "/v1/auth/logout" and method == "POST":
                session = self.require_session(conn)
                self.require_csrf(session)
                auth_api.logout(self, conn, session)
                return
            if path == "/v1/auth/logout-all" and method == "POST":
                session = self.require_session(conn)
                self.require_csrf(session)
                auth_api.logout_all(self, conn, session)
                return
            if path == "/v1/auth/password/forgot" and method == "POST":
                auth_api.forgot_password(self, conn)
                return
            if path == "/v1/auth/password/reset" and method == "POST":
                auth_api.reset_password(self, conn)
                return

            if path == "/v1/me" and method == "GET":
                session = self.require_session(conn)
                me_api.get_me(self, conn, session)
                return
            if path == "/v1/me" and method == "PATCH":
                session = self.require_session(conn)
                self.require_csrf(session)
                me_api.update_me(self, conn, session)
                return
            if path == "/v1/me/password" and method == "POST":
                session = self.require_session(conn)
                self.require_csrf(session)
                me_api.change_password(self, conn, session)
                return
            if path == "/v1/me/sessions" and method == "GET":
                session = self.require_session(conn)
                me_api.list_sessions(self, conn, session)
                return
            if path.startswith("/v1/me/sessions/") and method == "DELETE":
                session = self.require_session(conn)
                self.require_csrf(session)
                session_id = path[len("/v1/me/sessions/") :]
                me_api.revoke_session(self, conn, session, session_id)
                return
            if path == "/v1/me/delete" and method == "POST":
                session = self.require_session(conn)
                self.require_csrf(session)
                me_api.delete_account(self, conn, session)
                return

            if path == "/v1/dev/outbox" and method == "GET":
                dev_api.get_outbox(self, conn, q)
                return

            if path.startswith("/v1/admin/"):
                session = self.require_session(conn)
                if not (db.has_role(conn, session["user_id"], ROLE_ADMIN) or db.has_role(conn, session["user_id"], ROLE_SUPER_ADMIN)):
                    raise ApiError(HTTPStatus.FORBIDDEN, "FORBIDDEN", "Admin access required")

                if path == "/v1/admin/users" and method == "GET":
                    admin_api.list_users(self, conn, q)
                    return
                if path.startswith("/v1/admin/users/"):
                    rest = path[len("/v1/admin/users/") :]
                    parts = [p for p in rest.split("/") if p]
                    if parts:
                        target_user_id = parts[0]
                        if len(parts) == 1 and method == "GET":
                            admin_api.get_user(self, conn, target_user_id)
                            return
                        if len(parts) == 1 and method == "PATCH":
                            self.require_csrf(session)
                            admin_api.update_user(self, conn, session, target_user_id)
                            return
                        if len(parts) == 2 and parts[1] == "disable" and method == "POST":
                            self.require_csrf(session)
                            admin_api.disable_user(self, conn, session, target_user_id)
                            return
                        if len(parts) == 2 and parts[1] == "enable" and method == "POST":
                            self.require_csrf(session)
                            admin_api.enable_user(self, conn, session, target_user_id)
                            return
                        if len(parts) == 3 and parts[1] == "sessions" and parts[2] == "revoke" and method == "POST":
                            self.require_csrf(session)
                            admin_api.revoke_sessions(self, conn, session, target_user_id)
                            return

                if path == "/v1/admin/audit-logs" and method == "GET":
                    admin_api.list_audit_logs(self, conn, q)
                    return

            raise ApiError(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Not found")


def serve(host: str, port: int, *, db_path: Path, cookie_secure: bool) -> int:
    httpd: ThreadingHTTPServer = ThreadingHTTPServer((host, port), UmsHandler)
    httpd.db_path = db_path  # type: ignore[attr-defined]
    httpd.cookie_secure = bool(cookie_secure)  # type: ignore[attr-defined]

    print(f"[UMS] Listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[UMS] Shutting down")
    finally:
        httpd.server_close()
    return 0
