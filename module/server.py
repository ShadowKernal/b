from __future__ import annotations

import argparse
from pathlib import Path

import app
import db


def main() -> int:
    parser = argparse.ArgumentParser(description="UMS demo server (stdlib Python + SQLite)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--db", default=str(app.APP_DIR / "ums.sqlite3"))
    parser.add_argument("--cookie-secure", action="store_true", help="Set Secure cookies (requires https)")
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with db.connect(db_path) as conn:
        db.migrate(conn)
        seeded = db.seed_admin_if_empty(conn)
        if seeded:
            email, pw = seeded
            print(f"[UMS] Seeded admin user: {email}")
            print(f"[UMS] Seeded admin password: {pw}")
            print("[UMS] Dev outbox: http://localhost:8000/dev/outbox")

    return app.serve(args.host, args.port, db_path=db_path, cookie_secure=bool(args.cookie_secure))


if __name__ == "__main__":
    raise SystemExit(main())
