# UMS Module (Runnable Demo)

This folder contains a small, framework-agnostic reference implementation of the User Management System using:

- Backend: Python standard library (`http.server`) + SQLite
- Frontend: vanilla HTML/CSS/JS
- Email: a dev outbox UI (no real emails are sent)

## Run

From the repo root:

```powershell
python ums/module/server.py
```

Then open:

- Login: `http://localhost:8000/login`
- Dev email outbox (verification/reset codes): `http://localhost:8000/dev/outbox`

## Admin

On first run (empty DB), the server seeds an admin account and prints credentials in the console.

## Data

- SQLite DB file: `ums/module/ums.sqlite3`
- Delete `ums/module/ums.sqlite3` to reset the demo.

## Notes

- This is intended as a drop-in module you can adapt into your own stack. For production, swap the outbox for a real email provider, harden rate limits, add MFA, and run behind TLS.

