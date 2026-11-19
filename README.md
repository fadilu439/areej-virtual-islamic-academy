# Areej Virtual Islamic Academy

A Flask-based online Islamic academy website with a public homepage and separate Admin, Staff, Student and Parent portals.

## Local development (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

The local development database is SQLite. The app does **not** create predictable demo accounts. To create the first local administrator, set a private password before starting the app for the first time:

```powershell
$env:AREEJ_INITIAL_ADMIN_PASSWORD = "choose-a-long-private-password"
python app.py
```

The initial administrator is created only when no admin account exists. Do not put the password in source control or share it in screenshots. If an administrator already exists, the app preserves that account.

## Tests

```powershell
python -m pip install "pytest>=8,<10"
python -m pytest -q
```

The GitHub Actions workflow runs syntax checks and security/regression tests on the integration branch and pull requests.

## Target production architecture (not yet activated)

- Render hosts the Flask web application.
- Supabase PostgreSQL stores persistent application records in the isolated `areej_app` schema.
- Supabase Storage stores private uploads in the private `areej-private-files` bucket.
- SQLite remains available for local development.
- The active production Render service has **not yet been switched** to PostgreSQL or Supabase Storage. Keep the current deployment unchanged until a separate staging deployment passes all checks.
- The browser never receives database credentials or the Supabase server-only Storage secret.

See [PERSISTENCE_AND_BACKUPS.md](PERSISTENCE_AND_BACKUPS.md) for staging configuration, migrations, encrypted backup setup and restore requirements.

## Security requirements

- Set a stable, high-entropy `AREEJ_SECRET_KEY` in the Render environment.
- Set `AREEJ_COOKIE_SECURE=1` for HTTPS production.
- Use a private `AREEJ_DATABASE_URL` only after staging tests pass. Prefer the Supabase Session Pooler connection string if the Render network cannot reach the direct database endpoint.
- For private file storage, set `AREEJ_STORAGE_BACKEND=supabase`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and `AREEJ_SUPABASE_BUCKET=areej-private-files`.
- Never use the Supabase publishable/anon key as the server database password or server Storage secret.
- Do not expose the `areej_app` schema to `anon` or `authenticated` client roles. Do not enable RLS without tested policies for the server's access model.
- Do not switch the production Render service to PostgreSQL or Storage until a staging service has passed all portal, upload, backup and restore checks.

## Important

The database import scripts refuse to overwrite populated destination tables. The existing Areej Supabase compatibility schema already contains records, so do not run the SQLite import script against that populated schema. Do not delete local source files after a migration until the destination has been verified and backed up.
