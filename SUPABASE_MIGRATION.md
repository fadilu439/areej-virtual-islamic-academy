# Areej SQLite → Supabase migration (staging branch)

## Safety rules
- Work only on `feature/supabase-migration` until staging tests pass.
- Do not change the existing Render production service or its environment variables during this stage.
- Never commit a Supabase database password, service-role key, Flask secret, or production database URL.
- Keep a private backup of the original SQLite database and uploads before migration.

## What is prepared
- `migrations/001_areej_compat_schema.sql` creates an isolated `areej_app` schema in Supabase.
- `scripts/migrate_sqlite_to_postgres.py` copies the 13 tables used by the current Flask app, preserving numeric IDs and Werkzeug password hashes.
- The migration script is read-only against SQLite and refuses to write into any non-empty destination table.

## Important design choice
The current Flask app expects SQLite table names, integer IDs, `?` placeholders, and SQLite-specific `INSERT OR IGNORE/REPLACE` statements. The existing Supabase `public` schema has a different UUID-based model and its own RLS policies. We therefore do **not** overwrite those public tables. The compatibility schema gives the existing Flask app a safe PostgreSQL landing area. A later code change will connect Flask to this schema and replace SQLite-only SQL syntax carefully.

## Prepare a private database backup
1. Obtain a fresh SQLite backup from the currently running application using its Admin backup download, if that route is available.
2. Extract `areej_academy.db` privately on your computer. Keep the accompanying uploads folder too.
3. Do not upload the database backup or uploads to GitHub.

## Prepare Supabase
1. Open the Areej Supabase project → SQL Editor.
2. Run the complete contents of `migrations/001_areej_compat_schema.sql`.
3. In Supabase project settings, obtain the direct PostgreSQL connection string (not an API key). Keep it private and do not paste it into chat or GitHub.

## Run the copy from a trusted local computer
Install dependencies with `python -m pip install "psycopg[binary]>=3.2,<4"`, then in PowerShell set:
```powershell
$env:AREEJ_SQLITE_PATH = "C:\\private\\backup\\areej_academy.db"
$env:DATABASE_URL = "YOUR_PRIVATE_POSTGRES_CONNECTION_STRING"
python scripts/migrate_sqlite_to_postgres.py
```
The script prints copied row counts. It does not migrate uploaded files; those need a separate private Supabase Storage migration and URL/path update.

## Not yet switched
This commit intentionally does not switch `app.py`, Render, authentication, or live traffic. The next implementation step is a tested PostgreSQL adapter and a staging-only deployment. Existing login hashes are copied as-is; no password is needed for this data copy. Do not remove the existing admin account.
