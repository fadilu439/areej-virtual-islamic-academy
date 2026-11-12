# Areej SQLite → Supabase migration (staging branch)

## Safety rules
- Work only on `feature/supabase-migration` until staging tests pass.
- Do not change the existing Render production service or its environment variables during this stage.
- Never commit a Supabase database password, service-role key, Flask secret, or production database URL.
- Keep a private backup of the original SQLite database and uploads before migration.

## What is prepared
- `migrations/001_areej_compat_schema.sql` creates an isolated `areej_app` schema in Supabase.
- `scripts/migrate_sqlite_to_postgres.py` copies the 13 tables used by the current Flask app, preserving numeric IDs and Werkzeug password hashes.
- `postgres_compat.py` translates the SQLite SQL syntax currently used by the Flask routes.
- `app.py` now supports an **opt-in** `AREEJ_DATABASE_URL`; SQLite remains the default when that variable is absent.
- The migration script is read-only against SQLite and refuses to write into any non-empty destination table.

## Important design choice
The current Flask app expects SQLite table names, integer IDs, `?` placeholders, and SQLite-specific `INSERT OR IGNORE/REPLACE` statements. The existing Supabase `public` schema has a different UUID-based model and its own RLS policies. We therefore do **not** overwrite those public tables. The compatibility schema gives the existing Flask app a safe PostgreSQL landing area. The adapter selects this schema through its connection search path and translates the app's current qmark placeholders and two `INSERT OR ...` patterns. The public Supabase schema and its RLS policies remain untouched. The compatibility schema is kept private: the SQL migration revokes schema, table and sequence privileges from `PUBLIC`, `anon` and `authenticated`, so it is not a client-facing Data API. Only the server-side database connection should use it. Foreign-key constraints are deliberately deferred until source data has been checked for orphaned IDs.

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
The script prints copied row counts. It does not migrate uploaded files; use the separate Storage migration procedure below.

## Flask connection switch (staging only)
After the schema is created and the data-copy script succeeds, configure the **staging environment only** with `AREEJ_DATABASE_URL` set to the private PostgreSQL connection string. The app keeps SQLite mode when this variable is absent. Do not add this variable to the production Render service yet. The current username/password login remains Werkzeug hash verification against the copied `users.password_hash`; the hash is copied unchanged, so no password is needed for the data copy. Do not remove or recreate the existing admin account.

The app's PostgreSQL backup-download route currently returns HTTP 503; use the private migration backup procedure until a PostgreSQL backup/export workflow is implemented. Uploaded files are still stored on the app filesystem and have not yet been migrated to Supabase Storage. Do not cut over production until uploads, database backup/restore, connection pooling, and full portal tests are complete.


## Private file storage (staging only)

The app includes `storage_backend.py`. Local disk remains the default. When
`AREEJ_STORAGE_BACKEND=supabase` is enabled, new payment proofs, message
attachments, and assignment submissions are uploaded to the private bucket
named by `AREEJ_SUPABASE_BUCKET` (default: `areej-private-files`). Message
downloads still pass through the Flask route, which checks that the logged-in
user is the sender or recipient before retrieving the object. No Storage URL or
secret key is sent to the browser.

### Create the bucket
1. In Supabase Dashboard → Storage, create a bucket named
   `areej-private-files`.
2. Set it to **Private** (never public).
3. Set the maximum file size to 5 MB to match the Flask request limit.
4. Do not add public read policies. The Flask server uses a server-only secret
   key; keep it in the staging service's private environment variables only.

### Copy files after the database rows have been copied
Keep the original SQLite backup and its `uploads` directory together. In a
trusted local PowerShell terminal, set the following variables privately
(values must not be pasted into chat or committed):
```powershell
$env:AREEJ_SQLITE_PATH = "C:\\private\\backup\\areej_academy.db"
$env:AREEJ_UPLOADS_ROOT = "C:\\private\\backup"
$env:DATABASE_URL = "YOUR_PRIVATE_POSTGRES_CONNECTION_STRING"
$env:SUPABASE_URL = "YOUR_SUPABASE_PROJECT_URL"
$env:SUPABASE_SECRET_KEY = "YOUR_SERVER_ONLY_SECRET_KEY"
$env:AREEJ_SUPABASE_BUCKET = "areej-private-files"
python scripts/migrate_uploads_to_supabase.py
```
The script opens SQLite read-only, checks that every referenced local file and
destination row exists before uploading, then updates the PostgreSQL paths in a
transaction. If interrupted after uploads, rerunning is safe because it uses
stable object paths with upsert. It does not delete the source files.

### Enable Storage in staging
Only after the file-copy script succeeds, configure the **staging** service:
```text
AREEJ_STORAGE_BACKEND=supabase
SUPABASE_URL=<project URL>
SUPABASE_SECRET_KEY=<server-only secret key>
AREEJ_SUPABASE_BUCKET=areej-private-files
```
Do not set these on production Render yet. Do not use the publishable/anon key
as a substitute for the server secret. Rotate any secret key that has ever been
shared in chat, screenshots, logs, or source control.

### Current limitations and required tests
- The existing app currently has a protected message-attachment download route.
  Payment-proof and assignment-file viewing workflows still need end-to-end UI
  coverage before cutover.
- The migration script requires a complete, fresh SQLite backup plus the
  matching uploads directory. It cannot recover files already lost from an
  ephemeral Render filesystem.
- Test all four portals, file upload/download permissions, missing files,
  oversized uploads, database restore, and rollback before changing production.
- Storage object uploads happen before the PostgreSQL path update transaction;
  a failed database update may leave an unreferenced private object. Rerunning
  is safe, and cleanup can be done after verifying the migrated records.
