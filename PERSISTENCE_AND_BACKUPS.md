# Areej persistence, storage and backup operations

## Current architecture

- The Flask application keeps SQLite as its local-development default.
- Production can use the isolated PostgreSQL schema `areej_app` by setting the private Render environment variable `AREEJ_DATABASE_URL`.
- The existing Supabase `public` schema is not replaced by the Flask compatibility schema.
- Private file uploads can use the existing private bucket `areej-private-files` when `AREEJ_STORAGE_BACKEND=supabase`.
- The server needs `SUPABASE_URL` and a server-only `SUPABASE_SECRET_KEY`. Never use a browser publishable/anon key for this server operation.

## Supabase migrations

The existing project already contains the `areej_app` schema and the core tables. Do not rerun the initial schema migration against populated tables as a data import. Apply only the reviewed incremental migration `migrations/002_areej_login_attempts.sql` to add the PostgreSQL table required by the hardened login throttle.

The compatibility schema has Row Level Security disabled, which triggers a Supabase Security Advisor warning. A read-only privilege check previously confirmed that `anon` and `authenticated` have no schema USAGE or table SELECT grants on this schema. The Flask app uses a server-side PostgreSQL connection. Do not blindly enable RLS without designing and testing server policies; enabling RLS with no policies can break application access. Keep the schema and all its tables/sequences inaccessible to client roles.

## Render staging configuration

Do not add these to production until staging tests and backup/restore checks pass. Configure a separate staging service with:

- `AREEJ_DATABASE_URL`: private PostgreSQL connection string for the existing Supabase project.
- `AREEJ_SECRET_KEY`: stable random Flask session secret.
- `AREEJ_COOKIE_SECURE=1`.
- `AREEJ_STORAGE_BACKEND=supabase`.
- `SUPABASE_URL`: project URL.
- `SUPABASE_SECRET_KEY`: server-only secret.
- `AREEJ_SUPABASE_BUCKET=areej-private-files`.

Do not commit any values. Do not place the database URL or secret key in GitHub source, screenshots, logs or chat. Confirm the bucket remains private and its 5 MB limit matches Flask's request limit.

## Encrypted database backups

The workflow `.github/workflows/areej-daily-backup.yml` runs daily and can also be started manually. It requires these GitHub Actions secrets:

- `AREEJ_DATABASE_URL`: private PostgreSQL connection string.
- `AREEJ_BACKUP_AGE_RECIPIENT`: age public recipient used to encrypt the dump.

It creates a custom-format dump of `public` and `areej_app`, encrypts it with age, removes the plaintext temporary dump, and uploads only the encrypted file as a private repository artifact with 30-day retention.

For longer-term independent retention, configure a private Cloudflare R2 bucket and these additional GitHub Actions secrets: `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and `R2_BUCKET`. The workflow uploads the encrypted backup to `areej/database/` when all four are present. Configure R2 lifecycle/versioning and access controls in the Cloudflare dashboard; do not assume the bucket is permanent until a restore test succeeds.

Keep the age identity/private key offline and separate from GitHub. Never store the age private key in this repository. To restore, first download an encrypted backup to a trusted machine, decrypt it with the offline age identity, and restore it only into a separate staging database using `pg_restore`. Never run a destructive restore against production as a test.

## Important limitations

- The encrypted database backup covers PostgreSQL schemas, not Supabase Storage objects. A separate encrypted Storage-object backup and restore test is still required before claiming full disaster recovery.
- GitHub artifacts expire after 30 days. R2 retention is optional and must be configured before this becomes long-term off-site backup.
- The migration scripts are for a fresh/empty staging schema. They deliberately refuse to overwrite populated destination tables. The existing Areej Supabase compatibility schema already contains records, so do not run the import script against it.
- The production Render service must not be switched to PostgreSQL or Supabase Storage until a staging service has passed all four portal, messaging, upload, login-throttle, backup and restore tests.
