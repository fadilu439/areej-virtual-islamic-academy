# Areej persistence, storage and backup operations

## Current architecture

- The Flask application keeps SQLite as its local-development default.
- Production can use the isolated PostgreSQL schema `areej_app` by setting the private Render environment variable `AREEJ_DATABASE_URL`.
- The existing Supabase `public` schema is not replaced by the Flask compatibility schema.
- Private file uploads can use the existing private bucket `areej-private-files` when `AREEJ_STORAGE_BACKEND=supabase`.
- The server needs `SUPABASE_URL` and a server-only `SUPABASE_SECRET_KEY`. Never use a browser publishable/anon key for this server operation.

## Supabase migrations

Apply reviewed migrations in order and only after a current encrypted backup has been created:

1. `migrations/002_areej_login_attempts.sql` adds the PostgreSQL table required by the hardened login throttle.
2. `migrations/003_areej_public_permissions_hardening.sql` removes unnecessary client maintenance privileges from existing `public` tables, removes direct client access to public sequences/functions that are not used by the current client policies, locks down the Flask-only `areej_app` schema, and tightens default privileges for future objects created by `postgres` and `supabase_admin`.

The permission migration intentionally preserves existing `SELECT`, `INSERT`, `UPDATE`, and `DELETE` table grants on `public` where they are currently present. Existing Row Level Security policies remain the row-level access control for those operations. It does not enable or disable RLS and does not change the existing policies. New public tables, sequences and functions require deliberate grants before client access is possible.

The compatibility schema `areej_app` has Row Level Security disabled because the Flask application uses a server-side PostgreSQL connection. Keep this schema and its tables, sequences, and functions inaccessible to `PUBLIC`, `anon`, and `authenticated`. Do not blindly enable RLS here: enabling it without policies can break the Flask backend.

The permission migration is covered by a disposable PostgreSQL regression test in `tests/sql/test_security_permissions_migration.sql`, which checks existing grants and the default privileges for both object-creating roles. The GitHub Actions test workflow runs this test against its own temporary PostgreSQL service; it does not connect to the hosted Supabase project.

Before applying migration 003 to the hosted project, verify the latest encrypted backup is downloadable and retain its decryption key offline. Apply it first to a separate staging database/schema, then test public course/announcement reads, admission submissions, all four portals, messaging, uploads and the Flask health endpoint. Do not apply it to production until those checks pass.

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

The workflow `.github/workflows/areej-daily-backup.yml` runs daily and can also be started manually. It backs up the configured four private buckets: `academy-learning`, `areej-private-files`, `chat-attachments`, and `payment-proofs`. It requires these GitHub Actions secrets:

- `AREEJ_DATABASE_URL`: private PostgreSQL connection string.
- `AREEJ_BACKUP_AGE_RECIPIENT`: age public recipient used to encrypt backups.
- `SUPABASE_URL` and `SUPABASE_SECRET_KEY`: server-only credentials used to list and download objects from the private Storage buckets.

It creates a custom-format dump of `public` and `areej_app`, then separately archives every object in the configured private Supabase Storage bucket. Both backups are encrypted with age; plaintext temporary files are removed. Only encrypted files are uploaded as GitHub Actions artifacts with 30-day retention.

For longer-term independent retention, configure a private Cloudflare R2 bucket and these additional GitHub Actions secrets: `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and `R2_BUCKET`. The workflow uploads the encrypted backup to `areej/database/` when all four are present. Configure R2 lifecycle/versioning and access controls in the Cloudflare dashboard; do not assume the bucket is permanent until a restore test succeeds.

Keep the age identity/private key offline and separate from GitHub. Never store the age private key in this repository. To restore, first download an encrypted backup to a trusted machine, decrypt it with the offline age identity, and restore it only into a separate staging database using `pg_restore`. Never run a destructive restore against production as a test.

## Important limitations

- The workflow includes a separate encrypted backup of objects in the configured private Storage bucket. A full restore test of both the database and every Storage object is still required before claiming disaster recovery is proven.
- GitHub artifacts expire after 30 days. R2 retention is optional and must be configured before this becomes long-term off-site backup.
- The migration scripts are for a fresh/empty staging schema. They deliberately refuse to overwrite populated destination tables. The existing Areej Supabase compatibility schema already contains records, so do not run the import script against it.
- The production Render service must not be switched to PostgreSQL or Supabase Storage until a staging service has passed all four portal, messaging, upload, login-throttle, backup and restore tests.
