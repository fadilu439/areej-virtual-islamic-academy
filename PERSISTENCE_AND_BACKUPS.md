# Areej persistence, storage and backup operations

## Current architecture

- Flask uses SQLite locally.
- The intended persistent backend is PostgreSQL in the server-only `areej_app` schema.
- Private uploads use the private Supabase Storage bucket `areej-private-files`.
- Database URLs and Supabase server secrets must remain server-side.

## Supabase migrations

- The production database already contains `areej_app.login_attempts`; migration 002 is already represented by the existing login-throttle migration and must not be replayed.
- Migration 003 hardens existing `public` table privileges, public functions/sequences, and the Flask-only `areej_app` schema.
- Migration 003 preserves existing public CRUD grants and does not change RLS policies or RLS state.
- It also tightens default privileges for objects created by the project `postgres` role.
- Supabase-hosted project access does not permit the project `postgres` role to alter default ACLs owned by the managed `supabase_admin` role. Migration 003 deliberately does not attempt that unsupported operation. Managed-role defaults require a separate platform-supported review; do not claim those defaults are hardened by this migration.
- `areej_app` remains server-only. Do not enable RLS there without policies designed and tested for the Flask server's connection role.

The migration has a disposable PostgreSQL regression test in `tests/sql/test_security_permissions_migration.sql`. It tests current privileges and future objects created by the project `postgres` role.

## Production deployment safeguards

The user has authorized proceeding directly against the current Production project because its data is test data and may be lost. This does not authorize reckless deletion or unreviewed application deployment. Before each production change:
1. Confirm the exact project/service target.
2. Inspect the SQL or code diff.
3. Apply the smallest reversible change.
4. Verify grants, RLS, login, and the public site immediately afterwards.
5. Keep Render Auto-Deploy disabled until a separate deployment check is approved.

## Storage and backups

The four current Storage buckets are private: `academy-learning`, `areej-private-files`, `chat-attachments`, and `payment-proofs`. The encrypted backup workflow exports the database and objects. GitHub artifacts expire after 30 days; independent long-term retention requires a configured private object-storage destination and a restore test.

Never place database URLs, service-role keys, Supabase secret keys, or the age private key in GitHub source, screenshots, logs, or chat. Keep the age identity offline.
