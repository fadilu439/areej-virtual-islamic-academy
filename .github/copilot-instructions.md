# AREEJ Virtual Islamic Academy — Copilot Development Instructions

These instructions apply to all work in this repository.

## Project and source of truth
- Repository: `fadilu439/areej-virtual-islamic-academy`.
- Production website: https://areej-virtual-islamic-academy.onrender.com
- `main` is the protected release line and must remain stable.
- Use the existing application architecture, conventions, database adapter, migrations, tests, and documentation as the source of truth. Inspect relevant files before editing.

## Mandatory branch safety
- Do all feature development and fixes on the `development` branch.
- Before editing, run `git status --short --branch` and inspect the current branch.
- Fetch the latest remote refs. If not already on `development`, switch to it and pull its latest changes. If local changes exist, do not overwrite, reset, stash, or discard them without explicit approval.
- Never commit development changes directly to `main`.
- Never force-push, rewrite shared history, delete branches, or reset a branch without explicit approval.
- If the `development` branch is missing locally, create it from the latest `origin/main`; do not create a second branch with a different name unless asked.

## Preserve the existing application
- Do not remove, disable, rename, or break existing features unless the user explicitly requests it.
- Preserve all four portals: Admin, Staff, Student, and Parent; existing dashboards, authentication, authorization, messaging, Help Center, directories, profile settings, courses, and other existing modules.
- Keep the user interface in English only.
- Preserve current role boundaries and data privacy. Do not grant users access to records or actions outside their authorised scope.
- Prefer small, focused, backward-compatible changes. Do not rewrite working files or architecture unnecessarily.
- Check existing tests and patterns before adding dependencies, routes, tables, or migrations.

## Security and privacy
- Treat authentication, sessions, CSRF protection, password handling, uploads, message permissions, and database access as security-critical.
- Validate and authorize every sensitive server-side action; never rely only on hidden buttons or client-side checks.
- Do not expose secrets, credentials, personal data, private files, or database connection strings in source code, logs, commits, or responses.
- Do not weaken security controls to make a feature pass.
- Do not add permissive RLS policies such as `USING (true)`, grant broad privileges, or use BYPASSRLS as a shortcut.
- Do not change production database roles, grants, RLS policies, or user data.

## Production protection — no exceptions without explicit approval
- Do not deploy, release, or trigger a Render production deployment.
- Do not change Render production settings, auto-deploy configuration, environment variables, secrets, domains, or service configuration.
- Do not run migrations or SQL writes against production Supabase.
- Do not modify production data, storage buckets, backups, database permissions, or RLS policies.
- Do not merge a pull request into `main` or push commits to `main`.
- These actions require the user's separate, explicit approval after a clear explanation of the impact and risks.

## Development and verification workflow
1. Understand the requested change and inspect the relevant routes, templates, models, migrations, tests, and permissions.
2. Identify possible effects on all four portals and existing features.
3. Implement the smallest safe change on `development`.
4. Add or update automated tests for the behaviour and relevant access-control boundaries.
5. Run the relevant test suite, linting, type checks, migration checks, and security checks available in the repository.
6. Review the diff for accidental deletions, unrelated edits, secrets, unsafe SQL, and production configuration changes.
7. Do not claim a test passed unless it was actually run and passed. Clearly report any test that could not be run and why.
8. Do not merge or deploy.

## Database and migrations
- Follow the repository's existing migration system and database compatibility conventions.
- Make migrations safe, ordered, documented, and reversible where the project supports rollback.
- Test migrations against a disposable/local/test database, never production.
- Check PostgreSQL and SQLite compatibility wherever both are supported.
- Do not mark production migrations as applied or assume they have been deployed.

## Completion report
At the end of each task, report:
- What changed and why.
- Exact files changed.
- Tests/checks actually run and their results.
- Any unresolved issue, limitation, or risk.
- Confirmation that work remains on `development`, with no merge to `main` and no production deployment.

## Priority
The highest priority is to improve AREEJ Virtual Islamic Academy without damaging the currently working application, its data, its users' privacy, or the live production website. When uncertain, stop before a destructive or production-impacting action and ask the user.
