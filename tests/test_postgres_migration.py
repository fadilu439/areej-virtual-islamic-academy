"""Integration test for the incremental PostgreSQL login-throttling migration.

Runs only when AREEJ_TEST_DATABASE_URL points at a disposable CI database.
It creates an isolated schema and never connects to the configured Supabase project.
"""
import os
from pathlib import Path

import pytest

DATABASE_URL = os.environ.get("AREEJ_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="requires an isolated PostgreSQL test database",
)


def test_login_attempts_migration_creates_private_table_and_index():
    import psycopg

    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "002_areej_login_attempts.sql"
    )

    with psycopg.connect(DATABASE_URL) as conn:
        # The Supabase migration revokes access from these client roles.
        # Create equivalents in the disposable CI database.
        conn.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                    CREATE ROLE anon NOLOGIN;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                    CREATE ROLE authenticated NOLOGIN;
                END IF;
            END
            $$;
            """
        )
        conn.execute("DROP SCHEMA IF EXISTS areej_app CASCADE")
        conn.execute("CREATE SCHEMA areej_app")

        sql = migration.read_text(encoding="utf-8")
        for statement in sql.split(";"):
            if statement.strip():
                conn.execute(statement)

        columns = {
            row[0]
            for row in conn.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'areej_app'
                  AND table_name = 'login_attempts'
                """
            ).fetchall()
        }
        assert columns == {
            "attempt_key",
            "window_started_at",
            "failed_attempts",
            "blocked_until",
        }

        indexes = {
            row[0]
            for row in conn.execute(
                """
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = 'areej_app'
                  AND tablename = 'login_attempts'
                """
            ).fetchall()
        }
        assert "login_attempts_pkey" in indexes
        assert "idx_areej_login_attempts_window" in indexes

        for role in ("anon", "authenticated"):
            allowed = conn.execute(
                "SELECT has_table_privilege(%s, 'areej_app.login_attempts', 'SELECT')",
                (role,),
            ).fetchone()[0]
            assert allowed is False, f"{role} unexpectedly has SELECT access"

        conn.execute("DROP SCHEMA areej_app CASCADE")
