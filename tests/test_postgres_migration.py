"""Integration test for the incremental PostgreSQL login-throttling migration.

Runs only when AREEJ_TEST_DATABASE_URL points at a disposable CI database.
It creates an isolated schema and never connects to the configured Supabase project.
"""
import os
from pathlib import Path

import pytest

from postgres_compat import PostgresCompatConnection

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
            schema_allowed = conn.execute(
                "SELECT has_schema_privilege(%s, 'areej_app', 'USAGE')",
                (role,),
            ).fetchone()[0]
            table_allowed = conn.execute(
                "SELECT has_table_privilege(%s, 'areej_app.login_attempts', 'SELECT')",
                (role,),
            ).fetchone()[0]
            assert schema_allowed is False, f"{role} unexpectedly has schema USAGE"
            assert table_allowed is False, f"{role} unexpectedly has SELECT access"

        # Make the disposable schema visible to the adapter's separate connection.
        conn.commit()

        # Exercise the real PostgreSQL adapter against the migrated table,
        # including the SQLite-style placeholders used by the Flask app.
        compat = PostgresCompatConnection.connect(DATABASE_URL)
        try:
            compat.execute(
                "INSERT INTO login_attempts(attempt_key,window_started_at,failed_attempts,blocked_until) VALUES(?,?,?,?)",
                ("ci-adapter-check", 100.0, 1, None),
            )
            compat.commit()
            row = compat.execute(
                "SELECT failed_attempts FROM login_attempts WHERE attempt_key=?",
                ("ci-adapter-check",),
            ).fetchone()
            assert row["failed_attempts"] == 1
        finally:
            compat.close()

        conn.execute("DROP SCHEMA areej_app CASCADE")


def test_academic_reports_migration_adds_reports_and_submission_review_fields():
    import psycopg

    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "009_areej_academic_reports.sql"
    )
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("DROP SCHEMA IF EXISTS areej_app CASCADE")
        conn.execute("CREATE SCHEMA areej_app")
        conn.execute("""
            DO $
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
                    CREATE ROLE service_role NOLOGIN;
                END IF;
            END
            $;
        """)
        conn.execute("CREATE TABLE areej_app.users (id bigserial PRIMARY KEY)")
        conn.execute("CREATE TABLE areej_app.classes (id bigserial PRIMARY KEY)")
        conn.execute("CREATE TABLE areej_app.assignment_submissions (id bigserial PRIMARY KEY)")
        for statement in migration.read_text(encoding="utf-8").split(";"):
            if statement.strip():
                conn.execute(statement)
        columns = {
            row[0] for row in conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_schema='areej_app' AND table_name='assignment_submissions'"
            ).fetchall()
        }
        assert {"score","feedback","status","reviewed_by","reviewed_at"}.issubset(columns)
        reports = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='areej_app' AND table_name='academic_reports'"
        ).fetchone()
        assert reports is not None
        conn.execute("DROP SCHEMA areej_app CASCADE")
        conn.commit()


def test_student_profiles_migration_adds_private_and_public_profile_fields():
    import psycopg

    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "008_areej_student_profiles.sql"
    )
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("DROP SCHEMA IF EXISTS areej_app CASCADE")
        conn.execute("CREATE SCHEMA areej_app")
        conn.execute("CREATE TABLE areej_app.users (id bigserial PRIMARY KEY)")
        for statement in migration.read_text(encoding="utf-8").split(";"):
            if statement.strip():
                conn.execute(statement)
        columns = {
            row[0] for row in conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_schema='areej_app' AND table_name='users'"
            ).fetchall()
        }
        assert {
            "age", "date_of_birth", "gender", "country", "state", "phone",
            "email", "guardian_name", "programme", "bio", "profile_visibility",
            "show_location",
        }.issubset(columns)
        conn.execute("INSERT INTO areej_app.users(profile_visibility) VALUES('private')")
        with pytest.raises(Exception):
            conn.execute("INSERT INTO areej_app.users(profile_visibility) VALUES('everyone')")
        conn.rollback()
        conn.execute("DROP SCHEMA areej_app CASCADE")
