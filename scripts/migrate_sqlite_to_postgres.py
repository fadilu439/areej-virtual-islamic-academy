"""Copy SQLite Areej records into an empty isolated Supabase schema.

The SQLite source is opened read-only. Every destination table is checked
before any write. This script is for a fresh/empty staging schema only; it
will refuse to overwrite existing rows.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import psycopg
from psycopg import sql

TABLES = (
    "users", "courses", "enrollments", "messages", "classes",
    "enrollments_academic", "attendance", "assignments",
    "assignment_submissions", "results", "learning_materials",
    "announcements", "parent_links", "login_attempts",
)


def main() -> int:
    sqlite_path = os.environ.get("AREEJ_SQLITE_PATH", "").strip()
    database_url = os.environ.get("AREEJ_DATABASE_URL", "").strip()
    if not sqlite_path or not database_url:
        print("Set AREEJ_SQLITE_PATH and AREEJ_DATABASE_URL privately.", file=sys.stderr)
        return 2

    source_path = Path(sqlite_path).expanduser()
    if not source_path.is_file():
        print("The SQLite source file does not exist.", file=sys.stderr)
        return 2

    source = sqlite3.connect(f"file:{source_path.resolve()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        with psycopg.connect(database_url, options="-c search_path=areej_app,public") as destination:
            schema = destination.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name='areej_app'"
            ).fetchone()
            if not schema:
                raise RuntimeError("Destination schema areej_app is missing. Apply migrations first.")

            source_tables = {
                row["name"] for row in source.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            prepared = {}

            # Validate every table and every destination before the first insert.
            for table in TABLES:
                if table == "login_attempts" and table not in source_tables:
                    rows = []
                    source_columns = None
                else:
                    if table not in source_tables:
                        raise RuntimeError(f"Source SQLite table is missing: {table}")
                    rows = source.execute(f'SELECT * FROM "{table}"').fetchall()
                    source_columns = {row["name"] for row in source.execute(
                        f'PRAGMA table_info("{table}")'
                    ).fetchall()}

                destination_columns = {
                    row[0] for row in destination.execute(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema='areej_app' AND table_name=%s",
                        (table,),
                    ).fetchall()
                }
                if not destination_columns:
                    raise RuntimeError(f"Destination table is missing: areej_app.{table}")
                if source_columns is not None and source_columns != destination_columns:
                    missing = sorted(source_columns - destination_columns)
                    extra = sorted(destination_columns - source_columns)
                    raise RuntimeError(
                        f"Column mismatch for {table}; missing={missing}; extra={extra}. "
                        "No data has been copied."
                    )

                count = destination.execute(
                    sql.SQL("SELECT count(*) FROM areej_app.{}").format(sql.Identifier(table))
                ).fetchone()[0]
                if count:
                    raise RuntimeError(
                        f"Destination areej_app.{table} already contains {count} row(s). "
                        "Refusing to overwrite existing data."
                    )
                prepared[table] = rows

            with destination.cursor() as cursor:
                for table, rows in prepared.items():
                    if not rows:
                        print(f"{table}: 0 rows")
                        continue
                    columns = list(rows[0].keys())
                    statement = sql.SQL("INSERT INTO areej_app.{} ({}) VALUES ({})").format(
                        sql.Identifier(table),
                        sql.SQL(", ").join(map(sql.Identifier, columns)),
                        sql.SQL(", ").join(sql.Placeholder() for _ in columns),
                    )
                    cursor.executemany(
                        statement,
                        [tuple(row[column] for column in columns) for row in rows],
                    )
                    print(f"{table}: copied {len(rows)} row(s)")

            for table in TABLES:
                if table in {"parent_links", "login_attempts"}:
                    continue
                destination.execute(
                    sql.SQL(
                        "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
                        "GREATEST(COALESCE((SELECT MAX(id) FROM areej_app.{}), 1), 1), "
                        "EXISTS (SELECT 1 FROM areej_app.{}) )"
                    ).format(sql.Identifier(table), sql.Identifier(table)),
                    (f"areej_app.{table}",),
                )

        print("Migration completed. The original SQLite source was not modified.")
        return 0
    finally:
        source.close()


if __name__ == "__main__":
    raise SystemExit(main())
