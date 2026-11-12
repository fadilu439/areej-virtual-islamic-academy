"""Copy the existing SQLite Areej database into the isolated Supabase schema.

Usage (PowerShell):
  $env:AREEJ_SQLITE_PATH = "C:\\path\\to\\areej_academy.db"
  $env:DATABASE_URL = "postgresql://..."
  python scripts/migrate_sqlite_to_postgres.py

The script never deletes or modifies the SQLite source. It stops if the
destination contains rows, preserving any pre-existing Supabase data.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import psycopg
from psycopg import sql

TABLES = (
    "users",
    "courses",
    "enrollments",
    "messages",
    "classes",
    "enrollments_academic",
    "attendance",
    "assignments",
    "assignment_submissions",
    "results",
    "learning_materials",
    "announcements",
    "parent_links",
)


def main() -> int:
    sqlite_path = os.environ.get("AREEJ_SQLITE_PATH")
    database_url = os.environ.get("DATABASE_URL")
    if not sqlite_path or not database_url:
        print("Set AREEJ_SQLITE_PATH and DATABASE_URL first.", file=sys.stderr)
        return 2

    source = Path(sqlite_path).expanduser()
    if not source.is_file():
        print(f"SQLite database not found: {source}", file=sys.stderr)
        return 2

    src = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    try:
        with psycopg.connect(database_url) as dst:
            dst.execute("SET search_path TO areej_app, public")
            for table in TABLES:
                count = dst.execute(
                    sql.SQL("SELECT count(*) FROM areej_app.{}").format(
                        sql.Identifier(table)
                    )
                ).fetchone()[0]
                if count:
                    raise RuntimeError(
                        f"Destination table areej_app.{table} is not empty "
                        f"({count} rows). Refusing to overwrite."
                    )

            # All writes happen in one PostgreSQL transaction.
            for table in TABLES:
                rows = src.execute(
                    f'SELECT * FROM "{table}"'
                ).fetchall()
                if not rows:
                    print(f"{table}: 0 rows")
                    continue

                columns = list(rows[0].keys())
                insert = sql.SQL("INSERT INTO areej_app.{} ({}) VALUES ({})").format(
                    sql.Identifier(table),
                    sql.SQL(", ").join(map(sql.Identifier, columns)),
                    sql.SQL(", ").join(sql.Placeholder() for _ in columns),
                )
                dst.executemany(
                    insert,
                    [tuple(row[column] for column in columns) for row in rows],
                )
                print(f"{table}: copied {len(rows)} rows")

            # Preserve SQLite integer IDs and make future generated IDs continue safely.
            for table in TABLES:
                if table == "parent_links":
                    continue
                dst.execute(
                    sql.SQL(
                        "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
                        "GREATEST(COALESCE((SELECT MAX(id) FROM areej_app.{}), 1), 1), "
                        "EXISTS (SELECT 1 FROM areej_app.{}) )"
                    ).format(sql.Identifier(table), sql.Identifier(table)),
                    (f"areej_app.{table}",),
                )
        print("Migration completed. SQLite source was left unchanged.")
        return 0
    finally:
        src.close()


if __name__ == "__main__":
    raise SystemExit(main())
