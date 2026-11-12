"""Small PostgreSQL adapter for the current SQLite-style Flask queries.

It intentionally targets the isolated areej_app schema and only translates
SQLite syntax currently used by app.py. Keep this adapter narrow and tested.
"""
from __future__ import annotations

import re
import psycopg
from psycopg.rows import dict_row


class PostgresCompatConnection:
    def __init__(self, connection):
        self._connection = connection

    @classmethod
    def connect(cls, database_url: str):
        connection = psycopg.connect(
            database_url,
            row_factory=dict_row,
            options="-c search_path=areej_app,public",
        )
        return cls(connection)

    @staticmethod
    def _translate(statement: str) -> str:
        query = statement.strip()
        upper = query.upper()

        if upper.startswith("INSERT OR IGNORE INTO "):
            query = re.sub(
                r"^INSERT\\s+OR\\s+IGNORE\\s+INTO",
                "INSERT INTO",
                query,
                count=1,
                flags=re.IGNORECASE,
            )
            query = query.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

        elif upper.startswith("INSERT OR REPLACE INTO "):
            query = re.sub(
                r"^INSERT\\s+OR\\s+REPLACE\\s+INTO",
                "INSERT INTO",
                query,
                count=1,
                flags=re.IGNORECASE,
            )
            table_match = re.match(
                r"INSERT\\s+INTO\\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                query,
                flags=re.IGNORECASE,
            )
            table = table_match.group(1).lower() if table_match else ""
            if table == "attendance":
                conflict = (
                    " ON CONFLICT (class_id, student_id, lesson_date) DO UPDATE SET "
                    "status = EXCLUDED.status, recorded_by = EXCLUDED.recorded_by"
                )
            elif table == "assignment_submissions":
                conflict = (
                    " ON CONFLICT (assignment_id, student_id) DO UPDATE SET "
                    "content = EXCLUDED.content, file_name = EXCLUDED.file_name, "
                    "file_path = EXCLUDED.file_path, submitted_at = EXCLUDED.submitted_at"
                )
            else:
                raise ValueError(f"Unsupported INSERT OR REPLACE table: {table}")
            query = query.rstrip().rstrip(";") + conflict

        # The existing Flask app uses qmark placeholders and does not place
        # question marks inside SQL string literals.
        return query.replace("?", "%s")

    def execute(self, statement: str, parameters=()):
        return self._connection.execute(self._translate(statement), parameters)

    def commit(self):
        self._connection.commit()

    def close(self):
        self._connection.close()
