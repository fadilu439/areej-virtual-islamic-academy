"""PostgreSQL adapter for the SQLite-style SQL used by Areej.

The application connects with a server-side database URL and uses the isolated
areej_app schema. Never expose this connection or its credentials to browsers.
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
            connect_timeout=10,
            application_name="areej-academy",
            options="-c search_path=areej_app,public",
        )
        return cls(connection)

    @staticmethod
    def _translate(statement: str) -> str:
        query = statement.strip()
        upper = query.upper()

        if upper.startswith("INSERT OR IGNORE INTO "):
            query = re.sub(
                r"^INSERT\s+OR\s+IGNORE\s+INTO",
                "INSERT INTO",
                query,
                count=1,
                flags=re.IGNORECASE,
            )
            query = query.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

        elif upper.startswith("INSERT OR REPLACE INTO "):
            query = re.sub(
                r"^INSERT\s+OR\s+REPLACE\s+INTO",
                "INSERT INTO",
                query,
                count=1,
                flags=re.IGNORECASE,
            )
            table_match = re.match(
                r"INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)",
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

        # The current app's SQL statements do not contain question marks inside
        # quoted SQL literals. Keep this adapter narrow and covered by tests.
        return query.replace("?", "%s")

    def execute(self, statement: str, parameters=()):
        return self._connection.execute(self._translate(statement), parameters)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()
