"""Copy referenced local Areej uploads into a private Supabase Storage bucket.

The source SQLite file is read-only and local files are never deleted. Run only
after the corresponding database rows have been copied to a staging database.
"""
from __future__ import annotations

import mimetypes
import os
import sqlite3
from pathlib import Path

TABLES = (
    ("enrollments", "id", "payment_proof", "payment-proofs", "uploads/payment-proofs"),
    ("messages", "id", "attachment_path", "messages", "uploads/messages"),
    ("assignment_submissions", "id", "file_path", "assignment-submissions", "uploads/messages"),
)


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def main() -> None:
    sqlite_path = Path(required("AREEJ_SQLITE_PATH")).resolve()
    uploads_root = Path(required("AREEJ_UPLOADS_ROOT")).resolve()
    database_url = required("AREEJ_DATABASE_URL")
    supabase_url = required("SUPABASE_URL")
    supabase_key = (
        os.environ.get("SUPABASE_SECRET_KEY")
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or ""
    ).strip()
    if not supabase_key:
        raise SystemExit("Set a server-only Supabase secret key privately.")
    bucket = os.environ.get("AREEJ_SUPABASE_BUCKET", "areej-private-files").strip()
    if not sqlite_path.is_file():
        raise SystemExit("The SQLite backup file does not exist.")

    import psycopg
    from supabase import create_client

    source = sqlite3.connect(f"file:{sqlite_path.as_posix()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    jobs = []
    try:
        for table, id_col, path_col, category, folder in TABLES:
            if not source.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone():
                continue
            rows = source.execute(
                f'SELECT "{id_col}", "{path_col}" FROM "{table}" '
                f'WHERE "{path_col}" IS NOT NULL AND "{path_col}" <> ""'
            ).fetchall()
            for row in rows:
                old_path = str(row[path_col])
                if old_path.startswith(category + "/"):
                    continue
                filename = Path(old_path).name
                if filename != old_path or filename in {"", ".", ".."}:
                    raise SystemExit(f"Unsafe source path in {table} record {row[id_col]}.")
                local_path = uploads_root / folder / filename
                if not local_path.is_file():
                    raise SystemExit(f"A referenced source file is missing: {table} record {row[id_col]}.")
                jobs.append((table, id_col, path_col, int(row[id_col]), old_path,
                             f"{category}/{filename}", local_path))
    finally:
        source.close()

    client = create_client(supabase_url, supabase_key)
    with psycopg.connect(database_url, options="-c search_path=areej_app,public") as conn:
        for table, id_col, path_col, row_id, old_path, new_path, local_path in jobs:
            found = conn.execute(
                f'SELECT "{id_col}" FROM "{table}" WHERE "{id_col}"=%s', (row_id,)
            ).fetchone()
            if not found:
                raise SystemExit(f"Destination record is missing: {table} id={row_id}.")

        for table, id_col, path_col, row_id, old_path, new_path, local_path in jobs:
            content_type = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
            client.storage.from_(bucket).upload(
                new_path, local_path.read_bytes(),
                {"content-type": content_type, "upsert": "true"},
            )

        with conn.transaction():
            for table, id_col, path_col, row_id, old_path, new_path, local_path in jobs:
                conn.execute(
                    f'UPDATE "{table}" SET "{path_col}"=%s '
                    f'WHERE "{id_col}"=%s AND "{path_col}"=%s',
                    (new_path, row_id, old_path),
                )

    print(f"Copied {len(jobs)} referenced file(s) to private bucket {bucket!r}.")
    print("Original local files were left untouched; verify downloads before cutover.")


if __name__ == "__main__":
    main()
