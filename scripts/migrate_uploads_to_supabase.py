"""Copy Areej uploads from a private SQLite backup into a private Supabase bucket.

Run after the database copy. The source SQLite database is opened read-only. The
script uploads all referenced files first, then updates PostgreSQL paths in one
transaction. Missing source files stop the run before any upload starts.
"""
import mimetypes
import os
import sqlite3
from pathlib import Path

def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value

def main() -> None:
    sqlite_path = Path(required("AREEJ_SQLITE_PATH")).resolve()
    uploads_root = Path(required("AREEJ_UPLOADS_ROOT")).resolve()
    database_url = required("DATABASE_URL")
    supabase_url = required("SUPABASE_URL")
    supabase_key = (os.environ.get("SUPABASE_SECRET_KEY") or
                    os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
    if not supabase_key:
        raise SystemExit("Set SUPABASE_SECRET_KEY in your private terminal environment.")
    bucket = os.environ.get("AREEJ_SUPABASE_BUCKET", "areej-private-files").strip()
    if not sqlite_path.is_file():
        raise SystemExit(f"SQLite backup not found: {sqlite_path}")

    import psycopg
    from psycopg.rows import dict_row
    from supabase import create_client

    source = sqlite3.connect(f"file:{sqlite_path.as_posix()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    jobs = []
    specs = [
        ("enrollments", "id", "payment_proof", "payment-proofs", "uploads/payment-proofs"),
        ("messages", "id", "attachment_path", "messages", "uploads/messages"),
        ("assignment_submissions", "id", "file_path", "assignment-submissions", "uploads/messages"),
    ]
    try:
        for table, id_col, path_col, category, folder in specs:
            rows = source.execute(
                f"""SELECT {id_col}, {path_col} FROM {table} WHERE {path_col} IS NOT NULL AND {path_col} <> ''"""
            ).fetchall()
            for row in rows:
                old_path = str(row[path_col])
                if old_path.startswith(category + "/"):
                    continue
                filename = Path(old_path).name
                if filename != old_path or filename in {"", ".", ".."}:
                    raise SystemExit(f"Unsafe legacy path in {table} id={row[id_col]}: {old_path}")
                local_path = uploads_root / folder / filename
                if not local_path.is_file():
                    raise SystemExit(f"Missing upload for {table} id={row[id_col]}: {local_path}")
                jobs.append((table, id_col, path_col, int(row[id_col]), old_path,
                             f"{category}/{filename}", local_path))
    finally:
        source.close()

    client = create_client(supabase_url, supabase_key)
    with psycopg.connect(database_url, options="-c search_path=areej_app,public",
                         row_factory=dict_row) as conn:
        for table, id_col, path_col, row_id, old_path, new_path, local_path in jobs:
            found = conn.execute(f"SELECT {id_col} FROM {table} WHERE {id_col} = %s",
                                 (row_id,)).fetchone()
            if not found:
                raise SystemExit(f"Destination row missing: {table} id={row_id}")
        for table, id_col, path_col, row_id, old_path, new_path, local_path in jobs:
            content_type = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
            client.storage.from_(bucket).upload(
                new_path, local_path.read_bytes(),
                {"content-type": content_type, "upsert": "true"},
            )
        with conn.transaction():
            for table, id_col, path_col, row_id, old_path, new_path, local_path in jobs:
                result = conn.execute(
                    f"UPDATE {table} SET {path_col} = %s WHERE {id_col} = %s AND {path_col} = %s",
                    (new_path, row_id, old_path),
                )
                if result.rowcount not in (0, 1):
                    raise RuntimeError(f"Unexpected update count for {table} id={row_id}")
    print(f"Uploaded and mapped {len(jobs)} file(s) to private bucket {bucket!r}.")
    print("Verify downloads in the staging app before production cutover.")

if __name__ == "__main__":
    main()
