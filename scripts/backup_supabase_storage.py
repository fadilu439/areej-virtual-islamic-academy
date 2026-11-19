"""Create an encrypted archive of every object in Areej's private Storage bucket.

Requires the Supabase Python client and age on PATH. Files are downloaded to a
temporary tar stream, encrypted, and never retained in plaintext on disk.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

from supabase import create_client


def safe_object_key(prefix: str, name: str) -> str:
    if not name or name in {".", ".."} or "\\" in name or "/" in name:
        raise ValueError("Unsafe Storage object name.")
    key = f"{prefix}/{name}" if prefix else name
    path = PurePosixPath(key)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Unsafe Storage object path.")
    return path.as_posix()


def list_all_objects(bucket, prefix: str = ""):
    offset = 0
    page_size = 100
    while True:
        entries = bucket.list(prefix, {"limit": page_size, "offset": offset})
        if not entries:
            break
        for entry in entries:
            name = entry.get("name", "")
            key = safe_object_key(prefix, name)
            if entry.get("id") is None:
                yield from list_all_objects(bucket, key)
            else:
                yield key
        if len(entries) < page_size:
            break
        offset += page_size


def main() -> int:
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = (
        os.environ.get("SUPABASE_SECRET_KEY")
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or ""
    ).strip()
    recipient = os.environ.get("AREEJ_BACKUP_AGE_RECIPIENT", "").strip()
    bucket_name = os.environ.get("AREEJ_SUPABASE_BUCKET", "areej-private-files").strip()
    if not url or not key or not recipient:
        raise SystemExit(
            "Set SUPABASE_URL, SUPABASE_SECRET_KEY and AREEJ_BACKUP_AGE_RECIPIENT privately."
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,62}", bucket_name):
        raise SystemExit("Invalid AREEJ_SUPABASE_BUCKET value.")
    if not shutil.which("age"):
        raise SystemExit("Required backup utility not found on PATH: age")

    output_dir = os.environ.get("AREEJ_BACKUP_DIR", "backups")
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    encrypted_path = os.path.join(output_dir, f"areej-storage-{stamp}.tar.gz.age")
    client = create_client(url, key)
    bucket = client.storage.from_(bucket_name)

    with tempfile.TemporaryDirectory(prefix="areej-storage-backup-") as temporary:
        archive_path = os.path.join(temporary, "storage.tar.gz")
        count = 0
        with tarfile.open(archive_path, "w:gz") as archive:
            for object_key in list_all_objects(bucket):
                payload = bytes(bucket.download(object_key))
                info = tarfile.TarInfo(name=object_key)
                info.size = len(payload)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))
                count += 1

        subprocess.run(
            ["age", "--recipient", recipient, "--output", encrypted_path, archive_path],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    digest = hashlib.sha256(open(encrypted_path, "rb").read()).hexdigest()
    print(f"Encrypted Storage backup created for {count} object(s): {os.path.basename(encrypted_path)}")
    print(f"SHA-256: {digest}")
    print("No plaintext Storage archive was retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
