"""Create an encrypted custom-format backup of Areej's PostgreSQL schemas.

Requires pg_dump and age on PATH. The plaintext dump is removed even if
encryption fails. Only the encrypted output should be retained or uploaded.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    database_url = os.environ.get("AREEJ_DATABASE_URL", "").strip()
    recipient = os.environ.get("AREEJ_BACKUP_AGE_RECIPIENT", "").strip()
    if not database_url or not recipient:
        raise SystemExit("Set AREEJ_DATABASE_URL and AREEJ_BACKUP_AGE_RECIPIENT as private environment secrets.")
    for executable in ("pg_dump", "age"):
        if not shutil.which(executable):
            raise SystemExit(f"Required backup utility not found on PATH: {executable}")

    output_dir = Path(os.environ.get("AREEJ_BACKUP_DIR", "backups"))
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    encrypted_path = output_dir / f"areej-postgres-{stamp}.dump.age"

    with tempfile.TemporaryDirectory(prefix="areej-db-backup-") as temporary:
        plain_path = Path(temporary) / "database.dump"
        environment = os.environ.copy()
        environment.setdefault("PGSSLMODE", "require")
        subprocess.run(
            ["pg_dump", "--dbname", database_url, "--format=custom", "--no-owner", "--no-acl",
             "--schema=public", "--schema=areej_app", "--file", str(plain_path)],
            env=environment, check=True, stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["age", "--recipient", recipient, "--output", str(encrypted_path), str(plain_path)],
            check=True, stdout=subprocess.DEVNULL,
        )

    digest = hashlib.sha256(encrypted_path.read_bytes()).hexdigest()
    print(f"Encrypted backup created: {encrypted_path.name}")
    print(f"SHA-256: {digest}")
    print("No plaintext database dump was retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
