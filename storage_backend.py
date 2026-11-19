"""Private file storage adapter for Areej Academy.

Local disk is used for development. Production can opt into a private Supabase
Storage bucket using a server-only secret key. Never return public object URLs.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

from werkzeug.utils import secure_filename

MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def supabase_storage_enabled() -> bool:
    return os.environ.get("AREEJ_STORAGE_BACKEND", "local").strip().lower() == "supabase"


@lru_cache(maxsize=1)
def _storage_client():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = (
        os.environ.get("SUPABASE_SECRET_KEY")
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or ""
    ).strip()
    if not url or not key:
        raise RuntimeError(
            "Supabase Storage requires SUPABASE_URL and a server-only secret key."
        )
    from supabase import create_client
    return create_client(url, key)


def _bucket_name() -> str:
    bucket = os.environ.get("AREEJ_SUPABASE_BUCKET", "areej-private-files").strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,62}", bucket):
        raise ValueError("Invalid Supabase Storage bucket name.")
    return bucket


def _safe_object_path(category: str, filename: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", category):
        raise ValueError("Invalid storage category.")
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename or filename in {".", ".."}:
        raise ValueError("Invalid storage filename.")
    return f"{category}/{safe_name}"


def save_upload(upload, category: str, local_folder: Path, filename: str) -> str:
    """Save a validated Flask FileStorage and return its private object path."""
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        raise ValueError("Invalid storage filename.")

    if not supabase_storage_enabled():
        local_folder.mkdir(parents=True, exist_ok=True)
        upload.save(local_folder / safe_name)
        return safe_name

    path = _safe_object_path(category, safe_name)
    data = upload.stream.read(MAX_UPLOAD_BYTES + 1)
    upload.stream.seek(0)
    if not data:
        raise ValueError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("The uploaded file exceeds the 5 MB limit.")

    _storage_client().storage.from_(_bucket_name()).upload(
        path,
        data,
        {
            "content-type": upload.content_type or "application/octet-stream",
            "upsert": "false",
        },
    )
    return path


def read_upload(path: str, local_folder: Path) -> bytes:
    """Read a legacy local file or an object from the private Supabase bucket."""
    if not path or not isinstance(path, str):
        raise FileNotFoundError("No file path was provided.")

    if supabase_storage_enabled():
        parts = Path(path).parts
        if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts):
            raise FileNotFoundError("Invalid storage path.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", parts[0]):
            raise FileNotFoundError("Invalid storage category.")
        clean_path = "/".join(parts)
        return bytes(_storage_client().storage.from_(_bucket_name()).download(clean_path))

    safe_name = Path(path).name
    if safe_name != path or safe_name in {"", ".", ".."}:
        raise FileNotFoundError("Invalid local file path.")
    return (local_folder / safe_name).read_bytes()
