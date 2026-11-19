"""Private file storage adapter for Areej Academy.

Local disk remains the default for development. Production may opt into a
private Supabase Storage bucket using server-only credentials.
"""
from __future__ import annotations
import os
from functools import lru_cache
from pathlib import Path
from werkzeug.utils import secure_filename

def supabase_storage_enabled() -> bool:
    return os.environ.get("AREEJ_STORAGE_BACKEND", "local").strip().lower() == "supabase"

@lru_cache(maxsize=1)
def _storage_client():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = (os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
    if not url or not key:
        raise RuntimeError("Supabase Storage requires SUPABASE_URL and a server-only secret key.")
    from supabase import create_client
    return create_client(url, key)

def _bucket_name() -> str:
    return os.environ.get("AREEJ_SUPABASE_BUCKET", "areej-private-files").strip()

def save_upload(upload, category: str, local_folder: Path, filename: str) -> str:
    """Save a Flask FileStorage and return the path stored in the database."""
    safe_name = secure_filename(filename) or "upload"
    if not supabase_storage_enabled():
        local_folder.mkdir(parents=True, exist_ok=True)
        upload.save(local_folder / safe_name)
        return safe_name
    path = f"{category}/{safe_name}"
    data = upload.stream.read()
    if not data:
        raise ValueError("The uploaded file is empty.")
    _storage_client().storage.from_(_bucket_name()).upload(
        path, data, {"content-type": upload.content_type or "application/octet-stream", "upsert": "false"}
    )
    return path

def read_upload(path: str, local_folder: Path) -> bytes:
    """Read a legacy local file or an object from the private Supabase bucket."""
    if not path:
        raise FileNotFoundError("No file path was provided.")
    if supabase_storage_enabled():
        clean_path = path.lstrip("/")
        if ".." in Path(clean_path).parts:
            raise FileNotFoundError("Invalid storage path.")
        return bytes(_storage_client().storage.from_(_bucket_name()).download(clean_path))
    safe_name = Path(path).name
    if safe_name != path or safe_name in {"", ".", ".."}:
        raise FileNotFoundError("Invalid local file path.")
    return (local_folder / safe_name).read_bytes()
