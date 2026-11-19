import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from werkzeug.datastructures import FileStorage
import storage_backend

class FakeBucket:
    def __init__(self):
        self.objects = {}
    def upload(self, path, data, options):
        self.objects[path] = bytes(data)
    def download(self, path):
        return self.objects[path]

class FakeStorage:
    def __init__(self):
        self.bucket = FakeBucket()
    def from_(self, bucket_name):
        return self.bucket

class FakeClient:
    def __init__(self):
        self.storage = FakeStorage()

class StorageBackendTests(unittest.TestCase):
    def test_local_upload_and_download(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / "messages"
            upload = FileStorage(stream=io.BytesIO(b"hello"), filename="hello.txt", content_type="text/plain")
            with patch.dict(os.environ, {"AREEJ_STORAGE_BACKEND": "local"}, clear=False):
                path = storage_backend.save_upload(upload, "messages", folder, "random_hello.txt")
                self.assertEqual(path, "random_hello.txt")
                self.assertEqual(storage_backend.read_upload(path, folder), b"hello")

    def test_supabase_upload_and_download_uses_private_object_path(self):
        fake = FakeClient()
        upload = FileStorage(stream=io.BytesIO(b"private"), filename="proof.pdf", content_type="application/pdf")
        with patch.dict(os.environ, {"AREEJ_STORAGE_BACKEND": "supabase", "AREEJ_SUPABASE_BUCKET": "areej-private-files"}, clear=False), patch.object(storage_backend, "_storage_client", return_value=fake):
            path = storage_backend.save_upload(upload, "payment-proofs", Path("/unused"), "proof-123.pdf")
            self.assertEqual(path, "payment-proofs/proof-123.pdf")
            self.assertEqual(storage_backend.read_upload(path, Path("/unused")), b"private")

    def test_local_download_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"AREEJ_STORAGE_BACKEND": "local"}, clear=False):
                with self.assertRaises(FileNotFoundError):
                    storage_backend.read_upload("../secret.txt", Path(temp_dir))

if __name__ == "__main__":
    unittest.main()
