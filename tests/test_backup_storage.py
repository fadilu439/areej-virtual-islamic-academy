import pytest

from scripts.backup_supabase_storage import safe_object_key


def test_storage_object_key_accepts_nested_private_path():
    assert safe_object_key("messages/2026", "proof.pdf") == "messages/2026/proof.pdf"


@pytest.mark.parametrize("name", ["", ".", "..", "../secret.txt", "folder/file.txt", r"folder\\file.txt"])
def test_storage_object_key_rejects_unsafe_names(name):
    with pytest.raises(ValueError):
        safe_object_key("messages", name)
