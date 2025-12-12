import base64
import hashlib
import struct

import encryption as encryption_module
import pytest

Encryption = encryption_module.Encryption


def _pbkdf2_derive_key(_self, password: str, salt: bytes) -> bytes:
    """
    Deterministic, fast KDF replacement for tests.

    Uses PBKDF2-HMAC-SHA256 to produce 32 bytes and base64-url encodes it
    so it can be used with Fernet. This produces different keys for
    different passwords so wrong-password behavior can be tested.
    """
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000, dklen=32)
    return base64.urlsafe_b64encode(key)


class DummyPasswordHasher:
    """Lightweight stand-in for argon2.PasswordHasher used to avoid heavy allocations in tests."""

    def __init__(self, *args, **kwargs):
        # Intentionally do nothing
        pass


def test_encrypt_decrypt_roundtrip(tmp_path, monkeypatch):
    # Prevent constructing the real
    monkeypatch.setattr(encryption_module, "PasswordHasher", DummyPasswordHasher)
    # Use the fast deterministic KDF for test run-time stability
    monkeypatch.setattr(Encryption, "_derive_key", _pbkdf2_derive_key)

    enc = Encryption()

    # Create a plaintext file
    plaintext = b"hello pytest world"
    file_path = tmp_path / "secret.txt"
    file_path.write_bytes(plaintext)

    # Encrypt
    enc.encrypt_file(str(file_path), password="correcthorsebattery")

    encrypted_path = tmp_path / (f"secret.txt{enc.ENCRYPTED_FILE_SUFFIX}")
    assert not file_path.exists()
    assert encrypted_path.exists()

    # Verify header structure (salt + 3x 4-byte ints)
    HEADER_SIZE = 16 + 4 + 4 + 4
    data = encrypted_path.read_bytes()
    assert len(data) > HEADER_SIZE
    salt = data[:16]
    assert len(salt) == 16
    # Unpack params to ensure they are present and parsable
    time_cost, memory_cost, parallelism = struct.unpack("<III", data[16 : 16 + 12])
    assert (
        isinstance(time_cost, int)
        and isinstance(memory_cost, int)
        and isinstance(parallelism, int)
    )

    # Decrypt with the same password
    enc.decrypt_file(str(encrypted_path), password="correcthorsebattery")

    # After decryption the encrypted file should be removed and plaintext restored
    assert not encrypted_path.exists()
    assert file_path.exists()
    assert file_path.read_bytes() == plaintext


def test_encrypting_already_encrypted_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(encryption_module, "PasswordHasher", DummyPasswordHasher)
    enc = Encryption()

    # Create a file that already has the encrypted suffix
    file_path = tmp_path / (f"already{enc.ENCRYPTED_FILE_SUFFIX}")
    file_path.write_text("data")

    with pytest.raises(ValueError):
        enc.encrypt_file(str(file_path), password="pwd")


def test_decrypt_non_encrypted_file_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(encryption_module, "PasswordHasher", DummyPasswordHasher)
    enc = Encryption()

    # Create a normal plaintext file and attempt to decrypt it
    file_path = tmp_path / "plain.txt"
    file_path.write_text("plain")

    with pytest.raises(ValueError):
        enc.decrypt_file(str(file_path), password="pwd")


def test_decrypt_with_wrong_password_fails_and_keeps_file(tmp_path, monkeypatch):
    # Use the dummy PasswordHasher and fast test KDF so tests are deterministic and fast
    monkeypatch.setattr(encryption_module, "PasswordHasher", DummyPasswordHasher)
    monkeypatch.setattr(Encryption, "_derive_key", _pbkdf2_derive_key)

    enc = Encryption()

    # Create plaintext and encrypt with a known password
    plaintext = b"secret data"
    file_path = tmp_path / "topsecret.txt"
    file_path.write_bytes(plaintext)
    enc.encrypt_file(str(file_path), password="right_password")

    encrypted_path = tmp_path / (f"topsecret.txt{enc.ENCRYPTED_FILE_SUFFIX}")
    assert encrypted_path.exists()

    # Attempt to decrypt with the wrong password -> should raise ValueError
    with pytest.raises(ValueError):
        enc.decrypt_file(str(encrypted_path), password="wrong_password")

    # Encrypted file should still exist and original plaintext should not be present
    assert encrypted_path.exists()
    assert not (tmp_path / "topsecret.txt").exists()
