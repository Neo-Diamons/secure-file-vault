import base64
import os
import struct

from argon2 import PasswordHasher, low_level
from argon2 import Type as Argon2Type
from cryptography.fernet import Fernet, InvalidToken


class Encryption:
    # --- Argon2id Configuration ---
    TIME_COST = 2  # Number of passes over the memory
    MEMORY_COST = 1024 * 1024  # 1GB of memory (1024 * 1024 KiB)
    PARALLELISM = 4
    KEY_LENGTH = 32  # Required key length for Fernet

    ENCRYPTED_FILE_SUFFIX = ".encrypted"

    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=self.TIME_COST,
            memory_cost=self.MEMORY_COST,
            parallelism=self.PARALLELISM,
            hash_len=self.KEY_LENGTH,
            type=Argon2Type.ID,
        )

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Private: Derives a cryptographic key from a password and salt."""

        # Low-level Argon2 KDF to get raw bytes suitable for Fernet.
        key_bytes = low_level.hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=self.TIME_COST,
            memory_cost=self.MEMORY_COST,
            parallelism=self.PARALLELISM,
            hash_len=self.KEY_LENGTH,
            type=low_level.Type.ID,
            version=low_level.ARGON2_VERSION,
        )

        # Fernet requires a 32-byte key, Base64 URL-safe encoded.
        return base64.urlsafe_b64encode(key_bytes)

    def is_encrypted(self, filepath: str) -> bool:
        return filepath.endswith(self.ENCRYPTED_FILE_SUFFIX)

    def encrypt_file(self, filepath: str, password: str):
        """
        Encrypts a file using a key derived from a password via Argon2id.
        A new random salt and the Argon2 parameters are stored in the file header.

        This function writes an output file using the ENCRYPTED_FILE_SUFFIX
        (original filename + ".encrypted"). The file will contain a header
        (16-byte salt followed by Argon2 parameters) followed by the
        ciphertext. After successfully writing the encrypted file, the
        original plaintext file is removed.
        """
        if self.is_encrypted(filepath):
            raise ValueError("File is already encrypted.")

        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        with open(filepath, "rb") as f:
            file_data = f.read()

        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(file_data)

        # Structure the header to contain key derivation parameters:
        # [Salt (16 bytes)] | [Time Cost (4 bytes)] | [Memory Cost (4 bytes)] | [Parallelism (4 bytes)] | [Encrypted Data]
        parts = []
        parts.append(salt)
        parts.append(struct.pack("<I", self.TIME_COST))
        parts.append(struct.pack("<I", self.MEMORY_COST))
        parts.append(struct.pack("<I", self.PARALLELISM))
        parts.append(encrypted_data)
        result = b"".join(parts)

        with open(filepath + self.ENCRYPTED_FILE_SUFFIX, "wb") as f:
            f.write(result)
        os.remove(filepath)

    def decrypt_file(self, filepath: str, password: str):
        """
        Decrypts a file using a key derived from the password and parameters
        read from the beginning of the encrypted file.
        """

        HEADER_SIZE = (
            16 + 4 + 4 + 4
        )  # Header: 16 bytes salt + 3 * 4 bytes for Argon2 params
        if not self.is_encrypted(filepath):
            raise ValueError("File is not encrypted.")

        try:
            with open(filepath, "rb") as f:
                header = f.read(HEADER_SIZE)
                if len(header) != HEADER_SIZE:
                    raise IOError("File is corrupted or too short (missing header).")
                salt = header[:16]
                time_cost, memory_cost, parallelism = struct.unpack("<III", header[16:])

                encrypted_data = f.read()

            self.TIME_COST = time_cost
            self.MEMORY_COST = memory_cost
            self.PARALLELISM = parallelism
            key = self._derive_key(password, salt)

            fernet = Fernet(key)
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except InvalidToken:
                raise ValueError(
                    "Decryption failed. Incorrect password or corrupted data."
                )
            except Exception as e:
                raise ValueError(
                    f"Decryption failed: Incorrect password or corrupted file. ({e})"
                )

            with open(filepath.removesuffix(self.ENCRYPTED_FILE_SUFFIX), "wb") as f:
                f.write(decrypted_data)
            os.remove(filepath)

        except (IOError, ValueError) as e:
            print(f"Error processing file {filepath}: {e}")
            raise
