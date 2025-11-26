import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryption:
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Private: Derives a cryptographic key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def is_encrypted(self, filepath: str) -> bool:
        return filepath.endswith(".encrypted")

    def encrypt_file(self, input_filename: str, output_filename: str, password: str):
        """
        Encrypts a file using a key derived from a password.
        A new random salt is generated for each encryption.
        """
        salt = os.urandom(16)
        key = self._derive_key(password, salt)

        with open(input_filename, "rb") as f:
            file_data = f.read()

        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(file_data)

        with open(output_filename, "wb") as f:
            f.write(salt)
            f.write(encrypted_data)

    def decrypt_file(self, input_filename: str, output_filename: str, password: str):
        """
        Decrypts a file using a key derived from a password.
        The salt is read from the beginning of the encrypted file.
        """
        with open(input_filename, "rb") as f:
            salt = f.read(16)
            encrypted_data = f.read()

        key = self._derive_key(password, salt)

        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        with open(output_filename, "wb") as f:
            f.write(decrypted_data)
