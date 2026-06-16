import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


class Crypto:

    def __init__(self):
        self.fernet = None

    def clear(self):
        if self.fernet:
            self.fernet = None

    # from master password
    def derive_key(self, password_bytes, salt_bytes):
        kdf = Argon2id(
            salt=salt_bytes, length=32, iterations=1, lanes=4, memory_cost=2**18
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        self.fernet = Fernet(key)

    def encrypt(self, password_bytes):
        if self.fernet is None:
            raise ValueError("Encryption key missing")
        encrypted_password = self.fernet.encrypt(password_bytes)
        return encrypted_password

    def decrypt(self, encrypted_password):
        if self.fernet is None:
            raise ValueError("Encryption key missing")
        password_bytes = self.fernet.decrypt(encrypted_password)
        return password_bytes
