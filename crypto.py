import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


class Crypto:

    def __init__(self):
        self.fernet = None

    # from master password
    def derive_key(self, password_bytes, salt_bytes):
        kdf = Argon2id(
            salt=salt_bytes, length=32, iterations=1, lanes=4, memory_cost=2**21
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        self.fernet = Fernet(key)
        return self.fernet

    def encrypt(self, password_bytes):
        encrypted_password = self.fernet.encrypt(password_bytes)
        return encrypted_password

    def decrypt(self, encrypted_password):
        password_bytes = self.fernet.decrypt(encrypted_password)
        return password_bytes
