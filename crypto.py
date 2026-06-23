import base64
from cryptography.fernet import Fernet


class Crypto:

    def __init__(self):
        self.dek = None
        self.fernet = None

    def clear(self):
        self.dek = None
        self.fernet = None

    def set_dek(self, dek):
        self.dek = dek
        key = base64.urlsafe_b64encode(dek)
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
