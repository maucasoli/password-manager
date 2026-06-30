from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os


class Crypto:

    def __init__(self):
        self.dek = None
        self.aesgcm = None

    def clear(self):
        self.dek = None
        self.aesgcm = None

    def get_dek(self):
        return self.dek

    def set_dek(self, dek):
        self.dek = dek
        self.aesgcm = AESGCM(dek)

    # for data
    def encrypt(self, password_bytes):
        if self.aesgcm is None:
            raise ValueError("Encryption key missing")

        # number used once
        nonce = os.urandom(12)
        encrypted_password = self.aesgcm.encrypt(nonce, password_bytes, None)
        return nonce + encrypted_password

    # db columns already in BLOB
    def decrypt(self, ciphertext):
        if self.aesgcm is None:
            raise ValueError("Encryption key missing")

        nonce = ciphertext[:12]
        encrypted_password = ciphertext[12:]
        try:
            password_bytes = self.aesgcm.decrypt(nonce, encrypted_password, None)
        except InvalidTag:
            raise ValueError("Decryption failed")
        return password_bytes
