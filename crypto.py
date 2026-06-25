import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class Crypto:

    def __init__(self):
        self.dek = None
        self.aesgcm = None

    def clear(self):
        self.dek = None
        self.aesgcm = None

    def set_dek(self, dek):
        self.dek = dek
        self.aesgcm = AESGCM(dek)

    # for data encryption
    def encrypt(self, password_bytes):
        if self.aesgcm is None:
            raise ValueError("Encryption key missing")
        
        # number used once
        nonce = os.urandom(12)
        encrypted_password = self.aesgcm.encrypt(nonce, password_bytes, None)

        # convert bytes to string
        return base64.b64encode(nonce + encrypted_password)

    # for data decryption
    def decrypt(self, encrypted_password):
        if self.aesgcm is None:
            raise ValueError("Encryption key missing")
        
        # decode before slicing
        raw = base64.b64decode(encrypted_password)
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        password_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
        return password_bytes
    