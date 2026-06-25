import base64
import database as db
from argon2 import PasswordHasher
import secrets
import re
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os

class Auth:

    def __init__(self, debug, crypto):
        self.debug = debug
        self.crypto = crypto
        self.ph = PasswordHasher()

    # from master password
    def derive_kek(self, password_bytes, salt_bytes):
        memory_cost = 2**18 if self.debug else 2**21

        kdf = Argon2id(
            salt=salt_bytes, length=32, iterations=3, lanes=4, memory_cost=memory_cost
        )
        return kdf.derive(password_bytes)

    # not for data
    def encrypt_dek(self, dek, kek):
        aesgcm = AESGCM(kek)
        nonce = os.urandom(12)
        encrypted_dek = aesgcm.encrypt(nonce, dek, None)
        return base64.b64encode(nonce + encrypted_dek)

    def decrypt_dek(self, encrypted_dek, kek):
        aesgcm = AESGCM(kek)
        raw = base64.b64decode(encrypted_dek)
        nonce = raw[:12]
        ciphertext = raw[12:]
        dek = aesgcm.decrypt(nonce, ciphertext, None)
        return dek


    def create_master_password(self, password):
        if not self.debug:
            if len(password) < 8:
                return "Password must be at least 8 characters long."
            if not re.search(r"[a-z]", password):
                return "Password must contain at least one lowercase letter."
            if not re.search(r"[A-Z]", password):
                return "Password must contain at least one uppercase letter."
            if not re.search(r"\d", password):
                return "Password must contain at least one number."
            if not re.search(r"[!@#$%&*()_?-]", password):
                return "Password must contain at least one special character."

        # hash master password
        hash = self.ph.hash(password)

        return True, hash

    def create_otp_secret(self):
        # create otp secret and encrypt it
        otp_secret = pyotp.random_base32().encode("utf-8")
        encrypted_otp = self.crypto.encrypt(otp_secret)
        return encrypted_otp

    def create_salt(self):
        # create salt for argon
        salt_bytes = secrets.token_bytes(32)
        return salt_bytes

    def verify_master_password(self, input_password):
        masterpw = db.check_master_password()
        try:
            if self.ph.verify(masterpw, input_password):
                return True
        except:
            return False
