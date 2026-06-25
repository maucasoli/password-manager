import secrets
import re
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os
import database as db


class Auth:

    def __init__(self, debug, crypto, OTP):
        self.debug = debug
        self.crypto = crypto
        self.OTP = OTP

    # derive from master password
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
        return nonce + encrypted_dek

    # db columns already in BLOB
    def decrypt_dek(self, ciphertext, kek):
        aesgcm = AESGCM(kek)
        nonce = ciphertext[:12]
        encrypted_dek = ciphertext[12:]
        dek = aesgcm.decrypt(nonce, encrypted_dek, None)
        return dek

    # password requirements
    def validate_master_password(self, password):
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
        return True

    def create_salt(self):
        salt_bytes = secrets.token_bytes(32)
        return salt_bytes

    def create_otp_secret(self):
        otp_secret = pyotp.random_base32().encode("utf-8")
        encrypted_otp = self.crypto.encrypt(otp_secret)
        return encrypted_otp

    # authentication
    def verify_master_password(self, input_password):
        # derive KEK
        password_bytes = input_password.encode("utf-8")
        salt_bytes = db.get_salt()
        kek = self.derive_kek(password_bytes, salt_bytes)

        # retrieve DEK
        encrypted_dek = db.get_dek()

        # verify if KEK decrypts DEK, otherwise incorrect password
        try:
            dek = self.decrypt_dek(encrypted_dek, kek)
        except Exception:
            return False

        # store DEK in memory
        self.crypto.set_dek(dek)

        return True

    # TODO: add this logic to change password
    def create_master_password(self, input_password):
        # derive KEK from master password and salt
        password_bytes = input_password.encode("utf-8")
        salt_bytes = self.create_salt()
        kek = self.derive_kek(password_bytes, salt_bytes)

        # create DEK and encrypt with KEK
        dek = os.urandom(32)
        encrypted_dek = self.encrypt_dek(dek, kek)

        # set DEK to create otp secret
        self.crypto.set_dek(dek)
        encrypted_otp = self.create_otp_secret()
        self.OTP.set_otp_secret(encrypted_otp)

        # save to database
        db.create_master_password(encrypted_dek, encrypted_otp)
        db.set_salt(salt_bytes)
