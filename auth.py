import secrets
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os
from database import Database
from crypto import Crypto
from otp import OTP


class Auth:

    def __init__(self, db: Database, crypto: Crypto, otp: OTP, debug):
        self.db = db
        self.crypto = crypto
        self.otp = otp
        self.debug = debug

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

    # authentication
    def verify_master_password(self, input_username, input_password):
        user_id = self.db.get_user_id(input_username)

        # derive KEK
        password_bytes = input_password.encode("utf-8")
        salt_bytes = self.db.get_salt(user_id)
        kek = self.derive_kek(password_bytes, salt_bytes)

        # retrieve DEK
        encrypted_dek = self.db.get_dek(user_id)

        # verify if KEK decrypts DEK, otherwise password is incorrect
        try:
            dek = self.decrypt_dek(encrypted_dek, kek)
        except Exception:
            return False

        # store DEK in memory
        self.crypto.set_dek(dek)

        return {"user_id": user_id, "username": input_username, "dek": dek}

    # create or change master password
    def create_master_password(self, input_password, change_password=False, session=None):
        # derive KEK from master password and salt
        password_bytes = input_password.encode("utf-8")
        salt_bytes = self.create_salt()
        kek = self.derive_kek(password_bytes, salt_bytes)

        # if user is changing password
        if change_password:
            # get DEK and otp secret (encrypted) from memory
            dek = self.crypto.get_dek()
            encrypted_otp = self.otp.get_otp_secret()

        # first time creating master password
        else:
            # create and set DEK to memory
            dek = os.urandom(32)
            self.crypto.set_dek(dek)
            # create and set otp secret
            encrypted_otp = self.otp.create_otp_secret()
            self.otp.set_otp_secret(encrypted_otp)

        # encrypt DEK with KEK
        encrypted_dek = self.encrypt_dek(dek, kek)

        # TODO: fix username
        # save to database
        if not session:
            self.db.create_master_password(
                "teste2", salt_bytes, encrypted_dek, encrypted_otp
            )
        else:
            self.db.update_master_password(salt_bytes, encrypted_dek, encrypted_otp, session.user_id)