import database as db
from argon2 import PasswordHasher
import secrets
import re

class Auth:


    @staticmethod
    def create_master_password(password):
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[a-z]", password):
            return "Password must contain at least one lowercase letter."
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter."
        if not re.search(r"\d", password):
            return "Password must contain at least one number."
        if not re.search(r"[!@#$%&*()_?-]", password):
            return "Password must contain at least one special character (@$!%*?&)."
        
        # hash master password
        ph = PasswordHasher()
        hash = ph.hash(password)

        # create salt for argon
        salt_bytes = secrets.token_bytes(32)
        salt_hex = salt_bytes.hex()

        return hash, salt_hex

    @staticmethod
    def verify_master_password(input_password):
        ph = PasswordHasher()

        masterpw = db.check_master_password()

        try:
            if ph.verify(masterpw, input_password):
                return True
        except:
            return False
