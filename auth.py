import database as db
from argon2 import PasswordHasher
import secrets


def verify_master_password(input_password):
    ph = PasswordHasher()

    masterpw = db.check_master_password()

    try:
        if ph.verify(masterpw, input_password):
            return True
    except:
        return False


def hash_password(password):
    ph = PasswordHasher()
    hash = ph.hash(password)
    return hash


def create_salt():
    salt_bytes = secrets.token_bytes(16)
    salt_hex = salt_bytes.hex()
    return salt_hex
