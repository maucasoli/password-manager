import secrets
import string


def generate_password(len=14):
    chars = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(chars) for _ in range(len))
    return password


def generate_recovery_code(parts=4, len=4):
    # no 0/O
    chars = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"
    segments = [
        "".join(secrets.choice(chars) for _ in range(len)) for _ in range(parts)
    ]
    return "-".join(segments)
