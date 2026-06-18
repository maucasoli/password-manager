import secrets
import string


def generate_password(len=14):
    chars = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(chars) for i in range(len))
    return password
