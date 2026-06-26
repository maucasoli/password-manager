import pyotp
import qrcode
from io import BytesIO
from PIL import ImageTk
from crypto import Crypto


class OTP:

    def __init__(self, crypto: Crypto, debug):
        self.crypto = crypto
        self.debug = debug

        self.totp = None
        self.secret = None

    def clear(self):
        self.totp = None
        self.secret = None

    def get_otp_secret(self):
        return self.secret

    def set_otp_secret(self, secret):
        self.secret = secret

    def create_otp_secret(self):
        otp_secret = pyotp.random_base32().encode("utf-8")
        encrypted_otp = self.crypto.encrypt(otp_secret)
        return encrypted_otp

    def generate_totp(self):
        secret = self.crypto.decrypt(self.secret).decode("utf-8")
        self.totp = pyotp.TOTP(secret)
        if self.debug:
            print("TOTP:", self.totp.now())
        return self.totp.now()

    def generate_uri(self):
        secret = self.crypto.decrypt(self.secret).decode("utf-8")
        buffer = BytesIO()

        uri = pyotp.TOTP(secret).provisioning_uri(
            name="admin", issuer_name="Password Manager"
        )

        img = qrcode.make(uri)
        img = img.resize((250, 250))
        img.save(buffer, format="PNG")
        buffer.seek(0)
        photo = ImageTk.PhotoImage(data=buffer.getvalue())
        return photo

    def verify_totp(self, totp):
        return self.totp.verify(totp)
