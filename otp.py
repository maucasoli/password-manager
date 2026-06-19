import pyotp
import database as db
import qrcode
from io import BytesIO
from PIL import ImageTk
import qrcode


class OTP:

    def __init__(self, crypto):
        self.crypto = crypto
        self.totp = None
        self.secret = None

    def clear(self):
        self.totp = None
        self.secret = None

    def set_otp_secret(self, secret):
        self.secret = secret

    def generate_totp(self):
        secret = self.crypto.decrypt(self.secret).decode("utf-8")
        self.totp = pyotp.TOTP(secret)
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
