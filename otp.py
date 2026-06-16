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

    def generate_totp(self):
        self.secret = db.get_otp_secret()
        secret_decrypted = self.crypto.decrypt(self.secret)
        self.totp = pyotp.TOTP(secret_decrypted)
        print("TOTP:", self.totp.now())
        return self.totp.now()

    def generate_uri(self):
        #secret = db.get_otp_secret()
        buffer = BytesIO()

        uri = pyotp.TOTP(self.secret).provisioning_uri(
            name="admin",
            issuer_name="Password Manager"
        )

        img = qrcode.make(uri)
        img = img.resize((250, 250))
        img.save(buffer, format="PNG")
        buffer.seek(0)
        photo = ImageTk.PhotoImage(data=buffer.getvalue())
        return photo

    def verify_totp(self, totp):
        return self.totp.verify(totp)
    