from ui import GUI
import argparse
from database import Database
from crypto import Crypto
from otp import OTP
from auth import Auth


def main():
    parser = argparse.ArgumentParser()
    # action store_true: if flag --> True, else False
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    db = Database()
    crypto = Crypto()
    otp = OTP(crypto, args.debug)
    auth = Auth(db, crypto, otp, args.debug)

    db.create_tables()

    app = GUI(db=db, crypto=crypto, otp=otp, auth=auth, debug=args.debug)
    app.run()


if __name__ == "__main__":
    main()
