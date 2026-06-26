from ui import GUI
import database as db
import argparse
from crypto import Crypto
from otp import OTP
from auth import Auth


def main():
    parser = argparse.ArgumentParser()
    # action store_true: if flag --> True, else False
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    db.create_tables()

    crypto = Crypto()
    otp = OTP(args.debug, crypto)
    auth = Auth(args.debug, crypto, otp)

    app = GUI(crypto=crypto, otp=otp, auth=auth, debug=args.debug)

    app.run()


if __name__ == "__main__":
    main()
