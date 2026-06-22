from ui import GUI
import database as db
import argparse


def main():
    parser = argparse.ArgumentParser()
    # action store_true: if flag --> True, else False
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    db.create_tables()
    app = GUI(debug=args.debug)
    app.run()


if __name__ == "__main__":
    main()
