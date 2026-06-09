from ui import Gui
import database as db


def main():
    db.connect()
    db.create_tables()
    gui = Gui()
    gui.page_login()


if __name__ == "__main__":
    main()
