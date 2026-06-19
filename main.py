from ui import GUI
import database as db


def main():
    db.create_tables()
    app = GUI()
    app.run()


if __name__ == "__main__":
    main()
