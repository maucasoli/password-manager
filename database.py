import sqlite3


def connect():
    con = sqlite3.connect("database.db")
    return con


def create_tables():
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS master ("
            "id INTEGER primary key,"
            "master_password TEXT NOT NULL,"
            "salt TEXT NOT NULL"
            ")"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS passwords ("
            "id INTEGER primary key,"
            "service TEXT NOT NULL,"
            "username TEXT NOT NULL,"
            "password TEXT NOT NULL"
            ")"
        )
        con.commit()


def check_master_password():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT master_password FROM master")
        try:
            master_password = cur.fetchone()[0]
            return master_password
        except:
            return False


def create_master_password(password, salt):
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO master (master_password, salt) VALUES (?, ?)", (password, salt)
        )
        con.commit()


def read_table():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT id, service, username FROM passwords")
        rows = cur.fetchall()
        return rows


def get_password(id):
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT password FROM passwords WHERE id = (?)", (id,))
        password = cur.fetchone()[0]
        return password


def add_password(service, username, password):
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
            (service, username, password),
        )
        con.commit()


def get_salt():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT salt FROM master")
        salt = cur.fetchone()[0]
        return salt


def exist_master_user():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM master")
        try:
            row = cur.fetchone()
            return row is not None
        except Exception as e:
            print(f"Error: {e}")
            return False
