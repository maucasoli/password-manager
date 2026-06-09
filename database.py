import sqlite3


def connect():
    con = sqlite3.connect("database.db")
    return con


def create_tables():
    con = connect()
    cur = con.cursor()

    cur.execute(
        "CREATE TABLE IF NOT EXISTS master ("
        "id INTEGER primary key,"
        "master_password TEXT NOT NULL,"
        "salt TEXT NOT NULL"
        ")"
    )
    con.commit()

    cur.execute(
        "CREATE TABLE IF NOT EXISTS passwords ("
        "id INTEGER primary key,"
        "service TEXT NOT NULL,"
        "username TEXT NOT NULL,"
        "password TEXT NOT NULL"
        ")"
    )
    con.commit()

    con.close()


def check_master_password():
    con = connect()
    cur = con.cursor()

    cur.execute("SELECT master_password FROM master")
    try:
        master_password = cur.fetchone()[0]
        return master_password
    except:
        return False


def create_master_password(password, salt):
    con = connect()
    cur = con.cursor()

    cur.execute(
        "INSERT INTO master (master_password, salt) VALUES (?, ?)", (password, salt)
    )

    con.commit()
    con.close()


def read_table():
    con = connect()
    cur = con.cursor()
    cur.execute("SELECT id, service, username FROM passwords")
    rows = cur.fetchall()
    con.close()
    return rows


def get_password(id):
    con = connect()
    cur = con.cursor()
    cur.execute("SELECT password FROM passwords WHERE id = (?)", (id,))
    password = cur.fetchone()[0]
    return password


def add_password(service, username, password):
    con = connect()
    cur = con.cursor()

    cur.execute(
        "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
        (service, username, password),
    )

    con.commit()
    con.close()


def get_salt():
    con = connect()
    cur = con.cursor()
    cur.execute("SELECT salt FROM master")
    salt = cur.fetchone()[0]
    return salt
