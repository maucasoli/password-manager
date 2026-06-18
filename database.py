import sqlite3


def connect():
    con = sqlite3.connect("database.db")
    return con


def create_tables():
    with connect() as con:
        cur = con.cursor()
        # no autoincrement due to insert or ignore
        cur.execute(
            "CREATE TABLE IF NOT EXISTS master ("
            "id INTEGER primary key,"
            "password_hash TEXT,"
            "mfa_enabled INTEGER DEFAULT 0,"
            "salt BLOB,"
            "otp_secret TEXT,"
            "language TEXT DEFAULT 'en'"
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
        cur.execute("INSERT OR IGNORE INTO master (id, language) VALUES (1, 'en')")
        con.commit()


def set_language(lang):
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET language = (?) WHERE id = 1", (lang,))
        con.commit()


def get_language():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT language FROM master WHERE id = 1")
        row = cur.fetchone()

        if row is None:
            return "en"

        return row[0]


def check_master_password():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT password_hash FROM master WHERE id = 1")
        try:
            master_password = cur.fetchone()[0]
            return master_password
        except:
            return False


def create_master_password(password, otp_secret):
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "UPDATE master SET password_hash = (?), otp_secret = (?) WHERE id = 1",
            (password, otp_secret),
        )
        con.commit()


def set_salt(salt):
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET salt = (?) WHERE id = 1", (salt,))
        con.commit()


# enable MFA
def set_mfa():
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET mfa_enabled = 1 WHERE id = 1")
        con.commit()


def disable_mfa():
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET mfa_enabled = 0, otp_secret = NULL WHERE id = 1")
        con.commit()


# get MFA status
def get_mfa():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT mfa_enabled FROM master WHERE id = 1")
        row = cur.fetchone()

        if row is None:
            return False

        return bool(row[0])


def set_otp_secret(otp_secret):
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET otp_secret = (?) WHERE id = 1", (otp_secret,))
        con.commit()


def read_table():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT id, service, username FROM passwords")
        rows = cur.fetchall()
        return rows


# TODO: fix try except
def get_password(id):
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT password FROM passwords WHERE id = (?)", (id,))
        password = cur.fetchone()[0]
        return password


# return [(id, password), ...]
def get_all_passwords():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT id, password FROM passwords")
        password = cur.fetchall()
        return password


def update_password(id, new_password):
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "UPDATE passwords SET password = (?) WHERE id = (?)", (new_password, id)
        )
        con.commit()


def add_password(service, username, password):
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
            (service, username, password),
        )
        con.commit()


def delete_password(id):
    with connect() as con:
        cur = con.cursor()
        cur.execute("DELETE FROM passwords WHERE id = (?)", (id,))
        con.commit()


def get_salt():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT salt FROM master WHERE id = 1")
        salt = cur.fetchone()[0]
        return salt


def exist_master_user():
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "SELECT password_hash FROM master WHERE id = 1 AND password_hash IS NOT NULL"
        )
        return cur.fetchone() is not None


def get_otp_secret():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT otp_secret FROM master WHERE id = 1")
        otp_secret = cur.fetchone()[0]
        return otp_secret
