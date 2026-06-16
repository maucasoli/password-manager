import sqlite3


def connect():
    con = sqlite3.connect("database.db")
    return con


def create_tables():
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS master ("
            "id INTEGER primary key AUTOINCREMENT,"
            "password_hash TEXT NOT NULL,"
            "mfa_enabled INTEGER NOT NULL DEFAULT 0,"
            "salt BLOB,"
            "otp_secret TEXT"
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
        cur.execute("SELECT password_hash FROM master")
        try:
            master_password = cur.fetchone()[0]
            return master_password
        except:
            return False


def create_master_password(password, otp_secret):
    with connect() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO master (password_hash, otp_secret) VALUES (?, ?)",
            (password, otp_secret),
        )
        con.commit()

def set_salt(salt):
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET salt = (?)", (salt,))
        con.commit()   

# enable MFA
def set_mfa():
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET mfa_enabled = 1")
        con.commit()

def disable_mfa():
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET mfa_enabled = 0")
        con.commit()
        cur.execute("UPDATE master SET otp_secret = NULL")
        con.commit()

# get MFA status
def get_mfa():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT mfa_enabled FROM master")
        row = cur.fetchone()

        if row is None:
            return False

        return bool(row[0])
    
def set_otp_secret(otp_secret):
    with connect() as con:
        cur = con.cursor()
        cur.execute("UPDATE master SET otp_secret = (?)", (otp_secret,))
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


def get_otp_secret():
    with connect() as con:
        cur = con.cursor()
        cur.execute("SELECT otp_secret FROM master")
        otp_secret = cur.fetchone()[0]
        return otp_secret
