import sqlite3
import os
import shutil
from datetime import datetime
from platformdirs import user_data_dir

DATA_DIR = user_data_dir("PasswordManager", appauthor=False)
DB_PATH = os.path.join(DATA_DIR, "database.db")


class Database:

    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)

    def connect(self):
        con = sqlite3.connect(DB_PATH)
        # needed for foreign key
        con.execute("PRAGMA foreign_keys = ON")
        return con

    #
    # main function
    #
    def create_tables(self):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT UNIQUE NOT NULL,"
                "salt BLOB,"
                "encrypted_dek BLOB,"
                "encrypted_otp_secret BLOB,"
                "mfa_enabled INTEGER DEFAULT 0,"
                "language TEXT DEFAULT 'en',"
                "failed_attempts INTEGER DEFAULT 0,"
                "locked_until DATETIME,"
                "created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))"
                ")"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS passwords ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "user_id INTEGER,"
                "service BLOB NOT NULL,"
                "username BLOB NOT NULL,"
                "password BLOB NOT NULL,"
                "created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),"
                "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
                ")"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS recovery_codes ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "user_id INTEGER NOT NULL,"
                "code_hash TEXT NOT NULL,"
                "used INTEGER NOT NULL DEFAULT 0,"
                "created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),"
                "used_at TEXT,"
                "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
                ")"
            )
            con.commit()

    #
    # page login
    #
    def get_failed_attempts(self, username):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "SELECT failed_attempts FROM users WHERE username = (?)", (username,)
            )
            row = cur.fetchone()

            if row is None:
                return None
            return row[0]

    def set_failed_attempts(self, username, attempts):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET failed_attempts = (?) WHERE username = (?)",
                (attempts, username),
            )
            con.commit()

    def get_locked_until(self, username):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "SELECT locked_until FROM users WHERE username = (?)", (username,)
            )
            row = cur.fetchone()

            if row is None:
                return None

            result = row[0]

            if result is None:
                return None

            return datetime.fromisoformat(result)

    def set_locked_until(self, username, locked_until):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET locked_until = (?) WHERE username = (?)",
                (locked_until, username),
            )
            con.commit()

    def create_master_password(
        self, username, salt_bytes, encrypted_dek, encrypted_otp_secret
    ):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO users (username, salt, encrypted_dek, encrypted_otp_secret) VALUES (?, ?, ?, ?)",
                (username, salt_bytes, encrypted_dek, encrypted_otp_secret),
            )
            con.commit()

    def update_master_password(
        self, salt_bytes, encrypted_dek, encrypted_otp_secret, user_id
    ):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET salt = (?), encrypted_dek = (?), encrypted_otp_secret = (?) WHERE id = (?)",
                (salt_bytes, encrypted_dek, encrypted_otp_secret, user_id),
            )
            con.commit()

    def get_user_id(self, username):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT id FROM users WHERE username = (?)", (username,))
            row = cur.fetchone()

            if row is None:
                return None
            return row[0]

    def username_exists(self, username):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT 1 FROM users WHERE username = (?)", (username,))
            return cur.fetchone() is not None

    def get_salt(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT salt FROM users WHERE id = (?)", (user_id,))
            row = cur.fetchone()

            if row is None:
                return None
            return row[0]

    def get_dek(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT encrypted_dek FROM users WHERE id = (?)", (user_id,))
            row = cur.fetchone()

            if row is None:
                return None
            return row[0]

    def get_mfa(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT mfa_enabled FROM users WHERE id = (?)", (user_id,))
            row = cur.fetchone()

            if row is None:
                return False
            return bool(row[0])

    def get_otp_secret(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "SELECT encrypted_otp_secret FROM users WHERE id = (?)", (user_id,)
            )
            row = cur.fetchone()

            if row is None:
                return False
            return row[0]

    def set_otp_secret(self, user_id, encrypted_otp_secret):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET encrypted_otp_secret = (?) WHERE id = (?)",
                (encrypted_otp_secret, user_id),
            )
            con.commit()

    def set_mfa(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("UPDATE users SET mfa_enabled = 1 WHERE id = (?)", (user_id,))
            con.commit()

    def set_recovery_code(self, user_id, code_hash):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                (user_id, code_hash),
            )
            con.commit()

    def get_recovery_code(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "SELECT code_hash FROM recovery_codes WHERE user_id = (?) AND used = 0",
                (user_id,),
            )
            row = cur.fetchone()

            if row is None:
                return None
            return row[0]

    def update_recovery_code(self, user_id, used, used_at):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE recovery_codes SET used = (?), used_at = (?) WHERE user_id = (?) AND used = 0",
                (used, used_at, user_id),
            )
            con.commit()

    def set_language(self, user_id, lang):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET language = (?) WHERE id = (?)", (lang, user_id)
            )
            con.commit()

    def get_language(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT language FROM users WHERE id = (?)", (user_id,))
            row = cur.fetchone()

            if row is None:
                return "en"
            return row[0]

    #
    # page passwords
    #
    def read_table_passwords(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "SELECT id, service, username FROM passwords WHERE user_id = (?)",
                (user_id,),
            )
            rows = cur.fetchall()
            return rows

    def get_password(self, id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("SELECT password FROM passwords WHERE id = (?)", (id,))
            row = cur.fetchone()

            if row is None:
                return None
            return row[0]

    def delete_password(self, id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("DELETE FROM passwords WHERE id = (?)", (id,))
            con.commit()

    def add_password(self, user_id, service, username, password):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO passwords (user_id, service, username, password) VALUES (?, ?, ?, ?)",
                (user_id, service, username, password),
            )
            con.commit()

    def disable_mfa(self, user_id):
        with self.connect() as con:
            cur = con.cursor()
            cur.execute("UPDATE users SET mfa_enabled = 0 WHERE id = (?)", (user_id,))
            con.commit()
