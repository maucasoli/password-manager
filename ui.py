import tkinter as tk
from tkinter import ttk
import database as db
import tkinter.messagebox as msg
import auth
from crypto import Crypto


class Gui:

    def __init__(self):
        self.root = tk.Tk()
        self.width = 400
        self.height = 300
        self.tree = None

        self.crypto = Crypto()

    def center_window(self, root, width, height):
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)

        root.geometry(f"{width}x{height}+{x}+{y}")

    def page_login(self):
        self.center_window(self.root, self.width, self.height)
        self.root.title("Password Manager")

        lbl_password = tk.Label(self.root, text="Master password:").pack()
        txt_password = tk.Entry(self.root, show="*")
        txt_password.pack()

        if not db.check_master_password():
            self.create_masterpw()

        # nome confuso
        def check_master_password():
            master_password = txt_password.get()
            if auth.verify_master_password(master_password):
                password_bytes = master_password.encode("utf-8")
                salt_bytes = bytes.fromhex(db.get_salt())
                self.fernet = self.crypto.derive_key(password_bytes, salt_bytes)
                self.page_passwords(self.root)
            else:
                tk.messagebox.showerror("Error", "Wrong password")

        btn_login = tk.Button(self.root, text="Login", command=check_master_password)
        btn_login.pack()

        self.root.mainloop()

    def create_masterpw(self):
        popup_masterpw = tk.Toplevel()
        popup_masterpw.title("Create Master Password")
        self.center_window(popup_masterpw, 300, 200)

        tk.Label(popup_masterpw, text="Master Password").pack(pady=5)
        pw_entry = tk.Entry(popup_masterpw)
        pw_entry.pack()

        def on_ok():
            masterpw = pw_entry.get()
            hash_masterpw = auth.hash_password(masterpw)
            salt_hex = auth.create_salt()

            db.create_master_password(hash_masterpw, salt_hex)
            msg.showinfo("Success", "Master password created")

            popup_masterpw.destroy()

        tk.Button(popup_masterpw, text="OK", command=on_ok).pack(pady=10)

    def add_password(self):
        popup = tk.Toplevel()
        popup.title("Add Password")
        self.center_window(popup, 300, 200)

        tk.Label(popup, text="Service").pack(pady=5)
        service_entry = tk.Entry(popup)
        service_entry.pack()

        tk.Label(popup, text="Username").pack(pady=5)
        username_entry = tk.Entry(popup)
        username_entry.pack()

        tk.Label(popup, text="Password").pack(pady=5)
        password_entry = tk.Entry(popup)
        password_entry.pack()

        def on_ok():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            password_bytes = password.encode("utf-8")
            encrypted_password = self.crypto.encrypt(password_bytes)

            db.add_password(service, username, encrypted_password)
            msg.showinfo("Success", "Password added")

            popup.destroy()
            self.load_data(self.tree)

        tk.Button(popup, text="OK", command=on_ok).pack(pady=10)

    def load_data(self, tree):
        passwords = db.read_table()

        # clean table
        for item in tree.get_children():
            tree.delete(item)

        # populate table
        for pw in passwords:
            id, service, username = pw
            tree.insert("", "end", values=(id, service, username, "********"))

    def page_passwords(self, root):
        for widget in root.winfo_children():
            widget.destroy()

        lbl_title = tk.Label(
            self.root,
            text="Passwords",
            font=("Arial", 20, "bold"),
        ).pack()

        btn_add = tk.Button(self.root, text="Add Password", command=self.add_password)
        btn_add.pack()

        self.tree = ttk.Treeview(
            self.root,
            columns=("id", "Service", "Username", "Password"),
            show="headings",
        )

        self.tree.heading("Service", text="Service")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")

        # hide id
        self.tree.column("id", width=0, stretch=False)
        self.tree.column("Service", width=50)
        self.tree.column("Username", width=150)
        self.tree.column("Password", width=150)

        self.tree.pack(fill="both", expand=True)

        self.load_data(self.tree)

        def show_password(event):
            item = self.tree.focus()
            values = self.tree.item(item, "values")
            id = values[0]
            encrypted_password = db.get_password(id)
            real_password = self.crypto.decrypt(encrypted_password).decode("utf-8")
            msg.showinfo("Password", real_password)

        # double click to show
        # todo: change to copy (30s)
        self.tree.bind("<Double-1>", show_password)
