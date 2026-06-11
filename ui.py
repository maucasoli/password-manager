import tkinter as tk
from tkinter import ttk
import database as db
import tkinter.messagebox as msg
from auth import Auth
from crypto import Crypto
import generator


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
        for widget in self.root.winfo_children():
            widget.destroy()

        self.center_window(self.root, self.width, self.height)
        self.root.title("Password Manager")

        lbl_password = tk.Label(self.root, text="Master password:").pack()
        txt_password = tk.Entry(self.root, show="*")
        txt_password.pack()

        # nome confuso
        def check_master_password():
            master_password = txt_password.get()
            if Auth.verify_master_password(master_password):
                password_bytes = master_password.encode("utf-8")
                salt_bytes = bytes.fromhex(db.get_salt())
                self.fernet = self.crypto.derive_key(password_bytes, salt_bytes)
                self.page_passwords(self.root)
            else:
                tk.messagebox.showerror("Error", "Wrong password")

        btn_login = tk.Button(self.root, text="Login", command=check_master_password)
        btn_login.pack()

        btn_create_master = tk.Button(self.root, text="Create Master User", command=lambda: self.create_master_password(self.root))
        btn_create_master.pack()

        self.root.mainloop()

    def create_master_password(self, root):
        if not db.exist_master_user():
            for widget in root.winfo_children():
                widget.destroy()

            lbl_password = tk.Label(self.root, text="Choose a master password:").pack()
            pw_entry = tk.Entry(self.root, show="*")
            pw_entry.pack()

            def on_ok():
                masterpw = pw_entry.get()
                # should return a tuple with hash and salt
                result = Auth.create_master_password(masterpw)
                
                # check if result is tuple or error string
                if isinstance(result, tuple):
                    hash_masterpw, salt = result
                    db.create_master_password(hash_masterpw, salt)
                    msg.showinfo("Success", "Master password created.")
                    self.page_login()
                else:
                    msg.showwarning("Error", result)

            tk.Button(root, text="Create", command=on_ok).pack(pady=10)
            tk.Button(root, text="Return", command=lambda: self.page_login()).pack(pady=10)
        else:
            msg.showwarning("Alert", "Master user exists")
            self.page_login()


    def add_password(self):
        popup = tk.Toplevel()
        popup.title("Add Password")
        self.center_window(popup, 300, 250)

        tk.Label(popup, text="Service").pack(pady=5)
        service_entry = tk.Entry(popup)
        service_entry.pack()

        tk.Label(popup, text="Username").pack(pady=5)
        username_entry = tk.Entry(popup)
        username_entry.pack()

        tk.Label(popup, text="Password").pack(pady=5)
        password_entry = tk.Entry(popup, show="*")
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

        def on_generate():
            password = generator.generate_password()
            # delete from 0 to end
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)

        tk.Button(popup, text="OK", command=on_ok).pack(pady=10)
        tk.Button(popup, text="Generate password", command=lambda: on_generate()).pack(pady=10)


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
