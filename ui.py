import tkinter as tk
from tkinter import ttk
import database as db
import tkinter.messagebox as msg
from auth import Auth
from crypto import Crypto
import generator
from otp import OTP


class Gui:

    def __init__(self):
        self.root = tk.Tk()
        self.width = 400
        self.height = 300
        self.tree = None

        self.crypto = Crypto()
        self.auth = Auth(self.crypto)
        self.OTP = OTP(self.crypto)

    def center_window(self, root, width, height):
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)

        root.geometry(f"{width}x{height}+{x}+{y}")

    def show_qrcode(self):
            popup = tk.Toplevel()
            popup.title("QR CODE")
            self.center_window(popup, 300, 250)

            photo = self.OTP.generate_uri()
            label = tk.Label(popup, image=photo)
            label.image = photo
            label.pack()

            db.set_mfa()

            popup.wait_window(popup)
       
    def page_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.center_window(self.root, self.width, self.height)
        self.root.title("Password Manager")

        lbl_password = tk.Label(self.root, text="Master password:").pack()
        txt_password = tk.Entry(self.root, show="*")
        txt_password.pack()

        def check_totp():
            popup = tk.Toplevel()
            popup.title("TOTP")
            self.center_window(popup, 300, 250)

            tk.Label(popup, text="TOTP").pack(pady=5)
            totp_entry = tk.Entry(popup)
            totp_entry.pack()
            
            totp = self.OTP.generate_totp()
            # list to keep scope
            result = [False]
            def on_otp():
                input_totp = totp_entry.get()
                if self.OTP.verify_totp(input_totp):
                    result[0] = True
                    popup.destroy()
                else:
                    tk.messagebox.showerror("Error", "Invalid TOTP", parent=popup)
                    totp_entry.delete(0, tk.END)
                    totp_entry.focus_set()

            # allow enter button
            totp_entry.bind("<Return>", lambda e: on_otp())
            tk.Button(popup, text="Check", command=on_otp).pack(pady=10)
            popup.wait_window(popup)

            return result[0]

        def verify_master_password():
            master_password = txt_password.get()
            # check if master password is correct
            if self.auth.verify_master_password(master_password):

                # derive key on login
                password_bytes = master_password.encode("utf-8")
                salt_bytes = db.get_salt()
                f = self.crypto.derive_key(password_bytes, salt_bytes)

                if db.get_mfa():
                    if check_totp():
                        self.page_passwords(self.root)
                else:
                    self.page_passwords(self.root)

            else:
                tk.messagebox.showerror("Error", "Wrong password")

        def add_2FA(entry):
            master_password = entry.get()
            if self.auth.verify_master_password(master_password):
                response = msg.askyesno(
                    "Success",
                    "Do you want to configure 2FA now?"
                )
                if response:
                    encrypted_otp = self.auth.create_otp_secret()
                    db.set_otp_secret(encrypted_otp)
                    self.show_qrcode()
            else:
                tk.messagebox.showerror("Error", "No 2FA or wrong password")

        btn_login = tk.Button(self.root, text="Login", command=verify_master_password)
        btn_login.pack()

        btn_create_master = tk.Button(self.root, text="Create Master User", command=lambda: self.create_master_password(self.root))
        btn_create_master.pack()

        # pass master password entry box
        btn_add_2FA = tk.Button(self.root, text="Add 2FA", command=lambda: add_2FA(txt_password))
        btn_add_2FA.pack()

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

                # derive key on register
                salt_bytes = self.auth.create_salt()
                f = self.crypto.derive_key(masterpw.encode('utf-8'), salt_bytes)

                # return a tuple with hash and salt
                result = self.auth.create_master_password(masterpw)
                # check if result is tuple or error string
                if isinstance(result, tuple):
                    hash_masterpw, encrypted_otp = result
                    #otp = self.crypto.decrypt(encrypted_otp).decode("utf-8")
                    db.create_master_password(hash_masterpw, encrypted_otp)
                    db.set_salt(salt_bytes)

                    response = msg.askyesno(
                        "Success",
                        "Do you want to configure 2FA now?"
                    )
                    if response:
                        db.set_mfa()
                        self.show_qrcode() 
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
            
            if service and username and password:
                db.add_password(service, username, encrypted_password)
                msg.showinfo("Success", "Password added")
                popup.destroy()
                self.load_data(self.tree)
            else:
                tk.messagebox.showerror("Error", "All fields required")
                popup.focus_set()


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

        def on_logout():
            for widget in root.winfo_children():
                widget.destroy()
            self.page_login()

        btn_logout = tk.Button(self.root, text="Exit", command=lambda: on_logout())
        btn_logout.pack()

        def on_remove_2fa():
            if db.get_mfa():
                response = msg.askyesno(
                    "Success",
                    "Do you want to remove 2FA?"
                )
                if response:
                    db.disable_mfa()
                    msg.showinfo("2FA status", "2FA has been disabled")
            else:
                tk.messagebox.showerror("Error", "2FA already disabled", parent=root)

        btn_remove_2fa = tk.Button(self.root, text="Remove 2FA", command=lambda: on_remove_2fa())
        btn_remove_2fa.pack()

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
