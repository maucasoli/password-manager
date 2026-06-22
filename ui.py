import tkinter as tk
from tkinter import ttk
import database as db
import tkinter.messagebox as msg
from auth import Auth
from crypto import Crypto
import generator
from otp import OTP
import time
from translations import t, set_lang
from ui_theme import Theme


class GUI:

    def __init__(self):
        self.root = tk.Tk()
        self.root.configure(bg="#1A1D2E")
        self.theme = Theme()

        self.width = 400
        self.height = 300
        self.tree = None

        self.lang = db.get_language()
        set_lang(self.lang)

        self.last_activity = time.time()
        self.locked = False

        self.root.bind_all("<Key>", self.update_activity)
        self.root.bind_all("<Button>", self.update_activity)
        self.root.bind_all("<Motion>", self.update_activity)
        self.root.bind_all("<MouseWheel>", self.update_activity)

        self.crypto = Crypto()
        self.auth = Auth(self.crypto)
        self.OTP = OTP(self.crypto)

    def run(self):
        self.page_login()

    # button in login page
    def toggle_lang(self):
        self.lang = "fr" if self.lang == "en" else "en"
        set_lang(self.lang)
        db.set_language(self.lang)
        self.page_login()

    def clear_memory(self):
        self.tree = None
        self.crypto.clear()
        self.OTP.clear()

    def update_activity(self, event=None):
        self.last_activity = time.time()

    def check_lock(self):
        if not self.locked:
            idle_time = time.time() - self.last_activity

            # seconds
            if idle_time >= 6000:
                for widget in self.root.winfo_children():
                    widget.destroy()
                self.clear_memory()
                self.locked = True
                msg.showwarning(t("DIALOG_ALERT"), t("MSG_LOGGED_OUT"))
                self.page_login()

        self.root.after(1000, self.check_lock)

    def center_window(self, root, width, height):
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)

        root.geometry(f"{width}x{height}+{x}+{y}")

    def show_qrcode(self):
        popup = tk.Toplevel()
        popup.title(t("TITLE_QR_CODE"))
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

        def check_totp():
            popup = tk.Toplevel()
            popup.title(t("TITLE_TOTP"))
            self.center_window(popup, 300, 250)

            tk.Label(popup, text=t("TITLE_TOTP")).pack(pady=5)
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
                    tk.messagebox.showerror(
                        t("DIALOG_ERROR"), t("MSG_INVALID_TOTP"), parent=popup
                    )
                    totp_entry.delete(0, tk.END)
                    totp_entry.focus_set()

            # allow enter button
            totp_entry.bind("<Return>", lambda e: on_otp())

            tk.Button(popup, text=t("BTN_CHECK"), command=on_otp).pack(pady=10)
            popup.wait_window(popup)

            return result[0]

        def verify_master_password():
            master_password = txt_password.get()
            # check if master password is correct
            if self.auth.verify_master_password(master_password):

                # derive key on login
                password_bytes = master_password.encode("utf-8")
                salt_bytes = db.get_salt()
                self.crypto.derive_key(password_bytes, salt_bytes)

                if db.get_mfa():
                    self.OTP.set_otp_secret(db.get_otp_secret())
                    if check_totp():
                        self.page_passwords(self.root)
                else:
                    self.page_passwords(self.root)

            else:
                tk.messagebox.showerror(t("DIALOG_ERROR"), t("MSG_WRONG_PASSWORD"))

        def add_2FA():
            master_password = txt_password.get()
            if self.auth.verify_master_password(master_password):
                response = msg.askyesno(t("DIALOG_SUCCESS"), t("MSG_CONFIGURE_2FA"))
                if response:
                    password_bytes = master_password.encode("utf-8")
                    salt_bytes = db.get_salt()
                    self.crypto.derive_key(password_bytes, salt_bytes)
                    encrypted_otp = self.auth.create_otp_secret()
                    self.OTP.set_otp_secret(encrypted_otp)
                    db.set_otp_secret(encrypted_otp)
                    self.show_qrcode()
            else:
                tk.messagebox.showerror(
                    t("DIALOG_ERROR"), t("MSG_NO_2FA_OR_WRONG_PASSWORD")
                )

        #
        self.center_window(self.root, self.width, self.height)
        self.root.title(t("TITLE_PASSWORD_MANAGER"))

        # label title
        self.theme.label(
            self.root, t("TITLE_PASSWORD_MANAGER"), ("Segoe UI", 18, "bold")
        ).pack(pady=10)

        # label type password
        self.theme.label(
            self.root, t("LABEL_MASTER_PASSWORD"), ("Segoe UI", 12), fg="#889082"
        ).pack(pady=(0, 5))

        # entry password
        txt_password = self.theme.entry(self.root, show="*", font=("Segoe UI", 12))
        txt_password.pack()

        # button login
        btn_login = self.theme.button(
            self.root,
            verify_master_password,
            t("BTN_LOGIN"),
            font=("Segoe UI", 12, "bold"),
            bg="#4F6EF7",
            width=18,
            height=1,
        )
        btn_login.pack(pady=10)

        # button create master user
        btn_create_master = self.theme.button(
            self.root,
            lambda: self.create_master_password(self.root),
            t("BTN_CREATE_MASTER_USER"),
            font=("Segoe UI", 11, "bold"),
            bg="#2F3355",
        )
        btn_create_master.pack(pady=(10, 0))

        # button add 2FA
        btn_add_2FA = self.theme.button(
            self.root,
            lambda: add_2FA(),
            t("BTN_ENABLE_2FA"),
            font=("Segoe UI", 11, "bold"),
            bg="#2F3355",
        )
        btn_add_2FA.pack(pady=(5, 5))

        # button language
        btn_lang = self.theme.button(
            self.root,
            lambda: self.toggle_lang(),
            t("FR/EN"),
            font=("Segoe UI", 11, "bold"),
            bg="#2F3355",
            width=6,
            height=2,
        )
        btn_lang.pack(side="right", padx=20, pady=(0,10))

        self.root.mainloop()

    def create_master_password(self, root):
        if not db.exist_master_user():
            for widget in root.winfo_children():
                widget.destroy()

            lbl_password = tk.Label(
                self.root, text=t("LABEL_CHOOSE_MASTER_PASSWORD")
            ).pack()
            pw_entry = tk.Entry(self.root, show="*")
            pw_entry.pack()

            lbl_password2 = tk.Label(
                self.root, text=t("LABEL_REENTER_MASTER_PASSWORD")
            ).pack()
            pw_entry2 = tk.Entry(self.root, show="*")
            pw_entry2.pack()

            def on_ok():
                masterpw = pw_entry.get()
                masterpw2 = pw_entry2.get()

                if masterpw == masterpw2:
                    # return a tuple with true and hash
                    result = self.auth.create_master_password(masterpw)
                    # check if result is tuple or error string
                    if isinstance(result, tuple):
                        # derive key on register
                        salt_bytes = self.auth.create_salt()
                        self.crypto.derive_key(masterpw.encode("utf-8"), salt_bytes)

                        _, masterpw_hash = result
                        encrypted_otp = self.auth.create_otp_secret()
                        self.OTP.set_otp_secret(encrypted_otp)
                        db.create_master_password(masterpw_hash, encrypted_otp)
                        db.set_salt(salt_bytes)

                        response = msg.askyesno(
                            t("DIALOG_SUCCESS"), t("MSG_CONFIGURE_2FA")
                        )
                        if response:
                            db.set_mfa()
                            self.show_qrcode()
                        self.page_login()
                    else:
                        msg.showwarning(t("DIALOG_ERROR"), result)
                else:
                    msg.showwarning(t("DIALOG_ERROR"), t("MSG_DIFFERENT_PASSWORD"))

            tk.Button(root, text=t("BTN_CREATE"), command=on_ok).pack(pady=10)
            tk.Button(root, text=t("BTN_BACK"), command=lambda: self.page_login()).pack(
                pady=10
            )
        else:
            msg.showwarning(t("DIALOG_ALERT"), t("MSG_MASTER_USER_EXISTS"))
            self.page_login()

    def add_password(self):
        popup = tk.Toplevel()
        popup.title(t("TITLE_ADD_PASSWORD"))
        self.center_window(popup, 300, 300)

        tk.Label(popup, text=t("LABEL_SERVICE")).pack(pady=5)
        service_entry = tk.Entry(popup)
        service_entry.pack()

        tk.Label(popup, text=t("LABEL_USERNAME")).pack(pady=5)
        username_entry = tk.Entry(popup)
        username_entry.pack()

        tk.Label(popup, text=t("LABEL_PASSWORD")).pack(pady=5)
        password_entry = tk.Entry(popup, show="*")
        password_entry.pack()

        tk.Label(popup, text=t("LABEL_REENTER_PASSWORD")).pack(pady=5)
        password_entry2 = tk.Entry(popup, show="*")
        password_entry2.pack()

        def on_ok():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            password2 = password_entry2.get()

            if password == password2:
                password_bytes = password.encode("utf-8")
                encrypted_password = self.crypto.encrypt(password_bytes)

                if service and username and password:
                    db.add_password(service, username, encrypted_password)
                    msg.showinfo(t("DIALOG_SUCCESS"), t("MSG_PASSWORD_ADDED"))
                    popup.destroy()
                    self.load_data(self.tree)
                else:
                    tk.messagebox.showerror(
                        t("DIALOG_ERROR"), t("MSG_ALL_FIELDS_REQUIRED")
                    )
                    popup.focus_set()
            else:
                msg.showwarning(t("DIALOG_ERROR"), t("MSG_DIFFERENT_PASSWORD"))
                self.add_password()

        def on_generate():
            password = generator.generate_password()
            # delete from 0 to end
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)
            password_entry2.delete(0, tk.END)
            password_entry2.insert(0, password)

        tk.Button(popup, text=t("BTN_OK"), command=on_ok).pack(pady=10)
        tk.Button(
            popup, text=t("BTN_GENERATE_PASSWORD"), command=lambda: on_generate()
        ).pack(pady=10)

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

        # start idle timer after login
        self.locked = False
        self.check_lock()

        # top frame (label title, button logout)
        top_frame = tk.Frame(self.root, bg="#2F3355")
        top_frame.pack(fill="x", padx=0, pady=(0, 10))

        # label title
        self.theme.label(
            top_frame, t("LABEL_PASSWORDS"), ("Segoe UI", 18, "bold"), bg="#2F3355"
        ).pack(side="left", padx=(5, 0), pady=(5, 5))

        # button logout
        btn_logout = self.theme.button(
            top_frame,
            lambda: on_logout(),
            t("BTN_LOGOUT"),
            font=("Segoe UI", 10, "bold"),
            bg="#D9534F",
            width=20,
            height=2,
        )
        btn_logout.pack(side="right", padx=(0, 5), pady=(5, 5))

        # middle frame (button add password, button remove 2FA)
        middle_frame = tk.Frame(self.root, bg="#1A1D2E")
        middle_frame.pack(fill="x", padx=0, pady=(0, 0))

        # button add password
        btn_add = self.theme.button(
            middle_frame,
            self.add_password,
            t("TITLE_ADD_PASSWORD"),
            font=("Segoe UI", 10, "bold"),
            bg="#4F6EF7",
            width=25,
            height=2,
        )
        btn_add.pack(side="left", padx=(5, 0), pady=(2, 2))

        # button remove 2FA
        btn_remove_2fa = self.theme.button(
            middle_frame,
            lambda: on_remove_2fa(),
            t("BTN_DISABLE_2FA"),
            font=("Segoe UI", 10, "bold"),
            bg="#2F3355",
            width=20,
            height=2,
        )
        btn_remove_2fa.pack(side="right", padx=(0, 5), pady=(2, 2))

        # bottom frame (button change master password)
        bottom_frame = tk.Frame(self.root, bg="#1A1D2E")
        bottom_frame.pack(fill="x", padx=0, pady=(0, 2))

        # button change master password
        btn_change_password = self.theme.button(
            bottom_frame,
            lambda: on_change_password(),
            t("BTN_CHANGE_PASSWORD"),
            font=("Segoe UI", 10, "bold"),
            bg="#2F3355",
            width=20,
            height=2,
        )
        btn_change_password.pack(side="right", padx=(0, 5), pady=(2, 5))

        def on_logout():
            for widget in root.winfo_children():
                widget.destroy()
            self.clear_memory()
            self.page_login()

        def on_remove_2fa():
            if db.get_mfa():
                response = msg.askyesno(
                    t("DIALOG_SUCCESS"), t("MSG_REMOVE_2FA_CONFIRM")
                )
                if response:
                    db.disable_mfa()
                    msg.showinfo(t("DIALOG_2FA_STATUS"), t("MSG_2FA_DISABLED"))
            else:
                tk.messagebox.showerror(
                    t("DIALOG_ERROR"), t("MSG_2FA_ALREADY_DISABLED"), parent=root
                )

        def on_change_password():
            popup = tk.Toplevel()
            popup.title(t("TITLE_CHANGE_PASSWORD"))
            self.center_window(popup, 300, 250)

            tk.Label(popup, text=t("LABEL_OLD_PASSWORD")).pack(pady=5)
            old_password_entry = tk.Entry(popup, show="*")
            old_password_entry.pack()

            tk.Label(popup, text=t("LABEL_NEW_PASSWORD")).pack(pady=5)
            new_password_entry = tk.Entry(popup, show="*")
            new_password_entry.pack()

            tk.Label(popup, text=t("LABEL_REENTER_PASSWORD")).pack(pady=5)
            new_password_entry2 = tk.Entry(popup, show="*")
            new_password_entry2.pack()

            # TODO: fix code repetition
            def on_ok():
                old_password = old_password_entry.get()
                new_password = new_password_entry.get()
                new_password2 = new_password_entry2.get()

                if self.auth.verify_master_password(old_password):
                    if new_password == new_password2:
                        # return a tuple with true and hash
                        result = self.auth.create_master_password(new_password)
                        # check if result is tuple or error string
                        if isinstance(result, tuple):

                            # decrypt
                            password_list = db.get_all_passwords()
                            for idx, (id, pw) in enumerate(password_list):
                                real_password = self.crypto.decrypt(pw).decode("utf-8")
                                password_list[idx] = (id, real_password)
                            encrypted_otp = db.get_otp_secret()
                            decrypted_otp = self.crypto.decrypt(encrypted_otp).decode(
                                "utf-8"
                            )

                            # derive new key
                            salt_bytes = self.auth.create_salt()
                            self.crypto.derive_key(
                                new_password.encode("utf-8"), salt_bytes
                            )

                            # encrypt
                            for _, (id, pw) in enumerate(password_list):
                                pw_bytes = pw.encode("utf-8")
                                encrypted_pw = self.crypto.encrypt(pw_bytes)
                                db.update_password(id, encrypted_pw)
                            otp_bytes = decrypted_otp.encode("utf-8")
                            encrypted_otp = self.crypto.encrypt(otp_bytes)
                            db.set_otp_secret(encrypted_otp)

                            _, masterpw_hash = result
                            db.create_master_password(masterpw_hash, encrypted_otp)
                            db.set_salt(salt_bytes)
                            msg.showinfo(
                                t("TITLE_CHANGE_PASSWORD"), t("MSG_PASSWORD_CHANGED")
                            )
                            popup.destroy()
                        else:
                            msg.showwarning(t("DIALOG_ERROR"), result)
                            popup.destroy()
                    else:
                        msg.showwarning(t("DIALOG_ERROR"), t("MSG_DIFFERENT_PASSWORD"))
                        popup.destroy()
                else:
                    tk.messagebox.showerror(t("DIALOG_ERROR"), t("MSG_WRONG_PASSWORD"))
                    popup.destroy()

            tk.Button(popup, text=t("BTN_OK"), command=on_ok).pack(pady=10)

        # treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview.Heading", background="#2F3355", foreground="#E5E7EB")
        style.configure(
            "Treeview",
            fieldbackground="#1A1D2E",
            background="#1A1D2E",
            foreground="#E5E7EB",
        )
        self.tree = ttk.Treeview(
            self.root,
            columns=("id", "Service", "Username", "Password"),
            show="headings",
        )

        self.tree.heading("Service", text=t("LABEL_SERVICE"))
        self.tree.heading("Username", text=t("LABEL_USERNAME"))
        self.tree.heading("Password", text=t("LABEL_PASSWORD"))

        # hide id column
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
            msg.showinfo(t("LABEL_PASSWORD"), real_password)

        # double click to show
        # todo: change to copy (30s)
        self.tree.bind("<Double-1>", show_password)

        # TODO: edit option
        def popup_menu(event):
            item = self.tree.identify_row(event.y)

            if not item:
                return

            # highlight chosen line
            self.tree.selection_set(item)

            menu = tk.Menu(self.root, tearoff=0)

            menu.add_command(label=t("BTN_COPY"), command=lambda: copy_password(item))
            menu.add_command(
                label=t("BTN_DELETE"), command=lambda: delete_password(item)
            )

            # show menu at mouse location
            menu.tk_popup(event.x_root, event.y_root)

        # when right-click > popup_menu
        self.tree.bind("<Button-3>", popup_menu)

        def copy_password(item):
            values = self.tree.item(item, "values")
            item_id = values[0]
            encrypted_password = db.get_password(item_id)
            real_password = self.crypto.decrypt(encrypted_password).decode("utf-8")

            self.root.clipboard_clear()
            self.root.clipboard_append(real_password)

        def delete_password(item):
            # get all columns
            values = self.tree.item(item, "values")

            item_id = values[0]

            response = msg.askyesno(t("BTN_DELETE"), t("MSG_ARE_YOU_SURE"))

            if response:
                db.delete_password(item_id)
                self.tree.delete(item)
