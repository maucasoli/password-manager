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


class Gui:

    def __init__(self):
        self.root = tk.Tk()
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
            if idle_time >= 60:
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

        self.center_window(self.root, self.width, self.height)
        self.root.title(t("TITLE_PASSWORD_MANAGER"))

        lbl_password = tk.Label(self.root, text=t("LABEL_MASTER_PASSWORD")).pack()
        txt_password = tk.Entry(self.root, show="*")
        txt_password.pack()

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
                    db.set_otp_secret(encrypted_otp)
                    self.show_qrcode()
            else:
                tk.messagebox.showerror(
                    t("DIALOG_ERROR"), t("MSG_NO_2FA_OR_WRONG_PASSWORD")
                )

        btn_login = tk.Button(
            self.root, text=t("BTN_LOGIN"), command=verify_master_password
        )
        btn_login.pack()

        btn_create_master = tk.Button(
            self.root,
            text=t("BTN_CREATE_MASTER_USER"),
            command=lambda: self.create_master_password(self.root),
        )
        btn_create_master.pack()

        # pass master password entry box
        btn_add_2FA = tk.Button(
            self.root, text=t("BTN_ENABLE_2FA"), command=lambda: add_2FA()
        )
        btn_add_2FA.pack()

        # button language
        btn_lang = tk.Button(
            self.root, text=t("FR/EN"), command=lambda: self.toggle_lang()
        )
        btn_lang.pack()

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
                    # derive key on register
                    salt_bytes = self.auth.create_salt()
                    self.crypto.derive_key(masterpw.encode("utf-8"), salt_bytes)

                    # return a tuple with hash and salt
                    result = self.auth.create_master_password(masterpw)
                    # check if result is tuple or error string
                    if isinstance(result, tuple):
                        hash_masterpw, encrypted_otp = result
                        db.create_master_password(hash_masterpw, encrypted_otp)
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

        lbl_title = tk.Label(
            self.root,
            text=t("LABEL_PASSWORDS"),
            font=("Arial", 20, "bold"),
        ).pack()

        btn_add = tk.Button(
            self.root, text=t("TITLE_ADD_PASSWORD"), command=self.add_password
        )
        btn_add.pack()

        def on_logout():
            for widget in root.winfo_children():
                widget.destroy()
            self.clear_memory()
            self.page_login()

        btn_logout = tk.Button(
            self.root, text=t("BTN_LOGOUT"), command=lambda: on_logout()
        )
        btn_logout.pack()

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

        btn_remove_2fa = tk.Button(
            self.root, text=t("BTN_DISABLE_2FA"), command=lambda: on_remove_2fa()
        )
        btn_remove_2fa.pack()

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
                        # derive key on register
                        salt_bytes = self.auth.create_salt()
                        self.crypto.derive_key(new_password.encode("utf-8"), salt_bytes)

                        # return a tuple with hash and salt
                        result = self.auth.create_master_password(new_password)
                        # check if result is tuple or error string
                        if isinstance(result, tuple):
                            hash_masterpw, encrypted_otp = result
                            db.create_master_password(hash_masterpw, encrypted_otp)
                            db.set_salt(salt_bytes)
                            msg.showinfo(t("TITLE_CHANGE_PASSWORD"), t("MSG_PASSWORD_CHANGED"))
                            popup.destroy()
                        else:
                            msg.showwarning(t("DIALOG_ERROR"), result)
                    else:
                        msg.showwarning(t("DIALOG_ERROR"), t("MSG_DIFFERENT_PASSWORD"))
                else:
                    tk.messagebox.showerror(t("DIALOG_ERROR"), t("MSG_WRONG_PASSWORD"))

            tk.Button(popup, text=t("BTN_OK"), command=on_ok).pack(pady=10)

        btn_change_password = tk.Button(
            self.root,
            text=t("BTN_CHANGE_PASSWORD"),
            command=lambda: on_change_password(),
        )
        btn_change_password.pack()

        self.tree = ttk.Treeview(
            self.root,
            columns=("id", "Service", "Username", "Password"),
            show="headings",
        )

        self.tree.heading("Service", text=t("LABEL_SERVICE"))
        self.tree.heading("Username", text=t("LABEL_USERNAME"))
        self.tree.heading("Password", text=t("LABEL_PASSWORD"))

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
