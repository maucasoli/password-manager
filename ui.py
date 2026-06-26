import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as msg
import generator
import time
from translations import t, set_lang
from ui_theme import Theme
from database import Database
from crypto import Crypto
from otp import OTP
from auth import Auth
from session import Session


class GUI:

    def __init__(self, db: Database, crypto: Crypto, otp: OTP, auth: Auth, debug=False):
        # if debug:
        # no password requirements
        # print TOTP to terminal
        # no auto-lock from idle
        self.debug = debug

        self.db = db
        self.crypto = crypto
        self.otp = otp
        self.auth = auth
        self.session = None

        self.root = tk.Tk()
        self.root.configure(bg="#1A1D2E")
        self.theme = Theme()

        self.width = 400
        self.height = 300
        self.tree = None

        # TODO: fix lang
        self.lang = "en"
        # self.lang = self.db.get_language()
        set_lang(self.lang)

        # for auto-lock
        self.last_activity = time.time()
        self.locked = False
        self.root.bind_all("<Key>", self.update_activity)
        self.root.bind_all("<Button>", self.update_activity)
        self.root.bind_all("<Motion>", self.update_activity)
        self.root.bind_all("<MouseWheel>", self.update_activity)

    def run(self):
        self.page_login()

    # button language
    def toggle_lang(self):
        self.lang = "fr" if self.lang == "en" else "en"
        set_lang(self.lang)
        self.db.set_language(self.session.user_id, self.lang)
        self.page_login()

    def clear_memory(self):
        self.tree = None
        self.crypto.clear()
        self.otp.clear()
        self.session = None

    def update_activity(self, event=None):
        self.last_activity = time.time()

    def check_lock(self):
        if self.debug:
            return

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
        popup.focus_set()

        photo = self.otp.generate_uri()
        label = tk.Label(popup, image=photo)
        label.image = photo
        label.pack()

        self.db.set_mfa(self.session.user_id)

        popup.bind("<Return>", lambda e: popup.destroy())
        popup.wait_window(popup)

    def page_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        def check_totp():
            # list to keep scope
            result = [False]

            def on_otp():
                input_totp = totp_entry.get()
                if self.otp.verify_totp(input_totp):
                    result[0] = True
                    popup.destroy()
                else:
                    tk.messagebox.showerror(
                        t("DIALOG_ERROR"), t("MSG_INVALID_TOTP"), parent=popup
                    )
                    totp_entry.delete(0, tk.END)
                    totp_entry.focus_set()

            #
            popup = tk.Toplevel()
            popup.configure(bg="#1A1D2E")
            popup.title(t("TITLE_TOTP"))
            self.center_window(popup, 300, 200)

            # label TOTP
            self.theme.label(popup, t("TITLE_TOTP"), ("Segoe UI", 18, "bold")).pack(
                pady=10
            )

            # entry TOTP
            totp_entry = self.theme.entry(popup, font=("Segoe UI", 12))
            totp_entry.pack(pady=(0, 10))
            # allow enter button
            totp_entry.bind("<Return>", lambda e: on_otp())
            totp_entry.focus_set()

            # button verify TOTP
            btn_verify_totp = self.theme.button(
                popup,
                on_otp,
                t("BTN_CHECK"),
                font=("Segoe UI", 12, "bold"),
                bg="#4F6EF7",
                width=18,
                height=1,
            )
            btn_verify_totp.pack(pady=10)

            totp = self.otp.generate_totp()

            popup.wait_window(popup)

            return result[0]

        # parameter event: for <return> button on login
        def verify_master_password(event=None):
            input_username = username_entry.get()
            input_password = txt_password.get()

            # return {user_id, dek} or None
            result = self.auth.verify_master_password(input_username, input_password)
            if result is False:
                tk.messagebox.showerror(t("DIALOG_ERROR"), t("MSG_WRONG_PASSWORD"))
                self.page_login()

            self.session = Session(result["user_id"], result["username"], result["dek"])

            # check if 2FA is enabled
            if self.db.get_mfa(self.session.user_id):
                self.otp.set_otp_secret(self.db.get_otp_secret(self.session.user_id))
                if check_totp():
                    self.page_passwords(self.root)
            else:
                self.page_passwords(self.root)

        #
        self.center_window(self.root, self.width, self.height)
        self.root.title(t("TITLE_PASSWORD_MANAGER"))

        # label title
        self.theme.label(
            self.root, t("TITLE_PASSWORD_MANAGER"), ("Segoe UI", 18, "bold")
        ).pack(pady=10)

        # TODO: translations
        # label username
        self.theme.label(self.root, "Username", ("Segoe UI", 12), fg="#889082").pack(
            pady=(0, 5)
        )

        username_entry = self.theme.entry(self.root, font=("Segoe UI", 12))
        username_entry.pack()
        username_entry.focus_set()

        # label type password
        self.theme.label(
            self.root, t("LABEL_MASTER_PASSWORD"), ("Segoe UI", 12), fg="#889082"
        ).pack(pady=(0, 5))

        # entry password
        txt_password = self.theme.entry(self.root, show="*", font=("Segoe UI", 12))
        txt_password.pack()
        # allow enter button
        txt_password.bind("<Return>", verify_master_password)

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

        # button create user
        btn_create_master = self.theme.button(
            self.root,
            lambda: self.create_master_password(self.root),
            t("BTN_CREATE_USER"),
            font=("Segoe UI", 11, "bold"),
            bg="#2F3355",
        )
        btn_create_master.pack(pady=(10, 0))

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
        btn_lang.pack(side="right", padx=20, pady=(0, 10))

        self.root.mainloop()

    def create_master_password(self, root):
        def on_ok(event=None):
            masterpw = pw_entry.get()
            masterpw2 = pw_entry2.get()

            if masterpw == masterpw2:
                # password requirements
                result = self.auth.validate_master_password(masterpw)
                # True or error string
                if result is True:
                    self.auth.create_master_password(masterpw)

                    response = msg.askyesno(t("DIALOG_SUCCESS"), t("MSG_CONFIGURE_2FA"))
                    if response:
                        self.db.set_mfa(self.session.user_id)
                        self.show_qrcode()
                    self.page_login()
                else:
                    msg.showwarning(t("DIALOG_ERROR"), result)
            else:
                msg.showwarning(t("DIALOG_ERROR"), t("MSG_DIFFERENT_PASSWORD"))

        for widget in root.winfo_children():
            widget.destroy()

        # label title
        self.theme.label(
            self.root, t("TITLE_CREATE_USER"), ("Segoe UI", 18, "bold")
        ).pack(pady=10)

        # TODO: use translations for username
        # label username
        self.theme.label(
            self.root,
            "Username",
            ("Segoe UI", 12),
            fg="#889082",
        ).pack(pady=(0, 2))

        # entry username
        username_entry = self.theme.entry(self.root, font=("Segoe UI", 12))
        username_entry.pack(pady=(0, 10))
        username_entry.focus_set()

        # label type password
        self.theme.label(
            self.root,
            t("LABEL_CHOOSE_MASTER_PASSWORD"),
            ("Segoe UI", 12),
            fg="#889082",
        ).pack(pady=(0, 2))

        # entry password
        pw_entry = self.theme.entry(self.root, show="*", font=("Segoe UI", 12))
        pw_entry.pack(pady=(0, 10))

        # label retype password
        self.theme.label(
            self.root,
            t("LABEL_REENTER_MASTER_PASSWORD"),
            ("Segoe UI", 12),
            fg="#889082",
        ).pack(pady=(0, 2))

        # entry retype password
        pw_entry2 = self.theme.entry(self.root, show="*", font=("Segoe UI", 12))
        pw_entry2.pack(pady=(0, 10))
        # allow enter button
        pw_entry2.bind("<Return>", on_ok)

        # button create user
        btn_create = self.theme.button(
            self.root,
            on_ok,
            t("BTN_CREATE"),
            font=("Segoe UI", 12, "bold"),
            bg="#4F6EF7",
            width=18,
            height=1,
        )
        btn_create.pack(pady=10)

        # button back
        btn_back = self.theme.button(
            self.root,
            lambda: self.page_login(),
            t("BTN_BACK"),
            font=("Segoe UI", 12, "bold"),
            bg="#2F3355",
            width=18,
            height=1,
        )
        btn_back.pack(pady=10)

    def add_password(self):
        def on_ok(event=None):
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            password2 = password_entry2.get()

            if password == password2:
                password_bytes = password.encode("utf-8")
                encrypted_password = self.crypto.encrypt(password_bytes)

                if service and username and password:
                    self.db.add_password(
                        self.session.user_id, service, username, encrypted_password
                    )
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

        #
        popup = tk.Toplevel()
        popup.configure(bg="#1A1D2E")
        self.center_window(popup, 300, 400)
        popup.title(t("TITLE_ADD_PASSWORD"))

        # label service
        self.theme.label(
            popup, t("LABEL_SERVICE"), ("Segoe UI", 12), fg="#889082"
        ).pack(pady=(5, 2))

        # entry service
        service_entry = self.theme.entry(popup, font=("Segoe UI", 12))
        service_entry.pack(pady=(0, 10))
        service_entry.focus_set()

        # label username
        self.theme.label(
            popup, t("LABEL_USERNAME"), ("Segoe UI", 12), fg="#889082"
        ).pack(pady=(0, 2))

        # entry username
        username_entry = self.theme.entry(popup, font=("Segoe UI", 12))
        username_entry.pack(pady=(0, 10))

        # label password
        self.theme.label(
            popup, t("LABEL_PASSWORD"), ("Segoe UI", 12), fg="#889082"
        ).pack(pady=(0, 2))

        # entry password
        password_entry = self.theme.entry(popup, show="*", font=("Segoe UI", 12))
        password_entry.pack(pady=(0, 10))

        # label retype password
        self.theme.label(
            popup, t("LABEL_REENTER_PASSWORD"), ("Segoe UI", 12), fg="#889082"
        ).pack(pady=(0, 2))

        # entry retype password
        password_entry2 = self.theme.entry(popup, show="*", font=("Segoe UI", 12))
        password_entry2.pack(pady=(0, 10))
        # allow enter button
        password_entry2.bind("<Return>", on_ok)

        # button add password
        btn_add = self.theme.button(
            popup,
            on_ok,
            t("BTN_OK"),
            font=("Segoe UI", 12, "bold"),
            bg="#4F6EF7",
            width=18,
            height=1,
        )
        btn_add.pack(pady=10)

        # button generate password
        btn_generate_password = self.theme.button(
            popup,
            lambda: on_generate(),
            t("BTN_GENERATE_PASSWORD"),
            font=("Segoe UI", 12, "bold"),
            bg="#2F3355",
            width=18,
            height=1,
        )
        btn_generate_password.pack(pady=10)

    def load_data(self, tree):
        passwords = self.db.read_table_passwords(self.session.user_id)

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

        # middle frame (button add password, button enable 2FA)
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
        btn_add.focus_set()

        # button enable 2FA
        btn_add_2FA = self.theme.button(
            middle_frame,
            lambda: on_enable_2FA(),
            t("BTN_ENABLE_2FA"),
            font=("Segoe UI", 11, "bold"),
            bg="#2F3355",
        )
        btn_add_2FA.pack(side="right", padx=(0, 5), pady=(2, 2))

        # bottom frame (button change master password, disable 2FA)
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
        btn_change_password.pack(side="left", padx=(5, 0), pady=(2, 2))

        # button disable 2FA
        btn_remove_2fa = self.theme.button(
            bottom_frame,
            lambda: on_disable_2fa(),
            t("BTN_DISABLE_2FA"),
            font=("Segoe UI", 10, "bold"),
            bg="#2F3355",
            width=20,
            height=2,
        )
        btn_remove_2fa.pack(side="right", padx=(0, 5), pady=(2, 2))

        def on_logout():
            for widget in root.winfo_children():
                widget.destroy()
            self.clear_memory()
            self.page_login()

        def on_enable_2FA():
            input_password = txt_password.get()
            if not self.auth.verify_master_password(
                self.session.username, input_password
            ):
                tk.messagebox.showerror(
                    t("DIALOG_ERROR"), t("MSG_NO_2FA_OR_WRONG_PASSWORD")
                )
                self.page_login()

            # ask user if they want to configure 2FA
            response = msg.askyesno(t("DIALOG_SUCCESS"), t("MSG_CONFIGURE_2FA"))
            if response:
                # create and set otp secret
                encrypted_otp = self.otp.create_otp_secret()
                self.otp.set_otp_secret(encrypted_otp)

                # save to database
                self.db.set_otp_secret(self.session.user_id, encrypted_otp)

                self.show_qrcode()

        def on_disable_2fa():
            if self.db.get_mfa(self.session.user_id):
                response = msg.askyesno(
                    t("DIALOG_SUCCESS"), t("MSG_REMOVE_2FA_CONFIRM")
                )
                if response:
                    self.db.disable_mfa(self.session.user_id)
                    msg.showinfo(t("DIALOG_2FA_STATUS"), t("MSG_2FA_DISABLED"))
            else:
                tk.messagebox.showerror(
                    t("DIALOG_ERROR"), t("MSG_2FA_ALREADY_DISABLED"), parent=root
                )

        def on_change_password():
            def on_ok(event=None):
                old_password = old_password_entry.get()
                new_password = new_password_entry.get()
                new_password2 = new_password_entry2.get()

                if not self.auth.verify_master_password(
                    self.session.username, old_password
                ):
                    tk.messagebox.showerror(t("DIALOG_ERROR"), t("MSG_WRONG_PASSWORD"))
                    popup.destroy()
                    return

                if new_password == new_password2:
                    result = self.auth.validate_master_password(new_password)

                    if result is True:
                        self.auth.create_master_password(
                            new_password, change_password=True, session=self.session
                        )
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

            #
            popup = tk.Toplevel()
            popup.configure(bg="#1A1D2E")
            self.center_window(popup, 300, 300)
            popup.title(t("TITLE_CHANGE_PASSWORD"))

            # label old password
            self.theme.label(
                popup, t("LABEL_OLD_PASSWORD"), ("Segoe UI", 12), fg="#889082"
            ).pack(pady=(5, 2))

            # entry old password
            old_password_entry = self.theme.entry(
                popup, show="*", font=("Segoe UI", 12)
            )
            old_password_entry.pack(pady=(0, 10))
            old_password_entry.focus_set()

            # label new password
            self.theme.label(
                popup, t("LABEL_NEW_PASSWORD"), ("Segoe UI", 12), fg="#889082"
            ).pack(pady=(0, 2))

            # entry new password
            new_password_entry = self.theme.entry(
                popup, show="*", font=("Segoe UI", 12)
            )
            new_password_entry.pack(pady=(0, 10))

            # label re-type new password
            self.theme.label(
                popup, t("LABEL_REENTER_PASSWORD"), ("Segoe UI", 12), fg="#889082"
            ).pack(pady=(0, 2))

            # entry re-type new password
            new_password_entry2 = self.theme.entry(
                popup, show="*", font=("Segoe UI", 12)
            )
            new_password_entry2.pack(pady=(0, 10))
            # allow enter button
            new_password_entry2.bind("<Return>", on_ok)

            btn_change_password = self.theme.button(
                popup,
                on_ok,
                t("BTN_OK"),
                font=("Segoe UI", 12, "bold"),
                bg="#4F6EF7",
                width=18,
                height=1,
            )
            btn_change_password.pack(pady=10)

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
            item_id = values[0]
            encrypted_password = self.db.get_password(item_id)
            real_password = self.crypto.decrypt(encrypted_password).decode("utf-8")
            msg.showinfo(t("LABEL_PASSWORD"), real_password)

        # double click to show
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
            encrypted_password = self.db.get_password(item_id)
            real_password = self.crypto.decrypt(encrypted_password).decode("utf-8")

            self.root.clipboard_clear()
            self.root.clipboard_append(real_password)

        def delete_password(item):
            # get all columns
            values = self.tree.item(item, "values")

            item_id = values[0]

            response = msg.askyesno(t("BTN_DELETE"), t("MSG_ARE_YOU_SURE"))

            if response:
                self.db.delete_password(item_id)
                self.tree.delete(item)
