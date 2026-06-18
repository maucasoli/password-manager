TRANSLATIONS = {
    "en": {
        # window titles
        "TITLE_PASSWORD_MANAGER": "Password Manager",
        "TITLE_QR_CODE": "QR Code",
        "TITLE_TOTP": "TOTP",
        "TITLE_ADD_PASSWORD": "Add Password",
        "TITLE_CHANGE_PASSWORD": "Change Password",
        # labels
        "LABEL_MASTER_PASSWORD": "Master password:",
        "LABEL_CHOOSE_MASTER_PASSWORD": "Choose a master password:",
        "LABEL_REENTER_MASTER_PASSWORD": "Re-enter master password:",
        "LABEL_SERVICE": "Service",
        "LABEL_USERNAME": "Username",
        "LABEL_PASSWORD": "Password",
        "LABEL_REENTER_PASSWORD": "Re-enter password:",
        "LABEL_PASSWORDS": "Passwords",
        "LABEL_OLD_PASSWORD": "Old password:",
        "LABEL_NEW_PASSWORD": "New password:",
        # buttons
        "BTN_LOGIN": "Login",
        "BTN_CREATE_MASTER_USER": "Create Master User",
        "BTN_ENABLE_2FA": "Enable 2FA",
        "BTN_DISABLE_2FA": "Disable 2FA",
        "BTN_CHANGE_PASSWORD": "Change master password",
        "BTN_CREATE": "Create",
        "BTN_BACK": "Back",
        "BTN_OK": "OK",
        "BTN_GENERATE_PASSWORD": "Generate password",
        "BTN_LOGOUT": "Logout",
        "BTN_CHECK": "Check",
        "BTN_COPY": "Copy password",
        "BTN_DELETE": "Delete",
        # dialogs — titles
        "DIALOG_ALERT": "Alert",
        "DIALOG_ERROR": "Error",
        "DIALOG_SUCCESS": "Success",
        "DIALOG_2FA_STATUS": "2FA status",
        # dialogs — messages
        "MSG_LOGGED_OUT": "You've been logged out",
        "MSG_WRONG_PASSWORD": "Incorrect password",
        "MSG_INVALID_TOTP": "Invalid TOTP code",
        "MSG_CONFIGURE_2FA": "Do you want to configure 2FA now?",
        "MSG_DIFFERENT_PASSWORD": "Passwords do not match",
        "MSG_NO_2FA_OR_WRONG_PASSWORD": "No 2FA enabled or wrong password",
        "MSG_MASTER_USER_EXISTS": "Master user already exists",
        "MSG_PASSWORD_ADDED": "Password added successfully",
        "MSG_ALL_FIELDS_REQUIRED": "All fields are required",
        "MSG_REMOVE_2FA_CONFIRM": "Do you want to disable 2FA?",
        "MSG_2FA_DISABLED": "2FA has been disabled",
        "MSG_2FA_ALREADY_DISABLED": "2FA is already disabled",
        "MSG_ARE_YOU_SURE": "Are you sure?",
        # auth validation
        "VALIDATION_PASSWORD_MIN_LENGTH": "Password must be at least 8 characters long.",
        "VALIDATION_PASSWORD_LOWERCASE": "Password must contain at least one lowercase letter.",
        "VALIDATION_PASSWORD_UPPERCASE": "Password must contain at least one uppercase letter.",
        "VALIDATION_PASSWORD_NUMBER": "Password must contain at least one number.",
        "VALIDATION_PASSWORD_SPECIAL_CHAR": "Password must contain at least one special character.",
    },
    "fr": {
        # window titles
        "TITLE_PASSWORD_MANAGER": "Gestionnaire de mots de passe",
        "TITLE_QR_CODE": "Code QR",
        "TITLE_TOTP": "TOTP",
        "TITLE_ADD_PASSWORD": "Ajouter un mot de passe",
        "TITLE_CHANGE_PASSWORD": "Modifier le mot de passe",
        # labels
        "LABEL_MASTER_PASSWORD": "Mot de passe principal :",
        "LABEL_CHOOSE_MASTER_PASSWORD": "Choisissez un mot de passe principal :",
        "LABEL_REENTER_MASTER_PASSWORD": "Saisissez de nouveau le mot de passe principal :",
        "LABEL_SERVICE": "Service",
        "LABEL_USERNAME": "Nom d'utilisateur",
        "LABEL_PASSWORD": "Mot de passe",
        "LABEL_REENTER_PASSWORD": "Saisissez de nouveau le mot de passe",
        "LABEL_PASSWORDS": "Mots de passe",
        "LABEL_OLD_PASSWORD": "Mot de passe actuel :",
        "LABEL_NEW_PASSWORD": "Nouveau mot de passe :",
        # buttons
        "BTN_LOGIN": "Connexion",
        "BTN_CREATE_MASTER_USER": "Créer un utilisateur principal",
        "BTN_ENABLE_2FA": "Activer la 2FA",
        "BTN_DISABLE_2FA": "Désactiver la 2FA",
        "BTN_CHANGE_PASSWORD": "Modifier master password",
        "BTN_CREATE": "Créer",
        "BTN_BACK": "Retour",
        "BTN_OK": "OK",
        "BTN_GENERATE_PASSWORD": "Générer un mot de passe",
        "BTN_LOGOUT": "Déconnexion",
        "BTN_CHECK": "Vérifier",
        "BTN_COPY": "Copier mot de passe",
        "BTN_DELETE": "Supprimer",
        # dialogs — titles
        "DIALOG_ALERT": "Alerte",
        "DIALOG_ERROR": "Erreur",
        "DIALOG_SUCCESS": "Succès",
        "DIALOG_2FA_STATUS": "Statut de la 2FA",
        # dialogs — messages
        "MSG_LOGGED_OUT": "Vous avez été déconnecté",
        "MSG_WRONG_PASSWORD": "Mot de passe incorrect",
        "MSG_INVALID_TOTP": "Code TOTP invalide",
        "MSG_CONFIGURE_2FA": "Voulez-vous configurer la 2FA maintenant ?",
        "MSG_DIFFERENT_PASSWORD": "Les mots de passe ne correspondent pas",
        "MSG_NO_2FA_OR_WRONG_PASSWORD": "Aucune 2FA activée ou mot de passe incorrect",
        "MSG_MASTER_USER_EXISTS": "L'utilisateur principal existe déjà",
        "MSG_PASSWORD_ADDED": "Mot de passe ajouté avec succès",
        "MSG_ALL_FIELDS_REQUIRED": "Tous les champs sont requis",
        "MSG_REMOVE_2FA_CONFIRM": "Voulez-vous désactiver la 2FA ?",
        "MSG_2FA_DISABLED": "La 2FA a été désactivée",
        "MSG_2FA_ALREADY_DISABLED": "La 2FA est déjà désactivée",
        "MSG_ARE_YOU_SURE": "Êtes-vous sûr ?",
        # auth validation
        "VALIDATION_PASSWORD_MIN_LENGTH": "Le mot de passe doit contenir au moins 8 caractères.",
        "VALIDATION_PASSWORD_LOWERCASE": "Le mot de passe doit contenir au moins une lettre minuscule.",
        "VALIDATION_PASSWORD_UPPERCASE": "Le mot de passe doit contenir au moins une lettre majuscule.",
        "VALIDATION_PASSWORD_NUMBER": "Le mot de passe doit contenir au moins un chiffre.",
        "VALIDATION_PASSWORD_SPECIAL_CHAR": "Le mot de passe doit contenir au moins un caractère spécial.",
    },
}

LANG = "en"


def set_lang(lang):
    global LANG
    LANG = lang


def t(key: str) -> str:
    # if not key in lang, return the key itself
    return TRANSLATIONS.get(LANG, TRANSLATIONS["en"]).get(key, key)
