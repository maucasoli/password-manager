# Password Manager

Desktop password manager written in Python/Tkinter. Built to actually learn applied cryptography (KDFs, envelope encryption) — the crypto here is the same kind of design real vaults use.

![Login page](https://github.com/maucasoli/password-manager/blob/main/docs/login.png "Login page")
![Password page](https://github.com/maucasoli/password-manager/blob/main/docs/password.png "Password page")
> *Note: All credentials, QR codes, and recovery keys displayed are mock data generated strictly for demonstration purposes.*

## Security

- **Master password never stored.** It's only used transiently to derive a key via **Argon2id**, combined with a random 256-bit salt.
- **Envelope encryption.** The derived key (KEK) never touches disk — it only decrypts a Data Encryption Key (DEK), which is what actually encrypts vault entries. Changing the master password just re-wraps the DEK, no need to re-encrypt every entry.
- **AES-256-GCM** for everything stored: service, username, password, TOTP secret. Each field gets its own random nonce.
- **Optional TOTP 2FA**, QR provisioning compatible with Google Authenticator/Authy. Secret is encrypted at rest like everything else.
- **Recovery codes without a backdoor.** Only the SHA-256 hash of the one-time code is stored, checked with `hmac.compare_digest`.

## Features

- Master password + optional 2FA login
- Encrypted vault (service / username / password)
- Secure password generator (`secrets`, not `random`)
- Single-use recovery codes for lost 2FA
- Login throttling + timed lockout
- Idle auto-lock, clipboard auto-clear
- Multi-user support
- EN/FR interface
- Local SQLite

## Layout

```
main.py          entry point / wiring
auth.py          master password, KEK/DEK, recovery codes, lockout
crypto.py        AES-256-GCM helpers
database.py      SQLite schema + queries
otp.py           TOTP secret, QR code
generator.py     secure password / recovery code generation
ui.py            Tkinter views
translations.py  i18n
```

## Running

```bash
pip install -r requirements.txt
python main.py
```

- `--debug` flag lowers the Argon2id cost for local testing only.

## Status

Personal project. Treat it as a portfolio piece, not a production vault.
