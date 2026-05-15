# 🔐 SecureVault

A web-based password manager built with Python, Flask, and MySQL. SecureVault lets users securely store, manage, and organize their credentials — from everyday social media logins to sensitive banking details — with AES-256 encryption and tiered security levels.

---

## Features

- **AES-256 Encryption** — all passwords and sensitive fields are encrypted at rest
- **Credential Tiers** — security levels (critical, high, medium, low) with different re-auth and clipboard rules per type
- **Bank Credentials** — dedicated storage for account numbers, card details, and PINs, encrypted separately from login passwords
- **Session Management** — token-based sessions with expiry
- **Audit Logging** — every action on the vault is logged per user
- **Failed Login Tracking** — logs wrong master password attempts with IP and timestamp
- **Password History** — old passwords are retained (encrypted) every time a vault entry is updated
- **User Preferences** — per-user settings for auto-logout, clipboard timeout, and theme

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | MySQL |
| Encryption | AES-256 (PyCryptodome) |
| Templating | Jinja2 |

---

## Database Schema

The schema includes the following tables:

- `users` — registered accounts with hashed master passwords
- `credential_types` — predefined categories with security tiers
- `vault` — core credential storage linked to a user and type
- `bank_credentials` — extended encrypted fields for banking entries
- `failed_login_attempts` — brute force tracking
- `password_history` — historical encrypted passwords per vault entry
- `user_preferences` — per-user app settings
- `sessions` — active session tokens with expiry
- `audit_log` — full action history per user and vault entry

---

## Project Structure

```
securevault/
├── app.py
├── securevault.sql
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   └── vault.html
├── static/
└── requirements.txt
```

---

## Authors

| Name | GitHub |
|---|---|
| Maaz Arshad Akhund | [@maaz2417](https://github.com/maaz2417) |
| Bushra Asad | [@11bushraasad](https://github.com/11bushraasad) |

---

## Course

**Database Systems Lab** — BS Software Engineering, 4th Semester  
Institute of Management Sciences (IMSciences), Peshawar

---

## License

This project is for academic purposes only.
