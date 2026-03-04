# CZar Password Manager
CZar is a lightweight, secure, open-source CLI password manager with strong encryption and user authentication.

## Features
* **User Accounts:** Create and manage separate user accounts with master password authentication
* **Simplified Design:** Intuitive CLI-based interface for easy password management
* **Secure Password Generation:** Generate strong randomized passwords with configurable length
* **Military-Grade Encryption:** AES-256-GCM authenticated encryption with PBKDF2 key derivation
* **Secure Master Password:** Passwords hashed with Argon2 for maximum security
* **Password Storage & Encryption:** Safely store and encrypt passwords for multiple accounts
* **Data Backup:** Export encrypted passwords to backup file and import them later
* **Cross-Platform:** Works on Windows and Linux
* **Secure Clipboard:** Auto-clear clipboard after copying sensitive data

## Requirements
* Python 3.7+
* See `requirements.txt` for dependencies

## Installation

1. Clone the repository:
    ```bash
    git clone <repository-url>
    cd CZar
    ```

2. Install required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Starting CZar
```bash
python startCzar.py
```

### Modes
Run CZar with different modes:

* **Interactive Mode** (default):
    ```bash
    python startCzar.py
    ```

* **Set Password** (create/store a password):
    ```bash
    python startCzar.py -m s
    ```

* **Get Password** (retrieve a stored password):
    ```bash
    python startCzar.py -m g
    ```

* **Delete Password**:
    ```bash
    python startCzar.py -m d
    ```

* **Export Backup** (encrypted backup):
    ```bash
    python startCzar.py -m e
    ```

* **Import Backup** (restore from backup):
    ```bash
    python startCzar.py -m i
    ```

## First Time Setup
1. Start the application: `python startCzar.py`
2. Choose "Create Account" (c)
3. Enter a username
4. Create a strong master password (used to encrypt all your passwords)
5. Confirm the master password

## Security Features
* **Master Password Authentication:** All users protected by Argon2 hashed master password
* **AES-256-GCM Encryption:** Industry-standard authenticated encryption
* **PBKDF2 Key Derivation:** 480,000 iterations for key length 32
* **Hidden Files:** Data directories hidden on Windows systems
* **Secure Random Generation:** Uses cryptographically secure `secrets` module
* **Authenticated Encryption:** Additional Authentication Data (AAD) prevents tampering

## Project Structure
```
CZar/
├── startCzar.py           # Main entry point
├── userManagement.py      # User account management and authentication
├── requirements.txt       # Project dependencies
├── README.md             # This file
├── crypto/
│   ├── aes.py           # AES-256-GCM encryption/decryption
│   └── randomPwd.py     # Secure password generation
├── ioUtils/
│   ├── ioUtilities.py       # File I/O operations
│   ├── clipboardUtils.py    # Clipboard management
│   └── readFromShell.py     # User input handling
├── data/                # User storage (encrypted passwords and users.json)
│   ├── users.json       # User accounts
│   └── [username]/      # Per-user encrypted password storage
└── Czar_logs/          # Application logs
```

## Notes
* Master password is required for every session - it's never stored
* Passwords are encrypted with your master password before storage
* Always backup your encrypted data before major changes
* Keep your master password secure - it cannot be recovered if lost

## License
See LICENSE file for details
