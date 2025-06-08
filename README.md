# CLI Password Manager

A simple command-line interface (CLI) password manager built with Python. This tool allows you to securely store and manage your passwords locally, encrypted with a master password.

pocho ©2025

## Features

*   **Secure Storage:** Passwords are encrypted using Fernet symmetric encryption.
*   **Master Password Protection:** All your passwords are protected by a single, strong master password.
*   **Key Derivation:** Uses PBKDF2HMAC with a high iteration count to derive encryption keys, protecting against brute-force attacks on your master password.
*   **Salting:**
    *   A unique salt is used for deriving the master password verifier.
    *   Each individual password entry is encrypted with a key derived using its own unique salt, enhancing security.
*   **Local Storage:** Password data is stored locally in JSON files (`master_config.json` and `passwords_data.json`).
*   **Interactive CLI:** Provides an interactive shell-like experience for managing passwords.
*   **Basic Commands:**
    *   `add`: Add a new password entry (service, username, password).
    *   `get`: Retrieve and decrypt a password for a service.
    *   `list`: List all stored service names and usernames.
    *   `delete`: Delete a password entry.
    *   `help`: Display available commands.
    *   `exit`: Exit the password manager.

*(Planned Features: `update` an entry, `generate` a strong password)*

## Security Considerations

*   **Master Password is Key:** The security of all your stored passwords relies **entirely** on the strength and secrecy of your master password.
    *   Choose a **long, complex, and unique** master password.
    *   **Do NOT forget your master password.** There is no recovery mechanism. If you lose it, your stored passwords will be inaccessible.
*   **Local Data Files:**
    *   The encrypted password data (`passwords_data.json`) and master password configuration (`master_config.json`) are stored locally on your computer.
    *   **These files should NOT be shared or committed to version control (like Git).** The `.gitignore` file in this repository is configured to ignore them.
    *   Anyone with access to these files AND your master password can decrypt your stored passwords. Ensure your computer is physically secure.
*   **Terminal History/Shoulder Surfing:** When using the `get` command, the password will be displayed in your terminal. Be mindful of your surroundings and your terminal's history settings.

## Prerequisites

*   Python 3.x (developed with Python 3.10+, but should work with recent Python 3 versions)
*   `pip` (Python package installer)

## Installation & Setup

1.  **Clone the Repository (or download the files):**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory-name>
    ```

2.  **Install Dependencies:**
    This project uses the `cryptography` library.
    ```bash
    pip install cryptography
    ```

3.  **First Run (Setup Master Password):**
    Run the script without any arguments to initiate the setup process:
    ```bash
    python cli_manager.py
    ```
    You will be guided through creating your master password. Please read the warnings carefully. After setup, you will be prompted to restart the application.

## Usage

1.  **Run the Password Manager:**
    After the initial setup, run the script again:
    ```bash
    python cli_manager.py
    ```
    You will be prompted to enter your master password to unlock the manager.

2.  **Interactive Commands:**
    Once unlocked, you'll see a `pm> ` prompt. Type `help` to see the list of available commands:
    *   `add <service> <username> <password>`
    *   `get <service>`
    *   `list`
    *   `delete <service>`
    *   `help`
    *   `exit`

    Arguments with spaces should be enclosed in quotes, e.g.:
    `add "My Web Service" myusername "my complex password"`

## Building an Executable (Optional)

You can create a standalone executable using tools like PyInstaller.

1.  **Install PyInstaller:**
    ```bash
    pip install pyinstaller
    ```
2.  **Build the Executable:**
    Navigate to the script's directory and run:
    ```bash
    pyinstaller --onefile cli_manager.py
    ```
    The executable will be created in a `dist` subfolder (e.g., `dist/cli_manager.exe` on Windows).

## Disclaimer

This project is primarily for educational purposes to demonstrate CLI application structure and basic cryptographic principles in Python. While it implements security best practices like strong key derivation and salting, always be cautious when managing sensitive data. Use at your own risk. For highly sensitive information, consider using well-vetted, professionally developed password managers.
