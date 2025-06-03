import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import getpass # For securely getting master password
import json    # For storing data as JSON (example)
import sys     # To check command-line arguments
import shlex   # For safely splitting command input


# Configuration
# This is the file where encrypted passwords will be stored
# It should be kept secure and not shared with anyone
# Configuration
PASSWORDS_DATA_FILE = "passwords_data.json"
MASTER_CONFIG_FILE = "master_config.json" # Stores master salt and verifier
VERIFIER_TEXT = b"cli_master_password_is_set_and_verified" # A known text for verification
# Specifies how many times the hashfunction is applied to input
# Increases the work factor for brute-force attacks
# A higher number means more time to derive the key, making it harder for attackers
PBKDF2_ITERATIONS = 480000

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a Fernet-compatible key from a master password and salt."""
    """Takes master password and a salt, then uses PBKDF2HMAC (a key derivation function) to create an encryption key.
       PBKDF2HMAC helps protect against brute-force attacks on master password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key size
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)

def setup_master_password():
    """Guides the user through setting up their master password."""
    print("--- Welcome to CLI Password Manager Setup ---")
    print("You need to set a master password.")
    print("This password will be used to encrypt a key that encrypts all your stored entries.")
    print("\nIMPORTANT:")
    print("1. Choose a STRONG and UNIQUE master password.")
    print("2. DO NOT FORGET IT. If you lose this password, you will lose access to ALL your stored passwords permanently.")
    print("   There is NO recovery mechanism.\n")
    print(" -- pocho © 2025\n")

    while True:
        mp1 = getpass.getpass("Enter new master password: ")
        if not mp1:
            print("Master password cannot be empty. Please try again.")
            continue
        mp2 = getpass.getpass("Confirm new master password: ")
        if mp1 == mp2:
            break
        else:
            print("Passwords do not match. Please try again.")

    master_salt = os.urandom(16) # Salt for the master password verifier
    # Key derived from master password and master_salt is used ONLY for the verifier
    key_for_verifier = derive_key(mp1, master_salt)
    f_verifier = Fernet(key_for_verifier)
    encrypted_verifier = f_verifier.encrypt(VERIFIER_TEXT)

    config_data = {
        "master_salt": base64.urlsafe_b64encode(master_salt).decode(),
        "encrypted_verifier": base64.urlsafe_b64encode(encrypted_verifier).decode()
    }
    try:
        with open(MASTER_CONFIG_FILE, "w") as f:
            json.dump(config_data, f, indent=4)
        print(f"\nMaster password set up successfully. Configuration saved to {MASTER_CONFIG_FILE}")

        # Initialize an empty passwords data file if it doesn't exist
        if not os.path.exists(PASSWORDS_DATA_FILE):
            with open(PASSWORDS_DATA_FILE, "w") as f:
                json.dump([], f)
        print(f"Password data will be stored in {PASSWORDS_DATA_FILE}")
        print("\nSetup complete. You can now use commands like 'add', 'get', etc.")
        print(f"For example: python {os.path.basename(sys.argv[0])} add <service> <username> <password>")
    except IOError as e:
        print(f"Error: Could not write master configuration: {e}")
        print("Setup failed. Please check file permissions and try again.")
        # Consider removing MASTER_CONFIG_FILE if partially written and failed
        if os.path.exists(MASTER_CONFIG_FILE):
            os.remove(MASTER_CONFIG_FILE)

def get_verified_master_password() -> str | None:
    """
    Prompts for master password, verifies it against stored verifier.
    Returns the master password string if verified, None otherwise.
    """
    if not os.path.exists(MASTER_CONFIG_FILE):
        # This case should ideally be handled before calling this function by checking setup status
        print(f"Error: Master password configuration ({MASTER_CONFIG_FILE}) not found.")
        print(f"Please run 'python {os.path.basename(sys.argv[0])}' to set it up.")
        return None

    try:
        with open(MASTER_CONFIG_FILE, "r") as f:
            config_data = json.load(f)
        master_salt_b64 = config_data.get("master_salt")
        encrypted_verifier_b64 = config_data.get("encrypted_verifier")

        if not master_salt_b64 or not encrypted_verifier_b64:
            print(f"Error: Master configuration file {MASTER_CONFIG_FILE} is corrupted or incomplete.")
            return None

        master_salt = base64.urlsafe_b64decode(master_salt_b64)
        encrypted_verifier = base64.urlsafe_b64decode(encrypted_verifier_b64)

    except (json.JSONDecodeError, KeyError, base64.binascii.Error, IOError) as e:
        print(f"Error reading or parsing master config file ({MASTER_CONFIG_FILE}): {e}")
        print("It might be corrupted. If the problem persists, you may need to remove it and set up again (this will require re-entering all passwords).")
        return None

    master_password_input = getpass.getpass("Enter your master password: ")
    if not master_password_input:
        print("Master password cannot be empty.")
        return None

    # Derive key using the input password and the stored master_salt
    derived_key_for_verifier = derive_key(master_password_input, master_salt)
    f_verifier = Fernet(derived_key_for_verifier)

    try:
        decrypted_verifier = f_verifier.decrypt(encrypted_verifier)
        if decrypted_verifier == VERIFIER_TEXT:
            return master_password_input # Password is correct
        else:
            # This case should ideally not happen if Fernet decrypts successfully with the right key
            # and VERIFIER_TEXT is constant. It implies a hash collision or an unexpected issue.
            print("Incorrect master password (verification mismatch).")
            return None
    except Exception: # Catches Fernet's InvalidToken if key is wrong or data is tampered
        return None

# --- Command Handler Functions ---
def clear_console():
    # Clear console based on the operating system
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Unix/Linux/Mac
        os.system('clear')

def handle_add_command(args_list: list, master_password: str):
    if len(args_list) != 3:
        print("Usage: add <service> <username> <password>")
        return

    service, username, password_to_add = args_list[0], args_list[1], args_list[2]

    entry_salt = os.urandom(16)
    encryption_key_for_entry = derive_key(master_password, entry_salt)
    fernet = Fernet(encryption_key_for_entry)
    encrypted_password_bytes = fernet.encrypt(password_to_add.encode())

    new_entry = {
        "service": service,
        "username": username,
        "password_encrypted": encrypted_password_bytes.decode(),
        "salt": base64.urlsafe_b64encode(entry_salt).decode()
    }
    entries = []
    try:
        if os.path.exists(PASSWORDS_DATA_FILE) and os.path.getsize(PASSWORDS_DATA_FILE) > 0:
            with open(PASSWORDS_DATA_FILE, "r") as f:
                entries = json.load(f)
        
        if any(entry['service'].lower() == service.lower() for entry in entries):
            print(f"Error: An entry for service '{service}' already exists. Use 'update' command.")
            return

        entries.append(new_entry)
        with open(PASSWORDS_DATA_FILE, "w") as f:
            json.dump(entries, f, indent=4)
        print(f"Entry for '{service}' added successfully.")
    except Exception as e:
        print(f"Error adding entry: {e}")

def handle_get_command(args_list: list, master_password: str):
    if len(args_list) != 1:
        print("Usage: get <service>")
        return
    service_to_get = args_list[0]
    try:
        if not os.path.exists(PASSWORDS_DATA_FILE) or os.path.getsize(PASSWORDS_DATA_FILE) == 0:
            print("Password data file is empty or not found.")
            return
        with open(PASSWORDS_DATA_FILE, "r") as f:
            entries = json.load(f)
        entry = next((e for e in entries if e['service'].lower() == service_to_get.lower()), None)

        if entry:
            entry_salt = base64.urlsafe_b64decode(entry['salt'])
            encrypted_password_bytes = entry['password_encrypted'].encode('utf-8')
            encryption_key_for_entry = derive_key(master_password, entry_salt)
            fernet = Fernet(encryption_key_for_entry)
            decrypted_password = fernet.decrypt(encrypted_password_bytes).decode()
            print(f"\nService: {entry['service']}\nUsername: {entry['username']}\nPassword: {decrypted_password}")
        else:
            print(f"No entry found for service '{service_to_get}'.")
    except Exception as e:
        print(f"Error getting entry: {e}")

def handle_list_command(args_list: list, master_password: str):
    # master_password might not be strictly needed here if we only show service/username
    # but it's passed for consistency and if future enhancements require it.
    if args_list: # list command takes no arguments
        print("Usage: list")
        return
    try:
        if not os.path.exists(PASSWORDS_DATA_FILE) or os.path.getsize(PASSWORDS_DATA_FILE) == 0:
            print("No entries to list.")
            return
        with open(PASSWORDS_DATA_FILE, "r") as f:
            entries = json.load(f)
        if not entries:
            print("No entries found.")
            return
        print("\n--- Stored Entries ---")
        for i, entry in enumerate(entries):
            service_name = entry.get('service', 'N/A')
            username = entry.get('username', 'N/A')
            print(f"{i+1}. Service: {service_name}, Username: {username}")
        print("--- End of List ---")
    except Exception as e:
        print(f"Error listing entries: {e}")

def handle_delete_command(args_list: list, master_password: str):
    if len(args_list) != 1:
        print("Usage: delete <service>")
        return
    service_to_delete = args_list[0]
    try:
        if not os.path.exists(PASSWORDS_DATA_FILE) or os.path.getsize(PASSWORDS_DATA_FILE) == 0:
            print("Password data file is empty or not found.")
            return
        with open(PASSWORDS_DATA_FILE, "r") as f:
            entries = json.load(f)
        
        original_length = len(entries)
        entries = [e for e in entries if e['service'].lower() != service_to_delete.lower()]

        if len(entries) < original_length:
            with open(PASSWORDS_DATA_FILE, "w") as f:
                json.dump(entries, f, indent=4)
            print(f"Entry for '{service_to_delete}' deleted successfully.")
        else:
            print(f"No entry found for service '{service_to_delete}'.")
    except Exception as e:
        print(f"Error deleting entry: {e}")

def handle_help_command():
    print("\nAvailable commands:")
    print("  add <service> <username> <password> - Add a new password entry.")
    print("  get <service>                       - Retrieve a password for a service.")
    print("  list                                - List all service entries (names and usernames).")
    print("  delete <service>                    - Delete a password entry for a service.")
    # print("  update <service> [--username NEW_USER] [--password NEW_PASS] - Update an entry.") # TODO
    # print("  generate [--length L] [--complexity C] - Generate a password.") # TODO
    print("  help                                - Show this help message.")
    print("  exit                                - Exit the password manager.")
    print("")

# --- Main Application Logic ---
def main():
    # Initial setup check - this happens before the interactive loop
    if not os.path.exists(MASTER_CONFIG_FILE):
        # If any command-line arguments are passed during first run,
        # it might be confusing. For simplicity, just run setup.
        print("First time setup...")
        setup_master_password()
        # setup_master_password now exits on failure, or prints success.
        # If setup was successful, we can proceed to ask for login or just tell them to restart.
        print("Setup complete. Please restart the application to log in.")
        return

    # If setup is done, try to get the verified master password to "unlock"
    verified_master_password = get_verified_master_password()
    if not verified_master_password:
        print("Master password verification failed. Exiting.")
        return # Exit if master password verification fails
    
    clear_console()  # Clear console for better readability
    print("\nPassword Manager Unlocked. Type 'help' for commands.")
    print("\n --- pocho © 2025 ---\n")

    # Main interactive loop
    while True:
        try:
            raw_input = input("pm> ").strip()
            if not raw_input:
                continue

            clear_console()  # Clear console for better readability

            # Use shlex to handle quoted arguments safely
            try:
                parts = shlex.split(raw_input)
            except ValueError as e:
                print(f"Error parsing command: {e}. Ensure quotes are matched if used.")
                continue
                
            command = parts[0].lower() if parts else ""
            args_list = parts[1:]

            if command == "add":
                handle_add_command(args_list, verified_master_password)
            elif command == "get":
                handle_get_command(args_list, verified_master_password)
            elif command == "list":
                handle_list_command(args_list, verified_master_password)
            elif command == "delete":
                handle_delete_command(args_list, verified_master_password)
            # TODO: Add handlers for update, generate
            elif command == "help":
                handle_help_command()
            elif command == "exit":
                print("Exiting Password Manager. Goodbye!")
                break
            else:
                print(f"Unknown command: '{command}'. Type 'help' for available commands.")
        except KeyboardInterrupt:
            print("\nExiting Password Manager (Ctrl+C). Goodbye!")
            break
        except EOFError: # Ctrl+D
            print("\nExiting Password Manager (EOF). Goodbye!")
            break
        except Exception as e_loop:
            print(f"An unexpected error occurred in the main loop: {e_loop}")
            # Optionally, decide if you want to break the loop on all errors or try to continue
            # For now, let's continue, but log it.
            # Consider adding logging for such errors.

if __name__ == "__main__":
    # Remove argparse for command line parsing if primary mode is interactive
    # The initial check for MASTER_CONFIG_FILE in main() handles the first run.
    main()



# def main():
#     # --- Initial Setup Check ---
#     if not os.path.exists(MASTER_CONFIG_FILE):
#         if len(sys.argv) > 1: # User tried to run a command before setup
#             print(f"Master password not set up. Please run 'python {os.path.basename(sys.argv[0])}' first to set it up.")
#             return
#         else: # No command, just 'python cli_manager.py' -> run setup
#             setup_master_password()
#             return # Exit after setup



#     # elif args.command == "update":
#     #     master_password = get_verified_master_password()
#     #     if not master_password:
#     #         return
#     #     print(f"Updating entry for service: {args.service} (implementation pending)...")
#     #     # TODO: Implement update logic (similar to add, but find existing, re-encrypt if password changes)
#     # elif args.command == "generate":
#     #     print(f"Generating password (implementation pending)...")
#     #     # TODO: Implement password generation logic
#     # # No need for 'elif args.command is None:' because subparsers are required.