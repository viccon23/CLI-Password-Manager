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

# Helper function to derive an encryption key from a master password and a salt
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
    print(" -- pvlco 2025\n")

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
        print("Incorrect master password.")
        return None

def main():
    # --- Initial Setup Check ---
    if not os.path.exists(MASTER_CONFIG_FILE):
        if len(sys.argv) > 1: # User tried to run a command before setup
            print(f"Master password not set up. Please run 'python {os.path.basename(sys.argv[0])}' first to set it up.")
            return
        else: # No command, just 'python cli_manager.py' -> run setup
            setup_master_password()
            return # Exit after setup

    # --- Setup is done, proceed with command parsing ---
    parser = argparse.ArgumentParser(
        description="Password Manager CLI. Manages encrypted password entries.",
        epilog=f"Example: python {os.path.basename(sys.argv[0])} add my_service my_username my_password123"
    )
    # Subparsers are required if setup is complete
    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    # Add command
    parser_add = subparsers.add_parser("add", help="Add new entry (service, username, password)")
    parser_add.add_argument("service", help="Name of the service (e.g., gmail.com)")
    parser_add.add_argument("username", help="Username for the service")
    parser_add.add_argument("password", help="Password for the service")

    # Get command
    parser_get = subparsers.add_parser("get", help="Get and decrypt password for a service")
    parser_get.add_argument("service", help="Name of the service to retrieve")

    # Delete command
    parser_delete = subparsers.add_parser("delete", help="Delete an entry for a service")
    parser_delete.add_argument("service", help="Name of the service to delete")

    # List command
    subparsers.add_parser("list", help="List all service entries (usernames only)")

    # Search command
    parser_search = subparsers.add_parser("search", help="Search for entries by service name")
    parser_search.add_argument("service_query", help="Part of the service name to search for")

    # Update command
    parser_update = subparsers.add_parser("update", help="Update an existing entry")
    parser_update.add_argument("service", help="Name of the service to update")
    parser_update.add_argument("--username", help="New username for the service (optional)")
    parser_update.add_argument("--password", help="New password for the service (optional, will be re-encrypted)")

    # Generate command
    parser_generate = subparsers.add_parser("generate", help="Generate a strong random password")
    parser_generate.add_argument("--length", type=int, default=16, help="Length of the password (default: 16)")
    parser_generate.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    parser_generate.add_argument("--no-numbers", action="store_true", help="Exclude numbers")
    parser_generate.add_argument("--no-lowercase", action="store_true", help="Exclude lowercase letters")
    parser_generate.add_argument("--no-uppercase", action="store_true", help="Exclude uppercase letters")


    # If no command is given (e.g., 'python cli_manager.py' after setup), argparse with required=True handles it.
    # However, if sys.argv has only 1 element, it means no command was passed.
    if len(sys.argv) == 1: # Should have been caught by setup check if MASTER_CONFIG_FILE didn't exist
                           # If it exists, and still len(sys.argv) == 1, print help.
        parser.print_help()
        return

    args = parser.parse_args()

    # --- Command Execution ---
    if args.command == "add":
        # Verify the master password before adding an entry
        master_password = get_verified_master_password()
        if not master_password:
            return # Verification failed or was cancelled by user

        # Generate a new, unique salt for this password entry
        entry_salt = os.urandom(16)
        
        # Derive the encryption key using the VERIFIED master password and the new entry's salt
        encryption_key_for_entry = derive_key(master_password, entry_salt)
        fernet = Fernet(encryption_key_for_entry)

        # Encrypt the actual password for the service
        encrypted_password_bytes = fernet.encrypt(args.password.encode())

        new_entry = {
            "service": args.service,
            "username": args.username,
            "password_encrypted": encrypted_password_bytes.decode(),
            "salt": base64.urlsafe_b64encode(entry_salt).decode()
        }

        entries = []
        try:
            if os.path.exists(PASSWORDS_DATA_FILE) and os.path.getsize(PASSWORDS_DATA_FILE) > 0:
                with open(PASSWORDS_DATA_FILE, "r") as f:
                    entries = json.load(f)
            
            if any(entry['service'].lower() == args.service.lower() for entry in entries):
                print(f"Error: An entry for service '{args.service}' already exists. Use 'update' command if you want to change it.")
                return

            entries.append(new_entry)
            with open(PASSWORDS_DATA_FILE, "w") as f:
                json.dump(entries, f, indent=4)
            
            print(f"Entry for '{args.service}' added successfully and encrypted.")

        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON from {PASSWORDS_DATA_FILE}. The file might be corrupted.")
        except IOError as e:
            print(f"Error saving entry to {PASSWORDS_DATA_FILE}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while adding the entry: {e}")
        
    elif args.command == "get":
        master_password = get_verified_master_password()
        if not master_password:
            return
        print(f"Getting entry for service: {args.service} (implementation pending)...")
        # TODO: Implement get logic (load entries, find service, use master_password and entry's salt to decrypt)
    elif args.command == "delete":
        master_password = get_verified_master_password() # May not be needed if just deleting, but good for consistency or if confirmation is added
        if not master_password:
            return
        print(f"Deleting entry for service: {args.service} (implementation pending)...")
        # TODO: Implement delete logic
    elif args.command == "list":
        # Listing service names and usernames might not require master password,
        # but if you want to be strict, you can ask for it to "unlock" the manager.
        # For now, let's assume it doesn't for listing non-sensitive parts.
        print("Listing all entries (implementation pending)...")
        # TODO: Implement list logic (load entries, print service/username)
    elif args.command == "search":
        print(f"Searching for service: {args.service_query} (implementation pending)...")
        # TODO: Implement search logic
    elif args.command == "update":
        master_password = get_verified_master_password()
        if not master_password:
            return
        print(f"Updating entry for service: {args.service} (implementation pending)...")
        # TODO: Implement update logic (similar to add, but find existing, re-encrypt if password changes)
    elif args.command == "generate":
        print(f"Generating password (implementation pending)...")
        # TODO: Implement password generation logic
    # No need for 'elif args.command is None:' because subparsers are required.

if __name__ == "__main__":
    main()