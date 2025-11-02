import getpass
from typing import Optional
import pyperclip
import PassManLib as lib  # Assuming your library is saved as PassManLib.py

# CUATION: COMPLETELY VIBECODED!!!!!!!!!!!!!!!!!!!
# TEMPORARY VERSION FOR TESTING PURPOSES ONLY!
# WILL BE OVERHAULED
def prompt_user_credentials() -> tuple[str, str]:
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    return username, password

def cli_create_user():
    print("=== Create New User ===")
    username, password = prompt_user_credentials()
    if lib.create_user(username, password):
        print("User created successfully!")
    else:
        print("Failed to create user.")

def cli_login() -> Optional[int]:
    print("=== Login ===")
    username, password = prompt_user_credentials()
    uid = lib.auth_user(username, password)
    if uid is not None:
        print(f"Logged in as {username} (uid {uid})")
        return uid
    print("Invalid username or password.")
    return None

def cli_add_password(uid: int):
    print("=== Add New Password ===")
    label = input("Label (site/app): ")
    login = input("Login/username: ")
    password = getpass.getpass("Password: ")
    if lib.add_password(uid, label, login, password):
        print(f"Password entry '{label}' added successfully!")
    else:
        print("Failed to add password entry.")

def cli_list_passwords(uid: int, show_decrypted: bool = False, master_password: str = ""):
    entries = lib.get_passwords(uid)
    if not entries:
        print("No passwords stored.")
        return
    for pid, label, login in entries:
        line = f"[{pid}] {label} -> {login}"
        if show_decrypted and master_password:
            decrypted = lib.decrypt_password(pid, master_password)
            if decrypted is not None:
                line += f" | {decrypted.decode(errors='replace')}"
            else:
                line += " | <decryption failed>"
        print(line)

def main():
    print("=== Welcome to PassMan CLI ===")
    lib.init_db()
    
    while True:
        print("\nAvailable commands:")
        print("1. Create user")
        print("2. Login")
        print("3. Quit")
        cmd = input("Select option: ").strip()
        
        if cmd == "1":
            cli_create_user()
        elif cmd == "2":
            uid = cli_login()
            if uid is None:
                continue
            master_password = getpass.getpass("Enter your master password for decryption: ")
            while True:
                print("\nUser commands:")
                print("1. Add password")
                print("2. List passwords")
                print("3. Logout")
                subcmd = input("Select option: ").strip()
                if subcmd == "1":
                    cli_add_password(uid)
                elif subcmd == "2":
                    cli_list_passwords(uid, show_decrypted=True, master_password=master_password)
                elif subcmd == "3":
                    print("Logging out...")
                    break
                else:
                    print("Unknown command.")
        elif cmd == "3":
            print("Exiting...")
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()
