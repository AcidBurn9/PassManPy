import os
import logging
import getpass
import pyperclip
from typing import Tuple
from PassManLib import PassMan, RegStatus

passman: PassMan = None # Global object for functions to work with. Initialised in main().

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def print_header(str = ""):
    clear()
    print(f"=== PassMan TUI ===\n")
    if str != "": print(f"{str}\n")

def press_enter_to_continue():
    input("\nPress ENTER to continue")

def kys(code=0):
    print_header()
    print("Exiting!")
    logging.info(f"========== Exiting with code {code} ==========")
    try: press_enter_to_continue()
    except: pass # In case of an interupt during "Press Enter to continue"
    clear()
    exit(code)

def print_error(error):
    print(f"\nERROR: {error}")

def invalid_option(option):
    print_error(f"[{option}] is not a valid option!")
    press_enter_to_continue()

def prompt_username() -> str:
    username = input("Username: ")
    return username

def prompt_password(prompt="Password: ") -> str:
    password = getpass.getpass(prompt)
    return password

def prompt_valid_option(options) -> (int | None):
    n = len(options)

    for i in range(0, n):
        print(f"{i+1}: {options[i]}")
    print("\n0: Exit")
    option = input(f"Select an option (0-{n}): ").strip()

    if option == "": return None
    try: option = int(option)
    except:
        invalid_option(option)
        return None

    if option >= 0 and option < (n + 1): return option
    else:
        invalid_option(option)
        return None

# Password menu options
def copy_password(pid: int):
    masterpass = prompt_password("Master password: ")
    plaintext = passman.decrypt_password(pid=pid, masterpass=masterpass)
    masterpass = None # wiping from memory as soon as not needed
    if plaintext is None:
        print_error("Could not retrieve the password")
        press_enter_to_continue()
        return

    print_header()
    pyperclip.copy(plaintext)
    plaintext = None # wiping from memory as soon as not needed
    print("Copied to the clipboard!")
    press_enter_to_continue()

def show_password(pid: int, label: str, login: str):
    masterpass = prompt_password("Master password: ")
    plaintext = passman.decrypt_password(pid=pid, masterpass=masterpass)
    masterpass = None # wiping from memory as soon as not needed
    if plaintext is None:
        print_error("Could not retrieve the password")
        press_enter_to_continue()
        return

    padding = ""
    for i in range(0, len(plaintext)): padding = padding + "="

    print_header(f"[{label}] {login}")
    print(f"{padding}\n{plaintext}\n{padding}")
    press_enter_to_continue()
    clear()

def update_password(pid: int, label: str, login: str):
    masterpass = prompt_password("Master password: ")

    print_header(f"[{label}] {login}")

    new_password = prompt_password("New password: ")
    if passman.update_password(pid=pid, masterpass=masterpass, new_password=new_password): print("\nSuccess!")
    else: print_error("Failed to update the password!")
    masterpass = None # wiping from memory as soon as not needed
    press_enter_to_continue()
    clear()

def delete_password(pid: int) -> bool:
    masterpass = prompt_password("Master password: ")
    success = passman.delete_password(pid=pid, masterpass=masterpass)
    masterpass = None # wiping from memory as soon as not needed
    if success:
        print("\nSuccess!")
        press_enter_to_continue()
        return True # Caller function needs to know if password no longer exists to exit the page for that password
    else:
        print_error("Failed to delete the password!")
        press_enter_to_continue()
        return False

def password_menu(pid: int, label: str, login: str):
    password_options = [
        "Copy password",
        "Show password",
        "Update password",
        "Delete password"
    ]
    while True:
        print_header(f"[{label}] {login}")
        option = prompt_valid_option(password_options)
        match option:
            case 1: copy_password(pid)
            case 2: show_password(pid, label, login)
            case 3: update_password(pid, label, login)
            case 4:
                if delete_password(pid): break
                else: continue
            case 0: break
            case None: continue
            case _: invalid_option(option)

# User menu options
def add_password(uid: int):
    print_header("Add password")
    label = input("Label: ")
    login = input("Login: ")
    password = prompt_password()

    if passman.add_password(uid=uid, label=label, login=login, password=password): print("\nSuccess!")
    else: print_error("Failed to add password!")

    press_enter_to_continue()

def list_passwords(uid: int, search_query: str = ""):
    print_header()
    if search_query != "": print(f"Search: '{search_query}'")
    entries = passman.search_passwords(uid=uid, search_query=search_query)

    if not entries:
        print("No passwords.")
        press_enter_to_continue()
        return

    options = [f"[{label}] {login}" for _, label, login in entries]

    i = prompt_valid_option(options)
    if i == 0 or i is None: return
    pid, label, login = entries[i - 1]
    password_menu(pid, label, login)

def search_passwords(uid: int):
    print_header()
    search_query = input("Search passwords: ")
    list_passwords(uid, search_query)

# Main menu options
def login_menu() -> Tuple[str, (int | None)]:
    print_header("LOGIN")
    username = prompt_username()
    password = prompt_password()
    return username, passman.auth_user(username=username, password=password)

def user_menu():
    username, uid = login_menu()
    if uid is None:
        print("\nAuthentication failed!")
        press_enter_to_continue()
        return

    user_menu_options = [
        "Add password",
        "Search passwords",
        "List all passwords"
    ]
    while True:
        print_header(f"Welcome, {username}!")
        option = prompt_valid_option(user_menu_options)
        match option:
            case 1: add_password(uid)
            case 2: search_passwords(uid)
            case 3: list_passwords(uid)
            case 0: break
            case None: continue
            case _: invalid_option(option)

def registration_menu():
    print_header("REGISTER")
    username = prompt_username()
    password1 = prompt_password()
    password2 = prompt_password("Confirm password: ")
    if password1 == password2:
        status = passman.create_user(username=username, password=password1)
        match status:
            case RegStatus.FAIL: print_error("Registration failed!")
            case RegStatus.TAKEN: print_error("Username is taken!")
            case RegStatus.SUCCESS: print("\nRegistration successful!")
    else: print_error("Passwords don't match!")
    press_enter_to_continue()

# Main menu
def main_menu():
    main_menu_options = [
        "Login",
        "Register"
    ]
    while True:
        print_header()
        option = prompt_valid_option(main_menu_options)
        match option:
            case 1: user_menu()
            case 2: registration_menu()
            case 0: kys()
            case None: continue
            case _: invalid_option(option)

def main():
    LOG_PATH = "PassManTUI.log"
    logging.basicConfig(
        filename=LOG_PATH,
        filemode="a",
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.INFO
    )
    logging.info("========== Starting PassManTUI ==========")
    
    try:
        global passman
        passman = PassMan()
        passman.init_db()
        main_menu()
    except KeyboardInterrupt: kys()
    except EOFError: kys()
    except Exception as e:
        logging.error(f"TUI: Unexpected error! ({e})")
        kys(1)

if __name__ == "__main__":
    main()
