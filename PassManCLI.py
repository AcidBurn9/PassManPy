import os
import sqlite3
import getpass
import pyperclip
from typing import Tuple
import PassManLib as passman

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def printHeader(str = ""):
    clear()
    print(f"=== PassMan CLI ===\n")
    if str != "": print(f"{str}\n")

def pressEnterToContinue():
    input("\nPress ENTER to continue")

def kys(code=0):
    printHeader()
    print("Exiting!")
    pressEnterToContinue()
    clear()
    exit(code)

def printError(error):
    print(f"\nERROR: {error}")

def invalidOption(option):
    printError(f"[{option}] is not a valid option!")
    pressEnterToContinue()

def promptUsername() -> str:
    username = input("Username: ")
    return username

def promptPassword(prompt="Password: ") -> str:
    password = getpass.getpass(prompt)
    return password

def promptValidOption(options) -> int | None:
    n = len(options)

    for i in range(0, n):
        print(f"{i+1}: {options[i]}")
    print("\n0: Exit")
    option = input(f"Select an option (0-{n}): ").strip()

    if option == "": return None
    try: option = int(option)
    except:
        invalidOption(option)
        return None

    if option >= 0 and option < (n + 1): return option
    else:
        invalidOption(option)
        return None

# Password menu options
def copyPassword(pid):
    password = promptPassword("Master password: ")
    plaintext = passman.decrypt_password(pid=pid, password=password)
    password = None # wiping from memory as soon as not needed
    if plaintext is None:
        printError("Could not retrieve the password")
        pressEnterToContinue()
        return

    printHeader()
    pyperclip.copy(plaintext)
    plaintext = None # wiping from memory as soon as not needed
    print("Copied to the clipboard!")
    pressEnterToContinue()

def showPassword(pid, label, login):
    password = promptPassword("Master password: ")
    plaintext = passman.decrypt_password(pid=pid, password=password)
    password = None # wiping from memory as soon as not needed
    if plaintext is None:
        printError("Could not retrieve the password")
        pressEnterToContinue()
        return

    padding = ""
    for i in range(0, len(plaintext)): padding = padding + "="

    printHeader(f"[{label}] {login}")
    print(f"{padding}\n{plaintext}\n{padding}")
    pressEnterToContinue()
    clear()

def updatePassword(pid, label, login):
    password = promptPassword("Master password: ")

    printHeader(f"[{label}] {login}")

    newPassword = promptPassword("New password: ")
    if passman.update_password(pid=pid, password=password, new_password=newPassword): print("\nSuccess!")
    else: printError("Failed to update the password!")
    password = None # wiping from memory as soon as not needed
    pressEnterToContinue()
    clear()

def deletePassword(pid) -> bool:
    password = promptPassword("Master password: ")
    if passman.delete_password(pid=pid, password=password):
        print("\nSuccess!")
        pressEnterToContinue()
        return True
    else:
        printError("Failed to delete the password!")
        pressEnterToContinue()
        return False

def passwordMenu(pid, label, login):
    passwordOptions = [
        "Copy password",
        "Show password",
        "Update password",
        "Delete password"
    ]
    while True:
        printHeader()
        print(f"[{label}] {login}\n")
        option = promptValidOption(passwordOptions)
        match option:
            case 1: copyPassword(pid)
            case 2: showPassword(pid, label, login)
            case 3: updatePassword(pid, label, login)
            case 4:
                if deletePassword(pid): break
                else: continue
            case 0: break
            case None: continue
            case _: invalidOption(option)

# User menu options
def addPassword(uid: int):
    printHeader("Add password")
    label = input("Label: ")
    login = input("Login: ")
    password = promptPassword()

    if passman.add_password(uid=uid, label=label, login=login, password=password): print("\nSuccess!")
    else: printError("Failed to add password!")

    pressEnterToContinue()

def showPasswords(uid: int, filter=""):
    printHeader()
    if filter!="": print(f"Search: {filter}")
    entries = passman.get_passwords(uid=uid)

    if not entries:
        print("No passwords.")
        pressEnterToContinue()
        return

    pids = []
    labels = []
    logins = []
    options = []
    for pid, label, login in entries:
        if filter in label or filter in login:
            pids.append(pid)
            labels.append(label)
            logins.append(login)
            options.append(f"[{label}] {login}")

    if not pids:
        print("No passwords.")
        pressEnterToContinue()
        return

    i = promptValidOption(options)
    if i == 0 or i is None: return
    else: i = i - 1
    pid = pids[i]
    passwordMenu(pid, labels[i], logins[i])

def searchPasswords(uid: int):
    printHeader()
    filter = input("Search passwords: ")
    showPasswords(uid, filter)

# Main menu options
def loginMenu() -> Tuple[str, str] | Tuple[str, None]:
    printHeader("LOGIN")
    username = promptUsername()
    password = promptPassword()
    return username, passman.auth_user(username=username, password=password)

def userMenu():
    username, uid = loginMenu()
    if uid is None:
        print("\nAuthentication failed!")
        pressEnterToContinue()
        return

    userMenuOptions = [
        "Add password",
        "Search passwords",
        "List all passwords"
    ]
    while True:
        printHeader(f"Welcome, {username}!")
        option = promptValidOption(userMenuOptions)
        match option:
            case 1: addPassword(uid)
            case 2: searchPasswords(uid)
            case 3: showPasswords(uid)
            case 0: break
            case None: continue
            case _: invalidOption(option)

def registrationMenu():
    printHeader("REGISTER")
    username = promptUsername()
    password1 = promptPassword()
    password2 = promptPassword("Confirm password: ")
    if password1 == password2:
        status = passman.create_user(username=username, password=password1)
        match status:
            case passman.Reg_Status.FAIL: printError("Registration failed!")
            case passman.Reg_Status.TAKEN: printError("Username is taken!")
            case passman.Reg_Status.SUCCESS: print("\nRegistration successful!")
    else: printError("Passwords don't match!")
    pressEnterToContinue()

# Main menu
def mainMenu():
    mainMenuOptions = [
        "Login",
        "Register"
    ]
    while True:
        printHeader()
        option = promptValidOption(mainMenuOptions)
        match option:
            case 1: userMenu()
            case 2: registrationMenu()
            case 0: kys()
            case None: continue
            case _: invalidOption(option)

def main():
    try:
        passman.init_db()
        mainMenu()
    except KeyboardInterrupt: kys()
    except EOFError: kys()
    except sqlite3.OperationalError as e:
        passman.logging.error(f"Database connection failure ({e})")
        pressEnterToContinue()
        kys(1)

if __name__ == "__main__":
    main()
