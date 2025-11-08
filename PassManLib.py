import sqlite3
import secrets
from typing import Tuple, List
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes

from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag

# Database
DB_PATH = "vault.db"
_DB_TABLE_USERS = """
    CREATE TABLE IF NOT EXISTS users (
        uid INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        pubkey BLOB NOT NULL,
        vault_salt BLOB NOT NULL
    );
    """
_DB_TABLE_PASSWORDS = """
    CREATE TABLE IF NOT EXISTS passwords (
        pid INTEGER PRIMARY KEY AUTOINCREMENT,
        uid INTEGER NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
        label TEXT NOT NULL,
        login TEXT NOT NULL,
        password BLOB NOT NULL,
        nonce BLOB NOT NULL,
        eph_pub BLOB NOT NULL
    );
    """

def _get_db_connection() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON;")
    return db

def init_db():
    with _get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(_DB_TABLE_USERS)
        cursor.execute(_DB_TABLE_PASSWORDS)

        db.commit()


# Master password
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=4,
        memory_cost=2**16,
    )
    key = bytearray(kdf.derive(password.encode()))
    key[0]  &= 248
    key[31] &= 127
    key[31] |= 64
    return bytes(key)

def _hash_pass(password: str) -> bytes:
    ph = PasswordHasher(
        memory_cost=2**15,
        time_cost=4,
        parallelism=4,
        hash_len=32
    )
    return ph.hash(password.encode())


# Users
def create_user(username: str, password: str) -> bool:
    try:
        salt = secrets.token_bytes(16)
        priv_bytes = _derive_key(password, salt)
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub = priv.public_key()
        priv = None # wiping from memory as soon as not needed

        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, pubkey, vault_salt) VALUES (?, ?, ?, ?)",
                (username, _hash_pass(password), pub.public_bytes_raw(), salt),
            )
            db.commit()

        return True
    except Exception as e:
        print(f"Failed to create user: {e}")
        return False

def auth_user(username: str, password: str) -> int | None:
    with _get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uid, password_hash FROM users WHERE username=?", (username,))
        row = cursor.fetchone()

    if not row: return None
    uid, passhash = row

    ph = PasswordHasher(
        memory_cost=2**15,
        time_cost=4,
        parallelism=4,
        hash_len=32
    )

    try:
        ph.verify(passhash, password)
        return uid
    except VerifyMismatchError: return None

def _get_user_pub(uid: int) -> X25519PublicKey:
    with _get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT pubkey FROM users WHERE uid=?", (uid,))
        row = cursor.fetchone()

    if not row: raise ValueError(f"User with uid {uid} not found")

    pub_bytes = row[0]
    pub = X25519PublicKey.from_public_bytes(pub_bytes)

    return pub


# Password storage
def _encrypt_password(pub: X25519PublicKey, plaintext: bytes, label: str, login: str) -> Tuple[bytes, bytes, bytes]:
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()

    shared = eph_priv.exchange(pub)

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-ecies")
    key = hkdf.derive(shared)

    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    aad = (label + "\n" + login).encode()
    ciphertext = aead.encrypt(nonce, plaintext, aad)

    return ciphertext, nonce, eph_pub.public_bytes_raw()

def _get_password_data(pid: int) -> tuple[str, str, bytes, bytes, bytes, str, bytes]:
    with _get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT p.label, p.login, p.password, p.nonce, p.eph_pub, u.username, u.vault_salt
            FROM passwords AS p
            JOIN users AS u ON p.uid = u.uid
            WHERE p.pid = ?
        """, (pid,))
        row = cursor.fetchone()

    if not row: raise ValueError(f"Password entry with pid {pid} not found")

    label, login, ciphertext, nonce, eph_pub_bytes, username, salt = row

    return label, login, ciphertext, nonce, eph_pub_bytes, username, salt

def _decrypt_password(pid: int, password: str) -> bytes | None:
    try:
        label, login, ciphertext, nonce, eph_pub_bytes, username, salt = _get_password_data(pid)
    except: return None

    if not auth_user(username, password): return None

    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)

    priv_bytes = _derive_key(password, salt)
    password = None # wiping from memory as soon as not needed
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    priv_bytes = None # wiping from memory as soon as not needed

    shared = priv.exchange(eph_pub)
    priv = None # wiping from memory as soon as not needed

    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-ecies").derive(shared)

    aead = ChaCha20Poly1305(key)
    aad = (label + "\n" + login).encode()
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        return None

def get_password_plaintext(pid: int, password: str) -> str | None:
    try:
        plaintext = _decrypt_password(pid, password).decode()
        return plaintext
    except UnicodeDecodeError as e:
        return None

def add_password(uid: int, label: str, login: str, password: str) -> bool:
    try:
        pub = _get_user_pub(uid)
        ct, nonce, eph_pub = _encrypt_password(pub, password.encode(), label, login)
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO passwords (uid, label, login, password, nonce, eph_pub) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, label, login, ct, nonce, eph_pub)
            )
            db.commit()
        return True
    except Exception as e:
        print(f"Failed to add password: {e}")
        return False

def delete_password(pid: int, password: str) -> bool:
    with _get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT u.username FROM passwords AS p JOIN users AS u ON p.uid = u.uid WHERE p.pid = ?", (pid,))
        row = cursor.fetchone()
    if not row: return False
    username = row[0]
    uid = auth_user(username, password)
    if not uid: return False

    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM passwords WHERE pid=? AND uid=? ", (pid, uid))
            db.commit()
        return True
    except Exception as e:
        print(f"Failed to delete password: {e}")
        return False

def update_password(pid: int, password: str, new_password: str) -> bool:
    label, login, _, _, _, username, _ = _get_password_data(pid)
    uid = auth_user(username, password)
    if not uid: return False
    try:
        pub = _get_user_pub(uid)
        ct, nonce, eph_pub = _encrypt_password(pub, new_password.encode(), label, login)

        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("UPDATE passwords SET password = ?, nonce = ?, eph_pub = ? WHERE pid = ? AND uid = ?", (ct, nonce, eph_pub, pid, uid))
            db.commit()
        return True
    except: return False

def get_passwords(uid: int) -> List[Tuple[int, str, str]]:
    with _get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT pid, label, login FROM passwords WHERE uid=?", (uid,))
        rows = cursor.fetchall()

    results = []
    for pid, label, login in rows:
        results.append((pid, label, login))
    return results
