import sqlite3
import secrets
import logging
from enum import Enum
from typing import Tuple, List
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes

from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag


# Logging
LOG_PATH = "PassManPy.log"
logging.basicConfig(
    filename=LOG_PATH,
    filemode="a",
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)
logging.info("========== Starting PassManPy ==========")


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
    logging.info(f"Initialising the database: {DB_PATH}")
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()

            cursor.execute(_DB_TABLE_USERS)
            cursor.execute(_DB_TABLE_PASSWORDS)

            db.commit()
    except Exception as e: logging.error(f"Failed to initialise the database: {DB_PATH}! ({e})")


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
class Reg_Status(Enum):
    FAIL = 0
    TAKEN = 1
    SUCCESS = 2
def create_user(username: str, password: str) -> Reg_Status:
    logging.debug(f"NEW_USER attempt for username={username}")
    salt = secrets.token_bytes(16)
    priv_bytes = _derive_key(password, salt)
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = priv.public_key()
    priv = None # wiping from memory as soon as not needed

    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, pubkey, vault_salt) VALUES (?, ?, ?, ?)",
                (username, _hash_pass(password), pub.public_bytes_raw(), salt),
            )
            db.commit()
            uid = cursor.lastrowid
            logging.info(f"Successful NEW_USER with username={username} and uid={uid}")
        return Reg_Status.SUCCESS
    except sqlite3.IntegrityError as e:
        logging.warning(f"Failed NEW_USER for username={username} (already exists)")
        return Reg_Status.TAKEN
    except Exception as e:
        logging.error(f"Failed NEW_USER for username={username}! ({e})")
        return Reg_Status.FAIL

def auth_user(username: str, password: str) -> int | None:
    logging.debug(f"AUTH attempt for username={username}")
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT uid, password_hash FROM users WHERE username=?", (username,))
            row = cursor.fetchone()
    except Exception as e:
        logging.error(f"Failed AUTH for username={username}! ({e})")
        return None

    if not row:
        logging.warning(f"Failed AUTH for username={username} (does not exist)")
        return None
    uid, passhash = row

    ph = PasswordHasher(
        memory_cost=2**15,
        time_cost=4,
        parallelism=4,
        hash_len=32
    )

    try:
        ph.verify(passhash, password)
        logging.info(f"Successful AUTH for uid={uid}")
        return uid
    except VerifyMismatchError:
        logging.warning(f"Failed AUTH for uid={uid}")
        return None
    except Exception as e:
        logging.error(f"Failed AUTH for uid={uid}! ({e})")
        return None

def _get_user_pub(uid: int) -> X25519PublicKey | None:
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT pubkey FROM users WHERE uid=?", (uid,))
            row = cursor.fetchone()
    except Exception as e:
        logging.error(f"Failed to retrieve pub for uid={uid}! ({e})")
        return None

    if not row:
        logging.warning(f"Failed to retrieve pub for uid={uid} (does not exist)")
        return None

    pub_bytes = row[0]
    pub = X25519PublicKey.from_public_bytes(pub_bytes)

    return pub


# Password storage
def _encrypt_password(pub: X25519PublicKey, plaintext: str, label: str, login: str) -> Tuple[bytes, bytes, bytes]:
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()

    shared = eph_priv.exchange(pub)

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-ecies")
    key = hkdf.derive(shared)

    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    aad = (label + "\n" + login)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), aad.encode())

    return ciphertext, nonce, eph_pub.public_bytes_raw()

def _get_password_data(pid: int) -> tuple[str, str, bytes, bytes, bytes, str, bytes] | None:
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT p.label, p.login, p.password, p.nonce, p.eph_pub, u.username, u.vault_salt
                FROM passwords AS p
                JOIN users AS u ON p.uid = u.uid
                WHERE p.pid = ?
            """, (pid,))
            row = cursor.fetchone()
        if not row: return None

        label, login, ciphertext, nonce, eph_pub_bytes, username, salt = row

        return label, login, ciphertext, nonce, eph_pub_bytes, username, salt
    except Exception as e:
        logging.error(f"Failed GET for pid={pid}! ({e})")
        return None

def decrypt_password(pid: int, password: str) -> str | None:
    logging.debug(f"Password DECRYPT attempt for pid={pid}")
    password_data = _get_password_data(pid)
    if password_data is None:
        logging.warning(f"Failed DECRYPT for pid={pid} (does not exist)")
        return None
    label, login, ciphertext, nonce, eph_pub_bytes, username, salt = password_data

    uid = auth_user(username, password)
    if not uid:
        logging.warning(f"Failed DECRYPT for pid={pid} (bad auth)")
        return None

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
        decrypted = aead.decrypt(nonce, ciphertext, aad)
        logging.info(f"Successful DECRYPT for pid={pid} by uid={uid}")
        return decrypted.decode()
    except (InvalidTag, TypeError):
        logging.error(f"Failed DECRYPT for pid={pid} by uid={uid}! (corrupted data)")
        return None
    except UnicodeDecodeError:
        logging.error(f"Failed DECRYPT for pid={pid} by uid={uid}! (unicode decode error)")
        return None
    except Exception as e:
        logging.error(f"Failed DECRYPT for pid={pid} by uid={uid}! ({e})")
        return None

def add_password(uid: int, label: str, login: str, password: str) -> bool:
    logging.debug(f"Password ADD attempt by uid={uid}")
    pub = _get_user_pub(uid)
    if pub is None:
        logging.warning(f"Failed ADD by uid={uid} (no public key)")
        return False
    ct, nonce, eph_pub = _encrypt_password(pub, password, label, login)
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO passwords (uid, label, login, password, nonce, eph_pub) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, label, login, ct, nonce, eph_pub)
            )
            db.commit()
            pid = cursor.lastrowid
            logging.info(f"Successful ADD by uid={uid} (pid={pid})")
        return True
    except Exception as e:
        logging.error(f"Failed ADD by uid={uid}! ({e})")
        return False

def delete_password(pid: int, password: str) -> bool:
    logging.debug(f"Password DELETE attempt for pid={pid}")
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT u.username FROM passwords AS p JOIN users AS u ON p.uid = u.uid WHERE p.pid = ?", (pid,))
            row = cursor.fetchone()
    except Exception as e:
        logging.error(f"Failed DELETE for pid={pid}! ({e})")
        return False

    if not row:
        logging.warning(f"Failed DELETE for pid={pid} (does not exist)")
        return False

    username = row[0]
    uid = auth_user(username, password)
    if not uid:
        logging.warning(f"Failed DELETE of pid={pid} (bad auth)")
        return False

    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM passwords WHERE pid=? AND uid=? ", (pid, uid))
            db.commit()
        logging.info(f"Successful DELETE of pid={pid} by uid={uid}")
        return True
    except Exception as e:
        logging.error(f"Failed DELETE of pid={pid} by uid={uid}! ({e})")
        return False

def update_password(pid: int, password: str, new_password: str) -> bool:
    logging.debug(f"Password UPDATE attempt for pid={pid}")
    password_data = _get_password_data(pid)
    if password_data is None:
        logging.warning(f"Failed UPDATE for pid={pid} (does not exist)")
        return False
    label, login, _, _, _, username, _ = password_data

    uid = auth_user(username, password)
    if not uid:
        logging.warning(f"Failed UPDATE of pid={pid} (bad auth)")
        return False

    pub = _get_user_pub(uid)
    if pub is None:
        logging.warning(f"Failed UPDATE for pid={pid} (no public key)")
        return False
    ct, nonce, eph_pub = _encrypt_password(pub, new_password, label, login)
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("UPDATE passwords SET password = ?, nonce = ?, eph_pub = ? WHERE pid = ? AND uid = ?", (ct, nonce, eph_pub, pid, uid))
            db.commit()
        logging.info(f"Successful UPDATE of pid={pid} by uid={uid}")
        return True
    except Exception as e:
        logging.error(f"Failed UPDATE of pid={pid} by uid={uid}! ({e})")
        return False

def get_passwords(uid: int) -> List[Tuple[int, str, str]]:
    logging.info(f"Fetching passwords with uid={uid}")
    results = []
    try:
        with _get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT pid, label, login FROM passwords WHERE uid=?", (uid,))
            results = cursor.fetchall()
    except Exception as e:
        logging.error(f"Failed to fetch passwords with uid={uid}! ({e})")

    return results
