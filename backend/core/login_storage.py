import os
import sqlite3
from typing import Optional

from config import DB_PATH, KEY_PATH

try:
    from cryptography.fernet import Fernet
except Exception:
    Fernet = None


def get_cipher():
    if Fernet is None:
        return None

    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
        try:
            os.chmod(KEY_PATH, 0o600)
        except Exception:
            pass

    key = KEY_PATH.read_bytes().strip()
    return Fernet(key)


def init_login_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS remembered_login (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            email TEXT,
            password_encrypted BLOB,
            mailbox_label TEXT,
            mail_limit INTEGER,
            updated_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_login(email_value: str, password_value: str, mailbox_label: str, mail_limit: int):
    cipher = get_cipher()
    encrypted = None
    if cipher and password_value:
        encrypted = cipher.encrypt(password_value.encode("utf-8"))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO remembered_login (id, email, password_encrypted, mailbox_label, mail_limit, updated_at)
        VALUES (1, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            email=excluded.email,
            password_encrypted=excluded.password_encrypted,
            mailbox_label=excluded.mailbox_label,
            mail_limit=excluded.mail_limit,
            updated_at=excluded.updated_at
        """,
        (email_value, encrypted, mailbox_label, mail_limit),
    )
    conn.commit()
    conn.close()


def load_saved_login() -> Optional[dict]:
    if not DB_PATH.exists():
        return None

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT email, password_encrypted, mailbox_label, mail_limit, updated_at "
        "FROM remembered_login WHERE id = 1"
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    email_value, encrypted, mailbox_label, mail_limit, updated_at = row
    password_value = ""
    cipher = get_cipher()

    if encrypted and cipher:
        try:
            password_value = cipher.decrypt(encrypted).decode("utf-8")
        except Exception:
            password_value = ""

    return {
        "email": email_value or "",
        "password": password_value,
        "mailbox_label": mailbox_label or "Hộp thư đến (INBOX)",
        "mail_limit": int(mail_limit or 15),
        "updated_at": updated_at,
    }


def clear_saved_login():
    if not DB_PATH.exists():
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM remembered_login WHERE id = 1")
    conn.commit()
    conn.close()


init_login_db()