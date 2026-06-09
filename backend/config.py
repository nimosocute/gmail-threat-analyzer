from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Lưu mọi file trực tiếp trong thư mục backend
APP_DIR = BASE_DIR

FEED_DIR = BASE_DIR
TRUSTLIST_DIR = BASE_DIR

DB_PATH = BASE_DIR / "saved_login.db"
KEY_PATH = BASE_DIR / "saved_login.key"
BRAND_ALLOWLIST_PATH = BASE_DIR / "brand_allowlist.csv"

ONLINE_LOOKUP_TIMEOUT = 4

MAILBOX_MAP = {
    "Hộp thư đến (INBOX)": "INBOX",
    "Spam": "[Gmail]/Spam",
    "Tất cả thư": "[Gmail]/All Mail",
}