import re

from config import FEED_DIR


URGENT_KEYWORDS = [
    "khẩn cấp", "khóa tài khoản", "xác minh ngay", "hạn cuối", "tạm ngưng",
    "bất thường", "ngay lập tức", "cập nhật thông tin", "đóng học phí",
    "verify now", "urgent", "immediately", "account suspended", "final notice",
    "payment overdue", "confirm now", "security alert", "login attempt",
    "unusual activity", "unauthorized", "suspended", "violation", "act now"
]

EMOTION_KEYWORDS = [
    "sợ", "lo", "hoảng", "khẩn", "ngay", "bị khóa", "mất quyền truy cập",
    "you are hacked", "compromised", "urgent", "security alert", "unauthorized",
    "final notice", "suspended", "violation", "warning", "alert"
]

LEAKED_PASSWORD_HINTS = [
    "i know your password", "i recorded you", "bitcoin", "btc", "wallet",
    "send payment", "webcam", "i have access to your device", "i will leak",
    "your password is", "i know that"
]

QR_PHISH_HINTS = [
    "scan qr", "qr code", "quét mã", "scan the code", "scan to view",
    "scan to login", "scan to verify", "scan to sign in"
]

BEC_HINTS = [
    "wire transfer", "bank account changed", "change bank details", "payment details updated",
    "urgent payment", "process payment", "thanh toán vào tài khoản mới", "đổi tài khoản ngân hàng",
    "chuyển khoản gấp"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "cutt.ly",
    "is.gd", "rebrand.ly", "buff.ly", "tiny.cc", "tiny.one", "lnkd.in"
}

REDIRECTOR_DOMAINS = {
    "google.com", "www.google.com", "l.facebook.com", "lm.facebook.com",
    "www.youtube.com", "youtube.com", "linkedin.com", "www.linkedin.com",
    "slack-redir.net", "nam12.safelinks.protection.outlook.com",
    "eur03.safelinks.protection.outlook.com", "urldefense.com", "proofpoint.com"
}

ANON_DOMAIN_HINTS = {
    "trycloudflare.com", "workers.dev", "ngrok-free.app", "ngrok.io",
    "duckdns.org", "serveo.net", "onion", "ipfs.io", "cloudfront.net", "pages.dev"
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "gq", "cf", "tk", "ml", "ga", "pw", "rest", "fit",
    "mom", "buzz", "cam", "monster", "cfd", "bar", "quest", "xin", "work",
    "zip", "mov", "country", "kim"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi",
    ".html", ".htm", ".zip", ".rar", ".7z", ".iso", ".img", ".docm", ".xlsm",
    ".pptm", ".lnk", ".ace", ".arj"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}

BRAND_DOMAIN_MAP = {
    "google": {"google.com", "accounts.google.com", "myaccount.google.com", "notifications.google.com", "security.google.com", "googleusercontent.com", "gstatic.com", "googleapis.com"},
    "gmail": {"gmail.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"},
    "office 365": {"office.com", "outlook.com", "microsoft.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com", "paypalobjects.com"},
    "facebook": {"facebook.com", "meta.com", "facebookmail.com", "fbcdn.net", "facebook.net"},
    "instagram": {"instagram.com", "facebook.com", "meta.com", "fbcdn.net"},
    "amazon": {"amazon.com", "amazon.co.jp", "amazon.com.au"},
    "docusign": {"docusign.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "onedrive": {"onedrive.live.com", "sharepoint.com", "office.com", "live.com"},
    "vietcombank": {"vietcombank.com.vn"},
    "mb bank": {"mbbank.com.vn", "mbbank.com"},
    "momo": {"momo.vn"},
    "fpt": {"fpt.edu.vn", "fe.edu.vn", "fap.fpt.edu.vn"},
    "dvsv": {"fpt.edu.vn", "fe.edu.vn", "fap.fpt.edu.vn"},
}

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "aol.com", "proton.me", "protonmail.com", "zoho.com"
}


GENERIC_REPLYTO_TITLES_OK = {
    "noreply", "no-reply", "no reply", "notification", "notifications",
    "support", "security", "facebook", "google"
}

TRUSTED_BRAND_FAMILIES = {
    "google": {
        "google.com", "accounts.google.com", "myaccount.google.com", "notifications.google.com",
        "security.google.com", "gaia.bounces.google.com", "gstatic.com", "googleusercontent.com",
        "googleapis.com"
    },
    "gmail": {"gmail.com", "mail.google.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com", "fbcdn.net", "facebook.net"},
    "instagram": {"instagram.com", "facebook.com", "meta.com", "fbcdn.net"},
    "paypal": {"paypal.com", "paypalobjects.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com", "sharepoint.com"},
    "outlook": {"outlook.com", "live.com", "office.com"},
    "fpt": {"fpt.edu.vn", "fe.edu.vn", "fap.fpt.edu.vn"},
    "dvsv": {"fpt.edu.vn", "fe.edu.vn", "fap.fpt.edu.vn"},
}

PAYPAL_DOMAINS = {"paypal.com", "paypalobjects.com"}

GOOGLE_TRUSTED_DOMAINS = {
    "google.com", "docs.google.com", "drive.google.com", "accounts.google.com",
    "myaccount.google.com", "notifications.google.com", "security.google.com",
    "mail.google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "forms.gle"
}

LOGINISH_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "update", "confirm", "secure", "security", "password", "reset",
    "billing", "invoice", "payment", "suspended", "unlock", "validate",
    "account", "webscr", "recover", "authenticate", "portal", "token",
    "reauth", "session", "credential", "approval", "authentication"
]

HTTP_URL_RE = re.compile(r"\bhttps?://[^\s<>'\"\]\)\}]+", re.IGNORECASE)
WWW_URL_RE = re.compile(r"(?<!@)\bwww\.[^\s<>'\"\]\)\}]+", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"(?<!@)\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})(?:/[^\s<>'\"]*)?",
    re.IGNORECASE,
)
ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
RTL_OVERRIDE_RE = re.compile(r"[\u202e\u202d\u202b\u202a\u2066\u2067\u2068\u2069]")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.IGNORECASE)

FEED_FILES = {
    "openphish": FEED_DIR / "openphish.txt",
    "phishtank": FEED_DIR / "phishtank.txt",
    "dbl_phish": FEED_DIR / "dbl_phish.txt",
    "dbl_abuse_phish": FEED_DIR / "dbl_abuse_phish.txt",
    "uribl_black": FEED_DIR / "uribl_black.txt",
    "uribl_grey": FEED_DIR / "uribl_grey.txt",
    "spamhaus_drop": FEED_DIR / "spamhaus_drop.txt",
    "blocklistde": FEED_DIR / "blocklistde.txt",
    "phished_excluded": FEED_DIR / "phished_excluded.txt",
    "phished_whitelisted": FEED_DIR / "phished_whitelisted.txt",
}

DEFAULT_BRAND_ALLOWLIST_ROWS = [
    ["brand", "usage", "match_type", "value", "aliases"],

    ["google", "sender", "exact_domain", "accounts.google.com", "google|gmail"],
    ["google", "sender", "exact_email", "no-reply@accounts.google.com", "google|gmail"],
    ["google", "link", "domain", "google.com", "google|gmail"],
    ["google", "link", "domain", "accounts.google.com", "google|gmail"],
    ["google", "link", "domain", "myaccount.google.com", "google|gmail|myaccount"],
    ["google", "link", "domain", "notifications.google.com", "google|gmail|myaccount"],
    ["google", "link", "domain", "security.google.com", "google|gmail|myaccount"],
    ["google", "link", "domain", "googleusercontent.com", "google|gmail"],
    ["google", "link", "domain", "gstatic.com", "google|gmail"],

    ["gmail", "link", "domain", "gmail.com", "gmail|google mail"],

    ["microsoft", "link", "domain", "microsoft.com", "microsoft|ms"],
    ["microsoft", "link", "domain", "microsoftonline.com", "microsoft|office 365|m365"],
    ["microsoft", "link", "domain", "office.com", "microsoft|office 365|m365"],

    ["outlook", "link", "domain", "outlook.com", "outlook|microsoft"],
    ["outlook", "link", "domain", "live.com", "outlook|hotmail|microsoft"],

    ["facebook", "sender", "exact_domain", "facebookmail.com", "facebook|meta"],
    ["facebook", "link", "domain", "facebook.com", "facebook|meta"],
    ["facebook", "link", "domain", "meta.com", "facebook|meta"],
    ["facebook", "link", "domain", "fbcdn.net", "facebook|meta"],

    ["instagram", "link", "domain", "instagram.com", "instagram|insta"],
    ["instagram", "link", "domain", "facebook.com", "instagram|insta|meta"],
    ["instagram", "link", "domain", "fbcdn.net", "instagram|insta|meta"],

    ["paypal", "sender", "exact_domain", "paypal.com", "paypal"],
    ["paypal", "link", "domain", "paypal.com", "paypal"],
    ["paypal", "link", "domain", "paypalobjects.com", "paypal"],

    ["apple", "sender", "exact_domain", "apple.com", "apple|icloud"],
    ["apple", "link", "domain", "apple.com", "apple|icloud"],
    ["apple", "link", "domain", "icloud.com", "apple|icloud"],

    ["dropbox", "sender", "exact_domain", "dropbox.com", "dropbox"],
    ["dropbox", "link", "domain", "dropbox.com", "dropbox"],

    ["docusign", "sender", "exact_domain", "docusign.com", "docusign|docu sign"],
    ["docusign", "link", "domain", "docusign.com", "docusign|docu sign"],

    ["adobe", "sender", "exact_domain", "adobe.com", "adobe|acrobat"],
    ["adobe", "link", "domain", "adobe.com", "adobe|acrobat"],

    ["onedrive", "sender", "exact_domain", "sharepoint.com", "onedrive|sharepoint|microsoft"],
    ["onedrive", "link", "domain", "sharepoint.com", "onedrive|sharepoint|microsoft"],
    ["onedrive", "link", "domain", "onedrive.live.com", "onedrive|sharepoint|microsoft"],

    ["fpt", "sender", "exact_domain", "fpt.edu.vn", "fpt"],
    ["fpt", "sender", "exact_domain", "fe.edu.vn", "fpt|fe"],
    ["fpt", "link", "domain", "fpt.edu.vn", "fpt"],
    ["fpt", "link", "domain", "fe.edu.vn", "fpt|fe"],
    ["fpt", "link", "domain", "fap.fpt.edu.vn", "fpt|fe|fap"],

    ["dvsv", "sender", "exact_domain", "fpt.edu.vn", "dvsv|fpt|phòng dịch vụ sinh viên|dịch vụ sinh viên"],
    ["dvsv", "sender", "exact_domain", "fe.edu.vn", "dvsv|fpt|phòng dịch vụ sinh viên|dịch vụ sinh viên"],
    ["dvsv", "link", "domain", "fpt.edu.vn", "dvsv|fpt|phòng dịch vụ sinh viên|dịch vụ sinh viên"],
    ["dvsv", "link", "domain", "fe.edu.vn", "dvsv|fpt|phòng dịch vụ sinh viên|dịch vụ sinh viên"],
    ["dvsv", "link", "domain", "fap.fpt.edu.vn", "dvsv|fpt|phòng dịch vụ sinh viên|dịch vụ sinh viên|fap"],
]

RULE_CATALOG = {
    "HEADER_FROM_DIFFERENT_DOMAINS": {"score": 5.2, "support": "legacy", "description": "From hiển thị và domain liên quan không đồng nhất"},
    "FROM_MISSP_REPLYTO": {"score": 5.0, "support": "legacy", "description": "Reply-To khác domain From"},
    "REPLYTO_WITHOUT_TO_CC": {"score": 2.2, "support": "legacy", "description": "Có Reply-To nhưng To/Cc trống hoặc bất thường"},
    "SPF_FAIL": {"score": 3.8, "support": "legacy", "description": "SPF fail"},
    "SPF_SOFTFAIL": {"score": 2.0, "support": "legacy", "description": "SPF softfail"},
    "DKIM_INVALID": {"score": 3.8, "support": "legacy", "description": "DKIM invalid/fail"},
    "DKIM_VALID": {"score": -1.0, "support": "legacy", "description": "DKIM pass"},
    "DMARC_FAIL": {"score": 4.6, "support": "legacy", "description": "DMARC fail"},
    "DMARC_PASS": {"score": -1.8, "support": "legacy", "description": "DMARC pass"},
    "DMARC_MISSING": {"score": 1.2, "support": "legacy", "description": "Thiếu DMARC trong ngữ cảnh spoofing"},
    "BRAND_IMPERSONATION": {"score": 4.2, "support": "legacy", "description": "Tên người gửi gợi ý thương hiệu nhưng domain không khớp"},
    "SPOOFED_FREEMAIL": {"score": 3.5, "support": "legacy", "description": "Freemail sender có dấu hiệu giả mạo"},
    "FROM_PAYPAL_SPOOF": {"score": 4.2, "support": "legacy", "description": "Mail chủ đề PayPal nhưng sender/link không thuộc PayPal"},
    "PAYPAL_PHISH_06": {"score": 0.8, "support": "legacy", "description": "PayPal heuristic 06"},
    "PAYPAL_PHISH_07": {"score": 1.4, "support": "legacy", "description": "PayPal heuristic 07"},
    "FROM_GOV_SPOOF": {"score": 4.2, "support": "legacy", "description": "Mạo danh cơ quan nhà nước"},
    "SOCIAL_ENGINEERING_LANGUAGE": {"score": 1.2, "support": "legacy", "description": "Từ ngữ thúc ép / đe dọa"},
    "BODY_SINGLE_URI": {"score": 0.8, "support": "legacy", "description": "Body gần như xoay quanh 1 URL"},
    "BODY_URI_ONLY": {"score": 1.8, "support": "legacy", "description": "Body gần như chỉ chứa URL"},
    "URL_IP_LITERAL": {"score": 4.8, "support": "legacy", "description": "URL dùng IP trực tiếp"},
    "URI_HEX_IP": {"score": 5.2, "support": "legacy", "description": "URL dùng IP encode kiểu hex"},
    "SHORTENER_URL": {"score": 2.3, "support": "legacy", "description": "Dùng dịch vụ rút gọn link"},
    "PUNYCODE_URL": {"score": 3.0, "support": "legacy", "description": "Phát hiện punycode / IDN"},
    "WEIRD_LONG_DOMAIN": {"score": 1.8, "support": "legacy", "description": "Domain dài hoặc nhiều dấu gạch nối"},
    "GOOG_REDIR_FRAUD": {"score": 4.2, "support": "legacy", "description": "Lạm dụng Google redirect"},
    "URI_DOTCN_SPOOF": {"score": 2.5, "support": "legacy", "description": "Có URL .cn trong ngữ cảnh spoof/login"},
    "URI_PHISH": {"score": 2.8, "support": "legacy", "description": "URL có pattern phishing"},
    "VISIBLE_TEXT_URL_MISMATCH": {"score": 5.2, "support": "legacy", "description": "Text hiển thị của link không khớp domain thật"},
    "GOOGLE_DOCS_PHISH": {"score": 2.8, "support": "legacy", "description": "Google Docs/Drive theme đáng ngờ"},
    "FORM_FRAUD": {"score": 5.0, "support": "legacy", "description": "Email chứa HTML form/password field"},
    "PHISH_ATTACH": {"score": 5.0, "support": "legacy", "description": "Attachment nguy hiểm / giống mẫu phishing"},
    "URIBL_DBL_PHISH": {"score": 7.0, "support": "legacy", "description": "Domain/URL nằm trong DBL phishing"},
    "BAD_FROM_HEADER": {"score": 4.5, "support": "legacy", "description": "Header From parse lỗi hoặc bất thường"},

    "MIME_BAD_EXT_IN_OBFUSCATED_ARCHIVE": {"score": 8.0, "support": "native", "description": "Bad ext in obfuscated archive"},
    "LEAKED_PASSWORD_SCAM": {"score": 7.0, "support": "native", "description": "BTC wallet + scam patterns"},
    "VIOLATED_DIRECT_SPF": {"score": 3.5, "support": "partial", "description": "Received nghèo nàn và SPF lỗi"},
    "ABUSE_FROM_INJECTOR": {"score": 2.0, "support": "partial", "description": "Dấu hiệu account compromise / abuse"},
    "FREEMAIL_REPLYTO_NEQ_FROM": {"score": 2.0, "support": "native", "description": "Reply-To là freemail và lệch From"},
    "AUTH_NA": {"score": 1.0, "support": "native", "description": "Không thấy rõ auth"},
    "AUTH_NA_OR_FAIL": {"score": 1.4, "support": "native", "description": "Không có auth nào pass"},
    "PHISH_EMOTION": {"score": 0.6, "support": "native", "description": "Subject/body tạo cảm xúc mạnh"},
    "REDIRECTOR_URL_ONLY": {"score": 1.5, "support": "native", "description": "Nội dung gần như chỉ có redirector URL"},
    "SUSPICIOUS_URL_IN_SUSPICIOUS_MESSAGE": {"score": 2.0, "support": "native", "description": "Thông điệp đáng ngờ + URL đáng ngờ"},
    "HAS_ANON_DOMAIN": {"score": 1.5, "support": "native", "description": "Domain relay / concealment"},
    "SPOOF_DISPLAY_NAME": {"score": 4.6, "support": "native", "description": "Display name spoof thương hiệu"},
    "ZERO_WIDTH_SPACE_URL": {"score": 5.2, "support": "native", "description": "URL có zero-width space"},
    "SPOOF_REPLYTO": {"score": 4.0, "support": "native", "description": "Reply-To off-domain"},
    "FUZZY_HTML_PHISHING_MISMATCH": {"score": 4.2, "support": "partial", "description": "Mismatch visible URL / href"},
    "REPLYTO_EQ_TO_ADDR": {"score": 2.5, "support": "native", "description": "Reply-To trùng To"},
    "R_SUSPICIOUS_URL": {"score": 3.2, "support": "native", "description": "URL đáng ngờ"},
    "FROM_NEQ_DISPLAY_NAME": {"score": 3.0, "support": "native", "description": "Display name chứa email khác"},
    "GPT_PHISHING": {"score": 0.6, "support": "partial", "description": "Heuristic social engineering (gated)"},
    "REPLYTO_EMAIL_HAS_TITLE": {"score": 1.2, "support": "native", "description": "Reply-To có title"},
    "REPLYTO_UNPARSEABLE": {"score": 1.3, "support": "native", "description": "Reply-To parse lỗi"},
    "REPLYTO_DOM_NEQ_FROM_DOM": {"score": 0.0, "support": "native", "description": "Reply-To domain khác From domain"},
    "DBL_PHISH": {"score": 7.5, "support": "feed", "description": "Spamhaus DBL phish"},
    "PH_SURBL_MULTI": {"score": 7.5, "support": "feed", "description": "Bị nhiều feed phishing đánh dấu"},
    "URIBL_BLACK": {"score": 7.5, "support": "feed", "description": "URIBL black"},
    "PHISHED_OPENPHISH": {"score": 7.0, "support": "feed", "description": "Khớp OpenPhish"},
    "PHISHED_PHISHTANK": {"score": 7.0, "support": "feed", "description": "Khớp PhishTank"},
    "RBL_SPAMHAUS_DROP": {"score": 7.0, "support": "feed", "description": "Spamhaus DROP"},
    "R_MIXED_CHARSET_URL": {"score": 5.0, "support": "native", "description": "Mixed charset/script URL"},
    "URL_ZERO_WIDTH_SPACES": {"score": 5.0, "support": "native", "description": "URL chứa zero-width"},
    "DBL_ABUSE_PHISH": {"score": 6.5, "support": "feed", "description": "Abused legit phish"},
    "RECEIVED_SPAMHAUS_DROP": {"score": 6.0, "support": "feed", "description": "Received IP thuộc Spamhaus DROP"},
    "URL_RTL_OVERRIDE": {"score": 5.0, "support": "native", "description": "URL dùng RTL override"},
    "MIME_ARCHIVE_IN_ARCHIVE": {"score": 4.2, "support": "partial", "description": "Archive trong archive"},
    "MIME_EXE_IN_GEN_SPLIT_RAR": {"score": 5.0, "support": "partial", "description": "EXE trong split RAR"},
    "URL_HOMOGRAPH_ATTACK": {"score": 5.0, "support": "native", "description": "URL homograph"},
    "URL_USER_VERY_LONG": {"score": 4.0, "support": "native", "description": "User field URL rất dài"},
    "HACKED_WP_PHISHING": {"score": 4.0, "support": "native", "description": "Phish từ WordPress bị hack"},
    "HFILTER_HELO_BADIP": {"score": 3.5, "support": "partial", "description": "HELO dùng IP xấu"},
    "PDF_SUSPICIOUS": {"score": 4.0, "support": "native", "description": "PDF đáng ngờ"},
    "MIME_BAD_ATTACHMENT": {"score": 3.5, "support": "partial", "description": "MIME type attachment bất thường"},
    "ONCE_RECEIVED_STRICT": {"score": 3.2, "support": "native", "description": "Single Received đáng ngờ"},
    "PHISHING": {"score": 4.0, "support": "native", "description": "Generic phishing"},
    "RBL_BLOCKLISTDE": {"score": 4.0, "support": "feed", "description": "Blocklist.de"},
    "R_SPF_PLUSALL": {"score": 2.5, "support": "partial", "description": "SPF +all"},
    "URL_NUMERIC_IP_USER": {"score": 4.0, "support": "native", "description": "Numeric IP + user field"},
    "MIME_DOUBLE_BAD_EXTENSION": {"score": 4.0, "support": "native", "description": "Double extension cloaking"},
    "RECEIVED_BLOCKLISTDE": {"score": 3.0, "support": "feed", "description": "Received IP in Blocklist.de"},
    "URL_BAD_UNICODE": {"score": 3.0, "support": "native", "description": "Bad Unicode in URL"},
    "URL_MULTIPLE_AT_SIGNS": {"score": 3.0, "support": "native", "description": "Multiple @ in URL"},
    "URL_SUSPICIOUS_TLD": {"score": 3.0, "support": "native", "description": "Suspicious TLD"},
    "URL_USER_LONG": {"score": 2.5, "support": "native", "description": "Long user field"},
    "HFILTER_HOSTNAME_UNKNOWN": {"score": 2.2, "support": "partial", "description": "Unknown client hostname"},
    "HFILTER_URL_ONELINE": {"score": 0.8, "support": "native", "description": "One-line URL and little text"},
    "URIBL_GREY": {"score": 2.5, "support": "feed", "description": "URIBL grey"},
    "HFILTER_URL_ONLY": {"score": 1.0, "support": "native", "description": "URL only in body"},
    "DMARC_POLICY_REJECT": {"score": 0.0, "support": "partial", "description": "DMARC reject policy observed (informational)"},
    "HFILTER_HELO_NOT_FQDN": {"score": 2.0, "support": "partial", "description": "HELO not FQDN"},
    "MIME_BAD_EXTENSION": {"score": 3.5, "support": "native", "description": "Bad extension"},
    "MIME_BAD_UNICODE": {"score": 2.5, "support": "native", "description": "Filename with bad Unicode"},
    "MIME_ENCRYPTED_ARCHIVE": {"score": 2.5, "support": "native", "description": "Encrypted archive"},
    "MIME_OBFUSCATED_ARCHIVE": {"score": 2.8, "support": "native", "description": "Obfuscated archive"},
    "RDNS_NONE": {"score": 2.0, "support": "partial", "description": "No RDNS"},
    "URL_BACKSLASH_PATH": {"score": 2.0, "support": "native", "description": "Backslash in URL"},
    "URL_EXCESSIVE_DOTS": {"score": 2.0, "support": "native", "description": "Too many dots in hostname"},
    "URL_NO_TLD": {"score": 2.0, "support": "native", "description": "URL no TLD"},
    "URL_USER_PASSWORD": {"score": 2.0, "support": "native", "description": "URL contains user field"},
    "DMARC_POLICY_QUARANTINE": {"score": 0.0, "support": "partial", "description": "DMARC quarantine policy (informational)"},
    "URL_NUMERIC_IP": {"score": 2.6, "support": "native", "description": "Numeric IP URL"},
    "URL_VERY_LONG": {"score": 1.8, "support": "native", "description": "Very long URL"},
    "ARC_REJECT": {"score": 1.5, "support": "partial", "description": "ARC checks failed"},
    "R_DKIM_REJECT": {"score": 1.8, "support": "native", "description": "DKIM reject"},
    "R_SPF_FAIL": {"score": 1.8, "support": "native", "description": "SPF reject"},
    "URL_REDIRECTOR_NESTED": {"score": 2.2, "support": "native", "description": "Nested redirector"},
    "URL_NUMERIC_PRIVATE_IP": {"score": 1.0, "support": "native", "description": "Private IP URL"},
    "FORGED_SENDER": {"score": 2.2, "support": "native", "description": "Sender differs from related headers"},
    "PDF_ENCRYPTED": {"score": 0.8, "support": "native", "description": "PDF encrypted"},
    "DMARC_POLICY_SOFTFAIL": {"score": 0.8, "support": "native", "description": "DMARC softfail"},
    "PDF_JAVASCRIPT": {"score": 1.8, "support": "native", "description": "PDF has JavaScript"},
    "PHISHED_EXCLUDED": {"score": 0.0, "support": "feed", "description": "Excluded phished URL"},
    "PHISHED_WHITELISTED": {"score": -5.0, "support": "feed", "description": "Whitelist exception"},

    "TRUSTLIST_BRAND_DOMAIN_MATCH": {"score": -3.5, "support": "trust", "description": "Sender domain khớp trust list chính chủ"},
    "TRUSTLIST_CLICKDOMAIN_MATCH": {"score": -2.0, "support": "trust", "description": "Click domain khớp trust list chính chủ"},
    "TRUSTLIST_BRAND_DOMAIN_MISS": {"score": 4.2, "support": "trust", "description": "Claim brand nhưng sender domain lệch trust list"},
    "CLICK_DOMAIN_OFF_BRAND": {"score": 4.0, "support": "trust", "description": "Claim brand nhưng click domain lệch trust list"},
    "AUTH_ALIGNMENT_STRONG_PASS": {"score": -3.0, "support": "trust", "description": "SPF/DKIM/DMARC align mạnh"},
    "AUTH_ALIGNMENT_FAIL": {"score": 4.0, "support": "trust", "description": "Auth alignment fail"},
    "DNS_BRAND_NO_DMARC": {"score": 2.2, "support": "trust", "description": "Brand domain không có DMARC hoặc SPF yếu"},
    "RDAP_NEW_DOMAIN": {"score": 4.0, "support": "trust", "description": "Domain mới tạo"},
    "RDAP_RECENT_DOMAIN": {"score": 2.0, "support": "trust", "description": "Domain còn rất mới"},
    "RDAP_NO_DATA": {"score": 0.0, "support": "trust", "description": "Không lấy được dữ liệu RDAP (informational)"},
    "FREEMAIL_BRAND_ABUSE": {"score": 5.5, "support": "trust", "description": "Dùng freemail để giả thương hiệu/dịch vụ lớn"},

    "TRUSTED_BRAND_AUTH": {"score": -3.0, "support": "trust", "description": "Brand thật + auth tốt"},
    "META_CREDENTIAL_THEFT": {"score": 7.0, "support": "meta", "description": "Tổ hợp credential theft"},
    "META_BRAND_SPOOF_HIGH": {"score": 7.5, "support": "meta", "description": "Brand spoof mức cao"},
    "META_LINK_SWAP": {"score": 6.5, "support": "meta", "description": "Link swap / redirector / shortener"},
    "META_ATTACHMENT_TRAP": {"score": 7.0, "support": "meta", "description": "Attachment trap"},
    "META_GOV_SPOOF": {"score": 6.0, "support": "meta", "description": "Gov spoof mức cao"},
    "META_PDF_PHISH": {"score": 6.5, "support": "meta", "description": "PDF phishing"},
    "META_QR_PHISH": {"score": 6.0, "support": "meta", "description": "QR phishing"},
    "META_BEC": {"score": 5.5, "support": "meta", "description": "Business Email Compromise"},
    "META_THREAD_HIJACK": {"score": 4.5, "support": "meta", "description": "Thread hijack"},
}

RSPAMD_RULES = [
    {"symbol": k, "score": v["score"], "description": v["description"], "support": v["support"]}
    for k, v in RULE_CATALOG.items()
]