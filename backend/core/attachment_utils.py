from typing import Dict, List

from constants import DANGEROUS_EXTENSIONS


def inspect_pdf_bytes(payload: bytes) -> Dict:
    info = {
        "is_pdf": False,
        "encrypted": False,
        "javascript": False,
        "suspicious": False,
        "size": len(payload or b""),
    }
    if not payload:
        return info

    head = payload[:2048]
    if b"%PDF" in head:
        info["is_pdf"] = True

    low = payload[:50000].lower()
    if b"/encrypt" in low:
        info["encrypted"] = True
    if b"/javascript" in low or b"/js" in low:
        info["javascript"] = True
    if b"/openaction" in low or b"/launch" in low or b"/submitform" in low:
        info["suspicious"] = True
    if info["encrypted"] or info["javascript"]:
        info["suspicious"] = True

    return info


def extract_attachments_meta(msg) -> List[Dict]:
    from core.parser_utils import decode_mime_words

    files = []
    for part in msg.walk():
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            name = decode_mime_words(filename or "attachment")
            payload = b""
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            ctype = (part.get_content_type() or "").lower()
            lower_name = name.lower()

            pdf_flags = (
                inspect_pdf_bytes(payload)
                if lower_name.endswith(".pdf") or ctype == "application/pdf"
                else {
                    "is_pdf": False,
                    "encrypted": False,
                    "javascript": False,
                    "suspicious": False,
                    "size": len(payload or b""),
                }
            )

            files.append(
                {
                    "filename": name,
                    "content_type": ctype,
                    "size": len(payload or b""),
                    "pdf": pdf_flags,
                }
            )
    return files


def has_dangerous_attachment(attachments: List[str]) -> List[str]:
    bad = []
    for filename in attachments:
        lowered = filename.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if lowered.endswith(ext):
                bad.append(filename)
                break
    return bad


def attachment_looks_phishy(filename: str) -> bool:
    name = (filename or "").lower()
    suspicious_words = [
        "invoice", "payment", "statement", "account", "secure", "document",
        "login", "password", "verify", "fax", "scan", "voicemail", "bill",
        "portal", "approval", "contract", "quotation"
    ]
    suspicious_exts = (
        ".html", ".htm", ".zip", ".rar", ".7z",
        ".docm", ".xlsm", ".pptm", ".js", ".vbs", ".lnk", ".iso", ".img", ".pdf"
    )
    return any(w in name for w in suspicious_words) and name.endswith(suspicious_exts)