import imaplib
import re
from typing import Dict, List, Optional, Tuple

from email import policy
from email.parser import BytesParser

from config import MAILBOX_MAP
from core.attachment_utils import extract_attachments_meta
from core.auth_utils import auth_summary
from core.parser_utils import (
    decode_mime_words,
    extract_bodies,
    format_date,
    get_email_address,
    get_received_headers,
    strip_html_to_text,
)
from core.url_utils import extract_urls


_GMAIL_MSGID_RE = re.compile(rb"X-GM-MSGID\s+(\d+)", re.IGNORECASE)
_GMAIL_THRID_RE = re.compile(rb"X-GM-THRID\s+(\d+)", re.IGNORECASE)
_GMAIL_NUMERIC_ID_RE = re.compile(r"\d{15,}")
_GMAIL_ALL_MAIL = MAILBOX_MAP.get("Tất cả thư", "[Gmail]/All Mail")
_FETCH_UID_RE = re.compile(rb"UID\s+(\d+)", re.IGNORECASE)
_FETCH_CHUNK_SIZE = 10


def connect_imap(username: str, app_password: str):
    username = (username or "").strip()
    app_password = re.sub(r"\s+", "", app_password or "")
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        status, data = mail.login(username, app_password)
        if status != "OK":
            raise RuntimeError(f"Login không trả về OK: {data}")
        return mail, None
    except imaplib.IMAP4.error as e:
        return None, f"Gmail từ chối IMAP login: {e}"
    except Exception as e:
        return None, f"Lỗi kết nối tới imap.gmail.com: {e}"



def _extract_gmail_ids_from_fetch_meta(fetch_meta: bytes) -> Tuple[str, str]:
    if not fetch_meta:
        return "", ""

    gmail_msgid = ""
    gmail_thrid = ""

    try:
        msg_match = _GMAIL_MSGID_RE.search(fetch_meta)
        thr_match = _GMAIL_THRID_RE.search(fetch_meta)

        if msg_match:
            gmail_msgid = msg_match.group(1).decode("ascii", errors="ignore").strip()
        if thr_match:
            gmail_thrid = thr_match.group(1).decode("ascii", errors="ignore").strip()
    except Exception:
        return "", ""

    return gmail_msgid, gmail_thrid



def _safe_decode_imap_id(raw_id) -> str:
    if isinstance(raw_id, bytes):
        return raw_id.decode(errors="ignore")
    return str(raw_id or "")



def _normalize_gmail_numeric_id(value) -> str:
    raw = str(value or "").strip().strip("<>")
    if not raw:
        return ""

    match = _GMAIL_NUMERIC_ID_RE.search(raw)
    return match.group(0) if match else ""



def _folder_select_attempts(folder: str) -> List[str]:
    raw = str(folder or "").strip()
    if not raw:
        return []

    escaped = raw.replace("\\", "\\\\").replace('"', '\\"')
    quoted = f'"{escaped}"'
    attempts: List[str] = [quoted, raw] if (any(ch.isspace() for ch in raw) or raw.startswith("[")) else [raw, quoted]

    dedup: List[str] = []
    seen = set()
    for item in attempts:
        if item not in seen:
            seen.add(item)
            dedup.append(item)
    return dedup



def _select_folder(mail, folder: str) -> Tuple[bool, str]:
    last_error = ""
    for candidate in _folder_select_attempts(folder):
        try:
            status, data = mail.select(candidate, readonly=True)
            if status == "OK":
                return True, ""
            last_error = f"Đăng nhập thành công nhưng không mở được mailbox '{folder}': {data}"
        except Exception as e:
            last_error = f"Đăng nhập thành công nhưng không mở được mailbox '{folder}': {e}"
    return False, last_error or f"Đăng nhập thành công nhưng không mở được mailbox '{folder}'."



def _extract_fetch_parts(msg_data) -> Tuple[bytes, bytes]:
    if not msg_data:
        return b"", b""

    for part in msg_data:
        if not isinstance(part, tuple) or len(part) < 2:
            continue

        fetch_meta = part[0] if isinstance(part[0], (bytes, bytearray)) else b""
        raw_email = part[1] if isinstance(part[1], (bytes, bytearray)) else b""

        if raw_email:
            return bytes(fetch_meta), bytes(raw_email)

    return b"", b""



def _extract_multi_fetch_parts(msg_data) -> List[Tuple[str, bytes, bytes]]:
    results: List[Tuple[str, bytes, bytes]] = []
    if not msg_data:
        return results

    for part in msg_data:
        if not isinstance(part, tuple) or len(part) < 2:
            continue

        fetch_meta = part[0] if isinstance(part[0], (bytes, bytearray)) else b""
        raw_email = part[1] if isinstance(part[1], (bytes, bytearray)) else b""
        if not fetch_meta or not raw_email:
            continue

        uid = ""
        try:
            uid_match = _FETCH_UID_RE.search(fetch_meta)
            if uid_match:
                uid = uid_match.group(1).decode("ascii", errors="ignore").strip()
        except Exception:
            uid = ""

        if uid:
            results.append((uid, bytes(fetch_meta), bytes(raw_email)))

    return results



def _build_email_record(raw_id, fetch_order: int, folder: str, fetch_meta: bytes, raw_email: bytes, extra: Optional[Dict] = None) -> Dict:
    gmail_msgid, gmail_thrid = _extract_gmail_ids_from_fetch_meta(fetch_meta)
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    subject = decode_mime_words(msg.get("Subject", "(Không có tiêu đề)"))
    sender = decode_mime_words(msg.get("From", "(Không rõ người gửi)"))
    reply_to = decode_mime_words(msg.get("Reply-To", ""))
    to_header = decode_mime_words(msg.get("To", ""))
    cc_header = decode_mime_words(msg.get("Cc", ""))
    return_path = decode_mime_words(msg.get("Return-Path", ""))
    sender_header_raw = decode_mime_words(msg.get("Sender", ""))
    date_header = msg.get("Date", "")

    text_body, html_body = extract_bodies(msg)
    attachment_meta = extract_attachments_meta(msg)
    attachments = [a["filename"] for a in attachment_meta]
    urls, anchor_pairs, url_debug = extract_urls(text_body, html_body)
    auth = auth_summary(msg)
    received_headers = get_received_headers(msg)

    headers_preview = "\n".join(
        [
            f"From: {msg.get('From', '')}",
            f"Sender: {msg.get('Sender', '')}",
            f"Reply-To: {msg.get('Reply-To', '')}",
            f"To: {msg.get('To', '')}",
            f"Cc: {msg.get('Cc', '')}",
            f"Return-Path: {msg.get('Return-Path', '')}",
            f"Received-SPF: {msg.get('Received-SPF', '')}",
            f"Authentication-Results: {' | '.join(msg.get_all('Authentication-Results', []))}",
            f"Subject: {msg.get('Subject', '')}",
            f"Date: {msg.get('Date', '')}",
            f"X-GM-MSGID: {gmail_msgid}",
            f"X-GM-THRID: {gmail_thrid}",
        ] + [f"Received[{i+1}]: {rh}" for i, rh in enumerate(received_headers[:6])]
    )

    email_record = {
        "id": _safe_decode_imap_id(raw_id),
        "fetch_order": fetch_order,
        "mailbox": folder,
        "date": format_date(date_header),
        "date_raw": date_header,
        "subject": subject,
        "sender": sender,
        "sender_email": get_email_address(sender),
        "sender_header": sender_header_raw,
        "reply_to": reply_to,
        "reply_to_email": get_email_address(reply_to),
        "to": to_header,
        "cc": cc_header,
        "return_path": return_path,
        "gmail_msgid": gmail_msgid,
        "gmail_thrid": gmail_thrid,
        "body_text": text_body,
        "body_html": html_body,
        "body_preview": text_body if text_body else strip_html_to_text(html_body),
        "attachments": attachments,
        "attachment_meta": attachment_meta,
        "urls": urls,
        "anchor_pairs": anchor_pairs,
        "url_debug": url_debug,
        "auth": auth,
        "headers_preview": headers_preview,
        "raw_size": len(raw_email),
        "received_headers": received_headers,
    }

    if extra:
        email_record.update(extra)

    return email_record



def _parse_uid_search_data(data) -> List[str]:
    uids: List[str] = []
    for part in data or []:
        if isinstance(part, bytes):
            tokens = part.decode(errors="ignore").strip().split()
        else:
            tokens = str(part or "").strip().split()

        for token in tokens:
            clean = token.strip()
            if clean:
                uids.append(clean)

    return uids



def _uid_search(mail, *criteria: str) -> List[str]:
    try:
        status, data = mail.uid("SEARCH", None, *criteria)
    except Exception:
        return []
    if status != "OK":
        return []
    return _parse_uid_search_data(data)



def fetch_emails(username: str, app_password: str, mailbox_label: str, limit: int) -> Tuple[List[Dict], str]:
    folder = MAILBOX_MAP.get(mailbox_label, "INBOX")
    emails_list: List[Dict] = []

    mail, err = connect_imap(username, app_password)
    if err:
        return [], err

    try:
        ok, select_err = _select_folder(mail, folder)
        if not ok:
            return [], select_err

        status, messages = mail.search(None, "ALL")
        if status != "OK":
            return [], f"Đăng nhập được nhưng không đọc được danh sách mail: {messages}"

        email_ids = messages[0].split()
        if not email_ids:
            return [], f"Mailbox '{folder}' hiện rỗng."

        latest_ids = email_ids[-limit:]
        latest_ids.reverse()

        for fetch_order, e_id in enumerate(latest_ids):
            status, msg_data = mail.fetch(e_id, "(BODY.PEEK[] X-GM-MSGID X-GM-THRID)")
            if status != "OK":
                continue

            fetch_meta, raw_email = _extract_fetch_parts(msg_data)
            if not raw_email:
                continue

            emails_list.append(
                _build_email_record(
                    raw_id=e_id,
                    fetch_order=fetch_order,
                    folder=folder,
                    fetch_meta=fetch_meta,
                    raw_email=raw_email,
                )
            )

        return emails_list, f"Đã tải {len(emails_list)} email từ {folder}"

    except Exception as e:
        return [], f"Lỗi sau khi đăng nhập IMAP: {e}"

    finally:
        try:
            mail.logout()
        except Exception:
            pass



def _chunked(values: List[str], size: int) -> List[List[str]]:
    return [values[i:i + size] for i in range(0, len(values), size)]



def fetch_emails_by_exact_targets(
    username: str,
    app_password: str,
    mailbox_label: str,
    targets: List[Dict],
    strict_exact: bool = True,
) -> Tuple[List[Dict], str, Dict]:
    primary_folder = MAILBOX_MAP.get(mailbox_label, "INBOX")
    requested_targets = list(targets or [])

    meta: Dict = {
        "requested_total": len(requested_targets),
        "matched_total": 0,
        "unmatched_total": 0,
        "primary_folder": primary_folder,
        "fallback_folder": _GMAIL_ALL_MAIL if primary_folder != _GMAIL_ALL_MAIL else "",
        "strict_exact": bool(strict_exact),
        "search_stats": {
            "matched_by_msgid": 0,
            "matched_by_thrid": 0,
            "searched_all_mail_fallback": 0,
            "folders_selected": 0,
            "fetch_batches": 0,
        },
        "unmatched_targets": [],
    }

    mail, err = connect_imap(username, app_password)
    if err:
        return [], err, meta

    selected_folder: Optional[str] = None
    msgid_search_cache: Dict[Tuple[str, str], List[str]] = {}
    thrid_search_cache: Dict[Tuple[str, str], List[str]] = {}
    fetched_cache: Dict[Tuple[str, str], Dict] = {}

    def ensure_selected(folder: str) -> Tuple[bool, str]:
        nonlocal selected_folder
        current_state = str(getattr(mail, "state", "") or "").upper()
        if selected_folder == folder and current_state == "SELECTED":
            return True, ""

        ok, select_err = _select_folder(mail, folder)
        if ok:
            selected_folder = folder
            meta["search_stats"]["folders_selected"] += 1
            return True, ""

        selected_folder = None
        return False, select_err

    def search_folder(folder: str, pending_indexes: List[int], folder_index: int) -> None:
        if not pending_indexes:
            return
        ok, _ = ensure_selected(folder)
        if not ok:
            return

        unmatched_after_msgid: List[int] = []
        for idx in pending_indexes:
            target = normalized_targets[idx]
            requested_msgid = target["requested_msgid"]
            if not requested_msgid:
                unmatched_after_msgid.append(idx)
                continue

            cache_key = (folder, requested_msgid)
            uids = msgid_search_cache.get(cache_key)
            if uids is None:
                uids = _uid_search(mail, "X-GM-MSGID", requested_msgid)
                msgid_search_cache[cache_key] = uids

            if uids:
                matched_targets[idx] = {
                    "uid": uids[-1],
                    "folder": folder,
                    "matched_by": "gmail_msgid",
                }
                if folder_index > 0:
                    meta["search_stats"]["searched_all_mail_fallback"] += 1
            else:
                unmatched_after_msgid.append(idx)

        for idx in unmatched_after_msgid:
            if matched_targets[idx] is not None:
                continue
            target = normalized_targets[idx]
            requested_thrid = target["requested_thrid"]
            if not requested_thrid:
                continue

            cache_key = (folder, requested_thrid)
            uids = thrid_search_cache.get(cache_key)
            if uids is None:
                uids = _uid_search(mail, "X-GM-THRID", requested_thrid)
                thrid_search_cache[cache_key] = uids

            if uids:
                matched_targets[idx] = {
                    "uid": uids[-1],
                    "folder": folder,
                    "matched_by": "gmail_thrid",
                }
                if folder_index > 0:
                    meta["search_stats"]["searched_all_mail_fallback"] += 1

    try:
        normalized_targets: List[Dict] = []
        for out_index, target in enumerate(requested_targets):
            requested_msgid = _normalize_gmail_numeric_id(target.get("gmail_msgid", ""))
            requested_thrid = _normalize_gmail_numeric_id(target.get("gmail_thrid", ""))
            normalized_targets.append(
                {
                    "out_index": out_index,
                    "row_index": target.get("row_index"),
                    "row_subject": str(target.get("subject", "") or ""),
                    "row_sender": str(target.get("sender", "") or ""),
                    "requested_msgid": requested_msgid,
                    "requested_thrid": requested_thrid,
                }
            )

        matched_targets: List[Optional[Dict]] = [None] * len(normalized_targets)
        pending_indexes: List[int] = []
        for idx, target in enumerate(normalized_targets):
            if target["requested_msgid"] or target["requested_thrid"]:
                pending_indexes.append(idx)
            else:
                meta["unmatched_targets"].append(
                    {
                        "row_index": target["row_index"],
                        "subject": target["row_subject"],
                        "sender": target["row_sender"],
                        "gmail_msgid": "",
                        "gmail_thrid": "",
                        "reason": "missing_exact_ids",
                    }
                )

        search_folder(primary_folder, pending_indexes, 0)

        if primary_folder != _GMAIL_ALL_MAIL:
            remaining = [idx for idx in pending_indexes if matched_targets[idx] is None]
            if remaining:
                search_folder(_GMAIL_ALL_MAIL, remaining, 1)

        fetch_plan: Dict[str, List[str]] = {}
        for info in matched_targets:
            if not info:
                continue
            fetch_plan.setdefault(info["folder"], []).append(info["uid"])

        for folder, uids in fetch_plan.items():
            ok, _ = ensure_selected(folder)
            if not ok:
                continue

            dedup_uids: List[str] = []
            seen = set()
            for uid in uids:
                if uid and uid not in seen:
                    seen.add(uid)
                    dedup_uids.append(uid)

            for uid_chunk in _chunked(dedup_uids, _FETCH_CHUNK_SIZE):
                uid_set = ",".join(uid_chunk)
                status, msg_data = mail.uid("FETCH", uid_set, "(UID BODY.PEEK[] X-GM-MSGID X-GM-THRID)")
                if status != "OK":
                    continue

                meta["search_stats"]["fetch_batches"] += 1
                for uid, fetch_meta, raw_email in _extract_multi_fetch_parts(msg_data):
                    fetched_cache[(folder, uid)] = _build_email_record(
                        raw_id=uid,
                        fetch_order=0,
                        folder=folder,
                        fetch_meta=fetch_meta,
                        raw_email=raw_email,
                    )

        emails_list: List[Dict] = []
        for idx, target in enumerate(normalized_targets):
            match_info = matched_targets[idx]
            if not match_info:
                meta["unmatched_targets"].append(
                    {
                        "row_index": target["row_index"],
                        "subject": target["row_subject"],
                        "sender": target["row_sender"],
                        "gmail_msgid": target["requested_msgid"],
                        "gmail_thrid": target["requested_thrid"],
                        "reason": "not_found_in_selected_mailboxes",
                    }
                )
                continue

            fetch_cache_key = (match_info["folder"], match_info["uid"])
            base_email = fetched_cache.get(fetch_cache_key)
            if not base_email:
                meta["unmatched_targets"].append(
                    {
                        "row_index": target["row_index"],
                        "subject": target["row_subject"],
                        "sender": target["row_sender"],
                        "gmail_msgid": target["requested_msgid"],
                        "gmail_thrid": target["requested_thrid"],
                        "reason": f"empty_fetch:{match_info['uid']}",
                    }
                )
                continue

            output_email = dict(base_email)
            output_email.update(
                {
                    "fetch_order": target["out_index"],
                    "target_row_index": target["row_index"],
                    "target_subject": target["row_subject"],
                    "target_sender": target["row_sender"],
                    "requested_gmail_msgid": target["requested_msgid"],
                    "requested_gmail_thrid": target["requested_thrid"],
                    "matched_by": match_info["matched_by"],
                    "resolved_mailbox": match_info["folder"],
                }
            )
            emails_list.append(output_email)

            if match_info["matched_by"] == "gmail_msgid":
                meta["search_stats"]["matched_by_msgid"] += 1
            elif match_info["matched_by"] == "gmail_thrid":
                meta["search_stats"]["matched_by_thrid"] += 1

        meta["matched_total"] = len(emails_list)
        meta["unmatched_total"] = len(meta["unmatched_targets"])

        if emails_list:
            return emails_list, f"Đã scan exact {len(emails_list)}/{len(requested_targets)} mail theo Gmail IDs từ UI", meta

        return [], "Không tìm thấy mail nào khớp exact Gmail IDs từ UI", meta

    except Exception as e:
        return [], f"Lỗi exact scan sau khi đăng nhập IMAP: {e}", meta

    finally:
        try:
            mail.logout()
        except Exception:
            pass
