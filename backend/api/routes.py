from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from constants import RSPAMD_RULES
from core.analyzer import analyze_email, scan_all_emails
from core.feed_utils import get_brand_allowlist, load_text_feed
from core.imap_client import fetch_emails, fetch_emails_by_exact_targets
from core.login_storage import clear_saved_login, load_saved_login, save_login

router = APIRouter(prefix="/api", tags=["api"])


class AnalyzeEmailRequest(BaseModel):
    email: Dict[str, Any]
    enable_online_checks: bool = True


class FetchImapRequest(BaseModel):
    email: str
    app_password: str
    mailbox_label: str = "Hộp thư đến (INBOX)"
    limit: int = Field(default=15, ge=1, le=100)
    remember_login: bool = False


class BatchScanRequest(BaseModel):
    email: str
    app_password: str
    mailbox_label: str = "Hộp thư đến (INBOX)"
    limit: int = Field(default=15, ge=1, le=100)
    enable_online_checks: bool = True
    remember_login: bool = False


class ExactScanTarget(BaseModel):
    row_index: Optional[int] = None
    subject: str = ""
    sender: str = ""
    gmail_msgid: str = ""
    gmail_thrid: str = ""


class ExactTargetScanRequest(BatchScanRequest):
    targets: List[ExactScanTarget] = Field(default_factory=list)
    strict_exact: bool = True


@router.get("/health")
def health():
    return {"ok": True, "service": "phishing-backend"}


@router.get("/rules")
def get_rules():
    return {"count": len(RSPAMD_RULES), "rules": RSPAMD_RULES}


@router.get("/brand-allowlist")
def brand_allowlist():
    return get_brand_allowlist()


@router.get("/saved-login")
def get_saved_login():
    return load_saved_login()


@router.delete("/saved-login")
def delete_saved_login():
    clear_saved_login()
    return {"ok": True, "message": "Đã xóa đăng nhập đã lưu."}


@router.post("/fetch-imap-emails")
def fetch_imap_emails(payload: FetchImapRequest):
    emails, message = fetch_emails(
        payload.email,
        payload.app_password,
        payload.mailbox_label,
        payload.limit,
    )

    if payload.remember_login and emails:
        save_login(
            payload.email,
            payload.app_password,
            payload.mailbox_label,
            payload.limit,
        )

    return {
        "ok": bool(emails),
        "message": message,
        "count": len(emails),
        "emails": emails,
    }


@router.post("/analyze-email")
def analyze_email_route(payload: AnalyzeEmailRequest):
    score, label, issues, evidence = analyze_email(
        payload.email,
        enable_online_checks=payload.enable_online_checks,
    )
    return {
        "score": score,
        "label": label,
        "issues": issues,
        "evidence": evidence,
    }


@router.post("/scan-imap-batch")
def scan_imap_batch(payload: BatchScanRequest):
    emails, message = fetch_emails(
        payload.email,
        payload.app_password,
        payload.mailbox_label,
        payload.limit,
    )

    if payload.remember_login and emails:
        save_login(
            payload.email,
            payload.app_password,
            payload.mailbox_label,
            payload.limit,
        )

    if not emails:
        return {
            "ok": False,
            "message": message,
            "count": 0,
            "emails": [],
            "rows": [],
        }

    df = scan_all_emails(emails, enable_online_checks=payload.enable_online_checks)

    return {
        "ok": True,
        "message": message,
        "count": len(emails),
        "exact_mode": False,
        "emails": emails,
        "rows": df.to_dict(orient="records"),
    }


@router.post("/scan-imap-targets")
def scan_imap_targets(payload: ExactTargetScanRequest):
    emails, message, exact_meta = fetch_emails_by_exact_targets(
        payload.email,
        payload.app_password,
        payload.mailbox_label,
        [target.dict() for target in payload.targets[: payload.limit]],
        strict_exact=payload.strict_exact,
    )

    if payload.remember_login and emails:
        save_login(
            payload.email,
            payload.app_password,
            payload.mailbox_label,
            payload.limit,
        )

    if not emails:
        return {
            "ok": False,
            "message": message,
            "count": 0,
            "exact_mode": True,
            "exact_meta": exact_meta,
            "emails": [],
            "rows": [],
        }

    df = scan_all_emails(emails, enable_online_checks=payload.enable_online_checks)

    return {
        "ok": True,
        "message": message,
        "count": len(emails),
        "exact_mode": True,
        "exact_meta": exact_meta,
        "emails": emails,
        "rows": df.to_dict(orient="records"),
    }