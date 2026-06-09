from typing import Dict, List

from core.url_utils import remove_urls_from_text


def detect_attack_types(score: int, evidence: Dict) -> List[str]:
    fired = {r["rule"] for r in evidence.get("fired_rules", [])}
    attack_types = []

    if {"META_CREDENTIAL_THEFT", "GOOGLE_DOCS_PHISH", "VISIBLE_TEXT_URL_MISMATCH", "FUZZY_HTML_PHISHING_MISMATCH"} & fired:
        attack_types.append("Credential Theft")
    if {"META_ATTACHMENT_TRAP", "PHISH_ATTACH", "MIME_BAD_EXTENSION", "PDF_SUSPICIOUS"} & fired:
        attack_types.append("Attachment Malware / Lure")
    if {"BRAND_IMPERSONATION", "SPOOF_DISPLAY_NAME", "META_BRAND_SPOOF_HIGH", "FREEMAIL_BRAND_ABUSE"} & fired:
        attack_types.append("Brand Spoof")
    if {"FROM_GOV_SPOOF", "META_GOV_SPOOF"} & fired:
        attack_types.append("Government Spoof")
    if {"LEAKED_PASSWORD_SCAM"} & fired:
        attack_types.append("Sextortion / BTC Scam")
    if {"META_QR_PHISH"} & fired:
        attack_types.append("QR Phishing")
    if {"META_BEC"} & fired:
        attack_types.append("BEC / Payment Fraud")
    if {"META_THREAD_HIJACK"} & fired:
        attack_types.append("Thread Hijack")
    if not attack_types and score >= 70:
        attack_types.append("Generic High-Risk Phishing")

    return attack_types


def likely_thread_hijack(subject: str, body_text: str, urls: List[str], attachments: List[str]) -> bool:
    subj = (subject or "").lower().strip()
    body = remove_urls_from_text(body_text or "").lower()
    return (
        (subj.startswith("re:") or subj.startswith("fwd:") or subj.startswith("fw:"))
        and len(body.split()) <= 15
        and (bool(urls) or bool(attachments))
    )