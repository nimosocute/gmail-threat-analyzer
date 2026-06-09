from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RuleHit:
    rule: str
    delta: float
    reason: str
    support: str
    description: str
    details: Optional[Any] = None


@dataclass
class AnalysisResult:
    score: int
    label: str
    issues: List[str]
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmailRecord:
    id: str
    fetch_order: int
    mailbox: str
    gmail_msgid: str
    gmail_thrid: str
    date: str
    date_raw: str
    subject: str
    sender: str
    sender_email: str
    sender_header: str
    reply_to: str
    reply_to_email: str
    to: str
    cc: str
    return_path: str
    body_text: str
    body_html: str
    body_preview: str
    attachments: List[str]
    attachment_meta: List[Dict[str, Any]]
    urls: List[str]
    anchor_pairs: List[Any]
    url_debug: Dict[str, List[str]]
    auth: Dict[str, str]
    headers_preview: str
    raw_size: int
    received_headers: List[str]
    