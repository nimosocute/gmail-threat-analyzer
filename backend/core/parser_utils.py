import re
import unicodedata
from html import unescape
from html.parser import HTMLParser
from typing import Dict, List, Tuple

from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime

from constants import EMAIL_RE, RTL_OVERRIDE_RE, ZERO_WIDTH_RE


class LinkHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.interactive_urls: List[str] = []
        self.technical_urls: List[str] = []
        self.anchor_pairs: List[Tuple[str, str]] = []
        self.base_href: str = ""
        self._current_anchor_href = None
        self._current_anchor_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        from core.url_utils import clean_url_candidate

        tag_name = (tag or "").lower()
        attr_map = {str(k).lower(): v for k, v in attrs if k}

        if tag_name == "base":
            href_val = attr_map.get("href")
            if href_val and not self.base_href:
                self.base_href = clean_url_candidate(href_val)
            return

        if tag_name in {"a", "area"}:
            href = attr_map.get("href")
            if href:
                self.interactive_urls.append(href)
            if tag_name == "a":
                self._current_anchor_href = href
                self._current_anchor_text = []
            return

        if tag_name == "form":
            action = attr_map.get("action")
            if action:
                self.interactive_urls.append(action)
            return

        if tag_name == "link":
            href = attr_map.get("href")
            if href:
                self.technical_urls.append(href)
            return

        for attr_name in ("src", "poster", "background"):
            value = attr_map.get(attr_name)
            if value:
                self.technical_urls.append(value)

    def handle_data(self, data):
        if self._current_anchor_href is not None and data:
            self._current_anchor_text.append(data)

    def handle_endtag(self, tag):
        if (tag or "").lower() == "a" and self._current_anchor_href is not None:
            visible = re.sub(r"\s+", " ", " ".join(self._current_anchor_text)).strip()
            self.anchor_pairs.append((self._current_anchor_href, visible))
            self._current_anchor_href = None
            self._current_anchor_text = []


def decode_mime_words(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        try:
            decoded_words = decode_header(value)
            out = []
            for word, encoding in decoded_words:
                if isinstance(word, bytes):
                    out.append(word.decode(encoding or "utf-8", errors="replace"))
                else:
                    out.append(str(word))
            return "".join(out)
        except Exception:
            return str(value)


def decode_part(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            content = part.get_payload()
            return content if isinstance(content, str) else ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_bodies(msg) -> Tuple[str, str]:
    plain_parts: List[str] = []
    html_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = (part.get_content_disposition() or "").lower()
            if disposition == "attachment":
                continue
            ctype = part.get_content_type().lower()
            text = decode_part(part).strip()
            if not text:
                continue
            if ctype == "text/plain":
                plain_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        ctype = msg.get_content_type().lower()
        text = decode_part(msg).strip()
        if ctype == "text/html":
            html_parts.append(text)
        else:
            plain_parts.append(text)

    return "\n\n".join(plain_parts), "\n\n".join(html_parts)


def strip_html_to_text(html_body: str) -> str:
    html = html_body or ""
    if not html:
        return ""

    html = re.sub(r"(?is)<!--.*?-->", " ", html)
    html = re.sub(
        r"(?is)<(script|style|svg|head|title|meta|link|noscript|template)\b.*?>.*?</\1>",
        " ",
        html,
    )
    html = re.sub(r"(?is)<br\s*/?>", "\n", html)
    html = re.sub(r"(?is)</(p|div|li|tr|table|section|article|h[1-6])>", "\n", html)
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def collapse_soft_linebreaks(text: str) -> str:
    if not text:
        return ""
    text = text.replace("=\r\n", "")
    text = text.replace("=\n", "")
    text = text.replace("\r", " ")
    text = text.replace("\n", " ")
    text = text.replace("\t", " ")
    return re.sub(r"\s+", " ", text).strip()


def extract_sender_claim_surface(sender_header: str) -> str:
    header = decode_mime_words(sender_header or "")
    header = unescape(header)
    actual_email = get_email_address(header)

    visible = header
    if actual_email:
        visible = re.sub(re.escape(actual_email), " ", visible, flags=re.IGNORECASE)

    visible = visible.replace("<", " ").replace(">", " ")
    visible = collapse_soft_linebreaks(visible)
    return visible


def normalize_brand_text(text: str) -> str:
    text = decode_mime_words(text or "")
    text = unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    text = RTL_OVERRIDE_RE.sub(" ", text)

    raw = collapse_soft_linebreaks(text).lower()
    flat = re.sub(r"[\[\]\(\)\{\}<>\"'`|,:;=/\\]+", " ", raw)
    flat = flat.replace("_", " ").replace("-", " ")
    flat = re.sub(r"\s+", " ", flat).strip()

    return f"{raw}\n{flat}"


def extract_emails_from_header(header_value: str) -> List[str]:
    header = str(header_value or "").strip()
    emails = EMAIL_RE.findall(header)
    deduped = []
    seen = set()
    for e in emails:
        e = e.lower()
        if e not in seen:
            seen.add(e)
            deduped.append(e)
    return deduped


def get_email_address(header_value: str) -> str:
    header = str(header_value or "").strip()
    _, email_addr = parseaddr(header)
    email_addr = (email_addr or "").strip().lower()
    if email_addr:
        return email_addr
    emails = extract_emails_from_header(header)
    if emails:
        return emails[-1]
    return ""


def get_domain_from_email_header(header_value: str) -> str:
    email_addr = get_email_address(header_value)
    if "@" not in email_addr:
        return ""
    return email_addr.split("@", 1)[1].lower()


def format_date(date_header: str) -> str:
    try:
        return parsedate_to_datetime(date_header).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return date_header or ""


def get_received_headers(msg) -> List[str]:
    return [str(v) for v in msg.get_all("Received", [])]