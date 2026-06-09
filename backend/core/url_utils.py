import ipaddress
import re
import unicodedata
from html import unescape
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from constants import (
    ANON_DOMAIN_HINTS,
    BARE_DOMAIN_RE,
    EMAIL_RE,
    GOOGLE_TRUSTED_DOMAINS,
    HTTP_URL_RE,
    RTL_OVERRIDE_RE,
    WWW_URL_RE,
    ZERO_WIDTH_RE,
)
from core.parser_utils import LinkHTMLParser, collapse_soft_linebreaks, strip_html_to_text

try:
    import tldextract  # type: ignore
except Exception:
    tldextract = None


COMMON_TWO_LABEL_SUFFIXES = {
    "ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp",
    "ac.kr", "co.kr", "go.kr", "ne.kr", "or.kr",
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk",
    "com.au", "edu.au", "gov.au", "net.au", "org.au",
    "com.vn", "edu.vn", "gov.vn", "net.vn", "org.vn",
}

LOW_RISK_ANCHOR_TEXT_HINTS = {
    "unsubscribe",
    "manage preferences",
    "manage preference",
    "manage settings",
    "email settings",
    "notification settings",
    "privacy",
    "privacy policy",
    "terms",
    "terms of service",
    "view in browser",
    "browser version",
    "web version",
    "subscription",
    "manage subscription",
}

LOW_RISK_URL_HINTS = (
    "unsubscribe",
    "optout",
    "opt-out",
    "manage-preferences",
    "manage_preferences",
    "email-settings",
    "notification-settings",
    "privacy",
    "terms",
    "view-in-browser",
    "view_in_browser",
)

ABSOLUTE_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", flags=re.IGNORECASE)
QUERY_ONLY_RE = re.compile(r"^[A-Za-z0-9._%+\-]+=[^/\s]+(?:&[A-Za-z0-9._%+\-]+=[^/\s]+)*$")
REDIRECT_PARAM_KEYS = ("url", "u", "q", "target", "dest", "destination", "redirect", "redirect_uri", "continue", "continue_url")


def _looks_absolute_url(raw_url: str) -> bool:
    return bool(ABSOLUTE_URL_RE.match(raw_url or ""))


def _looks_like_bare_host(raw_url: str) -> bool:
    token = (raw_url or "").strip().lower()
    if not token:
        return False
    if "/" in token or "?" in token or "#" in token or "=" in token or "&" in token:
        return False
    if token.startswith(("mailto:", "cid:", "data:", "javascript:", "vbscript:")):
        return False
    return bool(BARE_DOMAIN_RE.fullmatch(token))


def resolve_relative_url(raw_url: str, base_url: str = "") -> str:
    raw_url = unescape((raw_url or "").strip())
    if not raw_url:
        return ""

    raw_lower = raw_url.lower()
    if raw_lower.startswith(("mailto:", "cid:", "data:", "#")):
        return clean_url_candidate(raw_url)
    if raw_lower.startswith(("javascript:", "vbscript:")):
        return ""

    # protocol-relative URL: //example.com/path
    if raw_url.startswith("//"):
        return clean_url_candidate("https:" + raw_url)

    # nếu không có base thì bỏ các href tương đối / query-only kiểu rid=...,
    # nhưng vẫn giữ bare domain thật như fap.fpt.edu.vn
    if not base_url and not _looks_absolute_url(raw_url):
        if raw_url.startswith(("/", "./", "../", "?")):
            return ""
        if QUERY_ONLY_RE.fullmatch(raw_url):
            return ""
        if not _looks_like_bare_host(raw_url) and not raw_lower.startswith("www."):
            return ""

    try:
        if base_url and not _looks_absolute_url(raw_url):
            raw_url = urljoin(base_url, raw_url)
    except Exception:
        pass

    return clean_url_candidate(raw_url)





def _decoded_variants(value: str, max_rounds: int = 3) -> List[str]:
    out: List[str] = []
    current = value or ""
    for _ in range(max_rounds):
        if current not in out:
            out.append(current)
        nxt = unquote(current)
        if nxt == current:
            break
        current = nxt
    return out


def _extract_embedded_absolute_urls(raw_value: str) -> List[str]:
    candidates: List[str] = []

    for variant in _decoded_variants(raw_value):
        cleaned_variant = clean_url_candidate(variant)
        if cleaned_variant and _looks_absolute_url(cleaned_variant):
            candidates.append(cleaned_variant)

        for segment in (variant or "").split("/"):
            cleaned_segment = clean_url_candidate(segment)
            if cleaned_segment and _looks_absolute_url(cleaned_segment):
                candidates.append(cleaned_segment)

        m = re.search(r'https?://[^\s"\'<>]+', variant or "", flags=re.IGNORECASE)
        if m:
            cleaned_match = clean_url_candidate(m.group(0))
            if cleaned_match:
                candidates.append(cleaned_match)

    return _dedupe_urls(candidates)


def unwrap_redirect_url(url: str, depth: int = 0) -> str:
    cleaned = clean_url_candidate(url)
    if not cleaned or depth > 4:
        return cleaned

    try:
        parsed = urlsplit(cleaned)
    except Exception:
        return cleaned

    candidates: List[str] = []

    try:
        qs = parse_qs(parsed.query)
        for key in REDIRECT_PARAM_KEYS:
            for value in qs.get(key, []):
                candidates.extend(_extract_embedded_absolute_urls(value))
    except Exception:
        pass

    for raw_part in (parsed.path or "", parsed.fragment or ""):
        candidates.extend(_extract_embedded_absolute_urls(raw_part))

    candidates = _dedupe_urls(candidates)
    for candidate in candidates:
        if candidate and candidate != cleaned and hostname_from_url(candidate):
            return unwrap_redirect_url(candidate, depth + 1)

    return cleaned


def clean_url_candidate(url: str) -> str:
    url = unescape((url or "").strip())
    url = collapse_soft_linebreaks(url)
    url = url.strip(" \t\r\n\"'<>[](){}.,;!?")
    if ZERO_WIDTH_RE.search(url):
        url = ZERO_WIDTH_RE.sub("", url)
    if url.startswith("www."):
        url = "http://" + url
    return url



def maybe_normalize_domain_candidate(token: str) -> str:
    token = unescape((token or "").strip())
    token = collapse_soft_linebreaks(token)
    token = token.strip(" \t\r\n\"'<>[](){}.,;!?")
    token_lower = token.lower()
    if token_lower.startswith(("http://", "https://", "mailto:", "cid:", "data:", "javascript:", "vbscript:")):
        return ""
    if "@" in token_lower:
        return ""
    if any(ch in token_lower for ch in ("/", "?", "#", "&", "=")):
        return ""
    if not BARE_DOMAIN_RE.fullmatch(token_lower):
        return ""
    return "http://" + token_lower



def _canonical_url_key(url: str) -> str:
    cleaned = clean_url_candidate(url)
    if not cleaned:
        return ""

    lower = cleaned.lower()
    if lower.startswith(("mailto:", "cid:", "data:")):
        return lower

    try:
        parsed = urlsplit(cleaned)
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
            port = f":{parsed.port}" if parsed.port else ""
            return "|".join(
                [
                    parsed.hostname.lower(),
                    port,
                    parsed.path or "",
                    parsed.query or "",
                    parsed.fragment or "",
                ]
            )
    except Exception:
        pass

    return lower



def _url_preference_score(url: str) -> Tuple[int, int]:
    cleaned = clean_url_candidate(url)
    lower = cleaned.lower()
    if lower.startswith("https://"):
        return (3, len(cleaned))
    if lower.startswith("http://"):
        return (2, len(cleaned))
    return (1, len(cleaned))



def _dedupe_urls(items: List[str]) -> List[str]:
    best_by_key: Dict[str, str] = {}
    order: List[str] = []

    for item in items:
        cleaned = clean_url_candidate(item)
        if not cleaned:
            continue
        key = _canonical_url_key(cleaned)
        if not key:
            continue
        if key not in best_by_key:
            best_by_key[key] = cleaned
            order.append(key)
            continue
        if _url_preference_score(cleaned) > _url_preference_score(best_by_key[key]):
            best_by_key[key] = cleaned

    return [best_by_key[key] for key in order]



def is_low_risk_anchor(href: str, visible_text: str) -> bool:
    visible = collapse_soft_linebreaks(visible_text or "").lower()
    href_low = (href or "").lower()
    if visible in LOW_RISK_ANCHOR_TEXT_HINTS:
        return True
    if any(hint in visible for hint in LOW_RISK_ANCHOR_TEXT_HINTS):
        return True
    return any(hint in href_low for hint in LOW_RISK_URL_HINTS)



def parse_html_links(html_body: str) -> Tuple[List[str], List[str], List[str], List[Tuple[str, str]]]:
    if not html_body:
        return [], [], [], []

    parser = LinkHTMLParser()
    try:
        parser.feed(html_body)
        parser.close()
    except Exception:
        pass

    base_href = parser.base_href or ""

    interactive_urls: List[str] = []
    low_risk_urls: List[str] = []
    for raw_href, visible in parser.anchor_pairs:
        resolved_href = resolve_relative_url(raw_href, base_href)
        if not resolved_href:
            continue
        analysis_href = unwrap_redirect_url(resolved_href)
        if is_low_risk_anchor(analysis_href, visible):
            low_risk_urls.append(analysis_href)
        else:
            interactive_urls.append(analysis_href)

    for raw_url in parser.interactive_urls:
        resolved = resolve_relative_url(raw_url, base_href)
        if resolved:
            analysis_url = unwrap_redirect_url(resolved)
            if analysis_url not in interactive_urls and analysis_url not in low_risk_urls:
                interactive_urls.append(analysis_url)

    technical_urls: List[str] = []
    for raw_url in parser.technical_urls:
        resolved = resolve_relative_url(raw_url, base_href)
        if resolved:
            technical_urls.append(unwrap_redirect_url(resolved))

    # anchor_pairs vẫn giữ raw href đã clean nếu không resolve được,
    # để analyzer còn thấy dấu hiệu opaque target kiểu rid=...
    anchor_pairs: List[Tuple[str, str]] = []
    for raw_href, visible in parser.anchor_pairs:
        resolved_href = resolve_relative_url(raw_href, base_href)
        fallback = clean_url_candidate(raw_href)
        final_href = unwrap_redirect_url(resolved_href or fallback)
        if final_href:
            anchor_pairs.append((final_href, collapse_soft_linebreaks(visible)))

    return _dedupe_urls(interactive_urls), _dedupe_urls(low_risk_urls), _dedupe_urls(technical_urls), anchor_pairs



def extract_urls_from_text(text: str) -> List[str]:
    text = collapse_soft_linebreaks(text or "")
    results: List[str] = []

    email_spans: List[Tuple[int, int]] = []
    for m in EMAIL_RE.finditer(text):
        email_spans.append((m.start(), m.end()))

    url_spans: List[Tuple[int, int]] = []

    def overlaps(spans: List[Tuple[int, int]], start: int, end: int) -> bool:
        for s, e in spans:
            if start < e and end > s:
                return True
        return False

    for pattern in (HTTP_URL_RE, WWW_URL_RE):
        for m in pattern.finditer(text):
            if overlaps(email_spans, m.start(), m.end()):
                continue
            cleaned = clean_url_candidate(m.group(0))
            if cleaned:
                results.append(cleaned)
                url_spans.append((m.start(), m.end()))

    for m in BARE_DOMAIN_RE.finditer(text):
        if overlaps(email_spans, m.start(), m.end()):
            continue
        if overlaps(url_spans, m.start(), m.end()):
            continue

        token = m.group(0)
        start = m.start()
        end = m.end()

        prev_char = text[start - 1] if start > 0 else ""
        next_char = text[end] if end < len(text) else ""
        if prev_char in {"@", "/", ":"} or next_char == "@":
            continue

        window_left = text[max(0, start - 64):start]
        window_right = text[end:min(len(text), end + 64)]
        if "@" in window_left or "@" in window_right:
            continue

        normalized = maybe_normalize_domain_candidate(token)
        if normalized:
            results.append(normalized)

    return _dedupe_urls(results)



def extract_urls(text_body: str, html_body: str) -> Tuple[List[str], List[Tuple[str, str]], Dict[str, List[str]]]:
    text_hits = extract_urls_from_text(text_body or "")
    html_interactive_hits, html_low_risk_hits, html_technical_hits, anchor_pairs = parse_html_links(html_body or "")
    anchor_visible_hits: List[str] = []

    for href, visible in anchor_pairs:
        if visible and not is_low_risk_anchor(href, visible):
            anchor_visible_hits.extend(extract_urls_from_text(visible))

    html_text_hits = extract_urls_from_text(strip_html_to_text(html_body or ""))
    low_risk_set = {_canonical_url_key(x) for x in html_low_risk_hits}

    combined: List[str] = []
    best_by_key: Dict[str, str] = {}
    order: List[str] = []

    for bucket in (text_hits, html_interactive_hits, anchor_visible_hits, html_text_hits):
        for url in bucket:
            cleaned = clean_url_candidate(url)
            if not cleaned:
                continue
            key = _canonical_url_key(cleaned)
            if not key or key in low_risk_set:
                continue
            if key not in best_by_key:
                best_by_key[key] = cleaned
                order.append(key)
            elif _url_preference_score(cleaned) > _url_preference_score(best_by_key[key]):
                best_by_key[key] = cleaned

    combined = [best_by_key[key] for key in order]

    debug = {
        "text_body": text_hits,
        "html_interactive": html_interactive_hits,
        "html_low_risk": html_low_risk_hits,
        "html_technical": html_technical_hits,
        "anchor_visible_text": anchor_visible_hits,
        "html_visible_text": html_text_hits,
    }

    return combined, anchor_pairs, debug



def hostname_from_url(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""



def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False



def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().strip(".[]")



def registrable_domain(host: str) -> str:
    host = _normalize_host(host)
    if not host:
        return ""
    if is_ip_hostname(host):
        return host

    if tldextract is not None:
        try:
            parts = tldextract.extract(host)
            if parts.domain and parts.suffix:
                return f"{parts.domain}.{parts.suffix}".lower()
            if parts.domain:
                return parts.domain.lower()
        except Exception:
            pass

    labels = host.split(".")
    if len(labels) <= 2:
        return host

    suffix2 = ".".join(labels[-2:])
    if suffix2 in COMMON_TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])



def related_domains(domain_a: str, domain_b: str) -> bool:
    host_a = _normalize_host(domain_a)
    host_b = _normalize_host(domain_b)
    if not host_a or not host_b:
        return False
    if host_a == host_b:
        return True
    if is_ip_hostname(host_a) or is_ip_hostname(host_b):
        return host_a == host_b

    reg_a = registrable_domain(host_a)
    reg_b = registrable_domain(host_b)
    if reg_a and reg_b and reg_a == reg_b:
        return True

    return host_a.endswith("." + host_b) or host_b.endswith("." + host_a)



def domain_matches_any(domain: str, allowed_domains) -> bool:
    domain = (domain or "").lower().strip()
    if not domain:
        return False
    return any(related_domains(domain, good) for good in allowed_domains)



def looks_like_visible_url(text: str) -> bool:
    text = (text or "").strip().lower()
    return (
        text.startswith("http://")
        or text.startswith("https://")
        or text.startswith("www.")
        or bool(BARE_DOMAIN_RE.search(text))
    )



def remove_urls_from_text(text: str) -> str:
    text = collapse_soft_linebreaks(text or "")
    text = HTTP_URL_RE.sub(" ", text)
    text = WWW_URL_RE.sub(" ", text)
    text = BARE_DOMAIN_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()



def is_hex_ip_hostname(hostname: str) -> bool:
    host = (hostname or "").lower().strip().strip("[]")
    if not host:
        return False
    if re.fullmatch(r"0x[0-9a-f]+", host):
        return True
    if re.fullmatch(r"(?:0x[0-9a-f]+\.){3}0x[0-9a-f]+", host):
        return True
    if re.fullmatch(r"[0-9a-f]{8}", host) and any(c in "abcdef" for c in host):
        return True
    return False



def is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except Exception:
        return False



def has_mixed_scripts(text: str) -> bool:
    has_latin = False
    has_cyr = False
    has_greek = False

    for ch in text:
        try:
            name = unicodedata.name(ch)
        except Exception:
            continue
        if "LATIN" in name:
            has_latin = True
        elif "CYRILLIC" in name:
            has_cyr = True
        elif "GREEK" in name:
            has_greek = True

    return sum([has_latin, has_cyr, has_greek]) >= 2



def has_bad_unicode(text: str) -> bool:
    for ch in text:
        if ord(ch) < 32 and ch not in "\t\r\n":
            return True
        cat = unicodedata.category(ch)
        if cat in {"Cf", "Cs"} and ch not in "\u200b\u200c\u200d\u2060\ufeff":
            return True
    return False



def tld_from_host(host: str) -> str:
    host = (host or "").strip(".").lower()
    if "." not in host:
        return ""
    return host.rsplit(".", 1)[-1]



def is_google_redirect_fraud(url: str) -> Tuple[bool, str]:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()

        if host not in {"google.com", "www.google.com"}:
            return False, ""
        if path not in {"/url", "/imgres"}:
            return False, ""

        qs = parse_qs(parsed.query)
        target = ""
        for key in ("q", "url", "imgurl"):
            if qs.get(key):
                target = clean_url_candidate(qs[key][0])
                break

        if not target:
            return False, ""

        target_host = hostname_from_url(target)
        if target_host and not domain_matches_any(target_host, GOOGLE_TRUSTED_DOMAINS):
            return True, target

        return False, ""
    except Exception:
        return False, ""



def is_google_docs_like_url(url: str) -> bool:
    host = hostname_from_url(url)
    return domain_matches_any(host, {"docs.google.com", "drive.google.com", "forms.gle"})



def nested_redirect_depth(url: str, depth: int = 0) -> int:
    if depth > 5:
        return depth

    cleaned = clean_url_candidate(url)
    unwrapped = unwrap_redirect_url(cleaned)
    if unwrapped and unwrapped != cleaned:
        return nested_redirect_depth(unwrapped, depth + 1)

    try:
        parsed = urlsplit(cleaned)
        qs = parse_qs(parsed.query)
        for key in REDIRECT_PARAM_KEYS:
            if qs.get(key):
                nxt = clean_url_candidate(qs[key][0])
                if nxt and "://" in nxt:
                    return nested_redirect_depth(nxt, depth + 1)
    except Exception:
        pass
    return depth
