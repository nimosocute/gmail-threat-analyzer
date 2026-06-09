import re
from typing import Dict, List, Optional, Tuple

from constants import FREEMAIL_DOMAINS, TRUSTED_BRAND_FAMILIES
from core.feed_utils import get_brand_allowlist
from core.parser_utils import (
    extract_emails_from_header,
    extract_sender_claim_surface,
    get_domain_from_email_header,
    get_email_address,
    normalize_brand_text,
    strip_html_to_text,
)
from core.url_utils import related_domains


CLAIM_SOURCE_WEIGHTS = {
    "sender": 6,
    "subject": 4,
    "anchor": 4,
    "body_repeat": 2,
    "body_single": 1,
}

PRIMARY_CLAIM_SCORE = 6
MEDIUM_CLAIM_SCORE = 4


CLAIM_TEXT_STRIP_RE = re.compile(
    r"(?:https?://|www\.)\S+|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    flags=re.IGNORECASE,
)

RAW_VISIBLE_URL_RE = re.compile(r"^\s*(?:https?://|www\.)\S+\s*$", flags=re.IGNORECASE)
RAW_VISIBLE_HOST_RE = re.compile(r"^\s*[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/?#]\S*)?\s*$", flags=re.IGNORECASE)


BRAND_EQUIVALENCE = {
    "google": {"google", "gmail"},
    "gmail": {"google", "gmail"},
    "microsoft": {"microsoft", "outlook"},
    "outlook": {"microsoft", "outlook"},
    "facebook": {"facebook", "instagram"},
    "instagram": {"facebook", "instagram"},
}


def _prepare_claim_text(text: str, strip_contacts: bool = False) -> str:
    prepared = text or ""
    if strip_contacts:
        prepared = CLAIM_TEXT_STRIP_RE.sub(" ", prepared)
    return normalize_brand_text(prepared)


def equivalent_brands(brand: str, allowlist: Optional[Dict[str, Dict[str, set]]] = None) -> List[str]:
    allowlist = allowlist or get_brand_allowlist()
    brand = (brand or "").strip().lower()
    if not brand:
        return []

    out = []
    seen = set()
    for item in BRAND_EQUIVALENCE.get(brand, {brand}):
        item = (item or "").strip().lower()
        if item and item in allowlist and item not in seen:
            seen.add(item)
            out.append(item)
    if brand in allowlist and brand not in seen:
        out.append(brand)
    return out


def sender_matches_brand_family(
    brand: str,
    allowlist: Dict[str, Dict[str, set]],
    sender_email: str,
    sender_domain: str,
) -> bool:
    for candidate in equivalent_brands(brand, allowlist):
        if sender_matches_brand(allowlist.get(candidate, {}), sender_email, sender_domain):
            return True
    return False


def link_matches_brand_family(
    brand: str,
    allowlist: Dict[str, Dict[str, set]],
    url_hosts: List[str],
) -> bool:
    for candidate in equivalent_brands(brand, allowlist):
        if link_matches_brand(allowlist.get(candidate, {}), url_hosts):
            return True
    return False


def text_contains_alias(text: str, alias: str) -> bool:
    text = (text or "").lower()
    alias = (alias or "").strip().lower()
    if not alias:
        return False

    if " " in alias:
        return alias in text

    pattern = rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])"
    return bool(re.search(pattern, text, flags=re.IGNORECASE))



def _count_alias_occurrences(text: str, alias: str) -> int:
    text = (text or "").lower()
    alias = (alias or "").strip().lower()
    if not alias:
        return 0
    pattern = rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])"
    return len(re.findall(pattern, text, flags=re.IGNORECASE))



def sender_matches_brand(brand_bucket: Dict[str, set], sender_email: str, sender_domain: str) -> bool:
    sender_email = (sender_email or "").lower().strip()
    sender_domain = (sender_domain or "").lower().strip()

    if sender_email and sender_email in brand_bucket.get("sender_exact_email", set()):
        return True

    if sender_domain and sender_domain in brand_bucket.get("sender_exact_domain", set()):
        return True

    if sender_domain and any(related_domains(sender_domain, d) for d in brand_bucket.get("sender_domain", set())):
        return True

    return False



def link_matches_brand(brand_bucket: Dict[str, set], url_hosts: List[str]) -> bool:
    hosts = [(h or "").lower().strip() for h in url_hosts if h]
    if not hosts:
        return False

    exact_domains = brand_bucket.get("link_exact_domain", set())
    domain_rules = brand_bucket.get("link_domain", set())

    for host in hosts:
        if host in exact_domains:
            return True
        if any(related_domains(host, d) for d in domain_rules):
            return True

    return False



def is_freemail_domain(domain: str) -> bool:
    return (domain or "").lower() in FREEMAIL_DOMAINS


def brand_family_domains(brand: str, allowlist: Optional[Dict[str, Dict[str, set]]] = None) -> set:
    brand = (brand or "").lower().strip()
    allowlist = allowlist or get_brand_allowlist()
    bucket = allowlist.get(brand, {})
    family = set(TRUSTED_BRAND_FAMILIES.get(brand, set()))
    family.update(bucket.get("sender_domain", set()) or set())
    family.update(bucket.get("sender_exact_domain", set()) or set())
    family.update(bucket.get("link_domain", set()) or set())
    family.update(bucket.get("link_exact_domain", set()) or set())
    family.discard("")
    return {d.lower() for d in family if d}


def match_sender_brands(sender_email: str, sender_domain: str, allowlist: Optional[Dict[str, Dict[str, set]]] = None) -> List[str]:
    allowlist = allowlist or get_brand_allowlist()
    out = []
    for brand, bucket in allowlist.items():
        if sender_matches_brand(bucket, sender_email, sender_domain):
            out.append(brand)
    return sorted(set(out))


def match_click_brands(url_hosts: List[str], allowlist: Optional[Dict[str, Dict[str, set]]] = None) -> List[str]:
    allowlist = allowlist or get_brand_allowlist()
    hosts = [h for h in url_hosts if h]
    out = []
    for brand, bucket in allowlist.items():
        if link_matches_brand(bucket, hosts):
            out.append(brand)
    return sorted(set(out))



def _brand_signal_hits(text: str, aliases: set) -> List[str]:
    return sorted({alias for alias in aliases if alias and text_contains_alias(text, alias)})


def _looks_like_raw_visible_url(text: str) -> bool:
    value = (text or "").strip()
    if not value:
        return False
    if " " in value or "\n" in value or "\t" in value:
        return False
    return bool(RAW_VISIBLE_URL_RE.fullmatch(value) or RAW_VISIBLE_HOST_RE.fullmatch(value))


def extract_claimed_identities(
    sender_header: str,
    subject: str,
    body: str,
    html_body: str = "",
    anchor_pairs: Optional[List[Tuple[str, str]]] = None,
) -> List[Dict]:
    allowlist = get_brand_allowlist()

    sender_claim_surface = _prepare_claim_text(extract_sender_claim_surface(sender_header))
    subject_text = _prepare_claim_text(subject or "")
    body_source = strip_html_to_text(html_body or "") if html_body else (body or "")
    body_text = _prepare_claim_text(body_source, strip_contacts=True)
    anchor_texts = [
        _prepare_claim_text(visible)
        for _, visible in (anchor_pairs or [])
        if visible and not _looks_like_raw_visible_url(visible)
    ]

    identities: List[Dict] = []

    for brand, bucket in allowlist.items():
        aliases = set(bucket.get("aliases", set()) or set())
        aliases.add(brand)
        aliases = {a.strip().lower() for a in aliases if a and len(a.strip()) >= 2}
        if not aliases:
            continue

        sender_hits = _brand_signal_hits(sender_claim_surface, aliases)
        subject_hits = _brand_signal_hits(subject_text, aliases)
        anchor_hits = sorted({alias for text in anchor_texts for alias in aliases if text_contains_alias(text, alias)})
        body_hits = _brand_signal_hits(body_text, aliases)
        body_occurrences = sum(_count_alias_occurrences(body_text, alias) for alias in aliases)

        score = 0
        sources: List[str] = []
        if sender_hits:
            score += CLAIM_SOURCE_WEIGHTS["sender"]
            sources.append("sender")
        if subject_hits:
            score += CLAIM_SOURCE_WEIGHTS["subject"]
            sources.append("subject")
        if anchor_hits:
            score += CLAIM_SOURCE_WEIGHTS["anchor"]
            sources.append("anchor")
        if body_occurrences >= 2:
            score += CLAIM_SOURCE_WEIGHTS["body_repeat"]
            sources.append("body_repeat")
        elif body_occurrences == 1 and not (sender_hits or subject_hits or anchor_hits):
            score += CLAIM_SOURCE_WEIGHTS["body_single"]
            sources.append("body_single")

        strong_claim = bool(sender_hits or subject_hits or anchor_hits)
        repeated_body_claim = body_occurrences >= 2
        if not (strong_claim or repeated_body_claim):
            continue

        primary = bool(
            score >= PRIMARY_CLAIM_SCORE
            or (sender_hits and (subject_hits or anchor_hits))
            or (subject_hits and anchor_hits)
        )

        if score >= 10:
            strength = "very_strong"
        elif score >= PRIMARY_CLAIM_SCORE:
            strength = "strong"
        elif score >= MEDIUM_CLAIM_SCORE:
            strength = "medium"
        else:
            strength = "weak"

        identities.append(
            {
                "brand": brand,
                "aliases": sorted(aliases),
                "sender_hits": sender_hits,
                "subject_hits": subject_hits,
                "anchor_hits": anchor_hits,
                "body_hits": body_hits,
                "body_occurrences": body_occurrences,
                "sources": sources,
                "score": score,
                "strength": strength,
                "primary": primary,
            }
        )

    identities.sort(key=lambda item: (-int(item.get("score", 0)), item.get("brand", "")))
    return identities



def infer_claimed_brands(
    sender_header: str,
    subject: str,
    body: str,
    html_body: str = "",
    anchor_pairs: Optional[List[Tuple[str, str]]] = None,
) -> List[str]:
    identities = extract_claimed_identities(
        sender_header,
        subject,
        body,
        html_body=html_body,
        anchor_pairs=anchor_pairs,
    )
    return [item["brand"] for item in identities]



def detect_brand_impersonation(
    sender_header: str,
    subject: str,
    body: str,
    sender_domain: str,
    sender_email: str = "",
    html_body: str = "",
    anchor_pairs: Optional[List[Tuple[str, str]]] = None,
) -> List[str]:
    allowlist = get_brand_allowlist()
    claimed = infer_claimed_brands(
        sender_header,
        subject,
        body,
        html_body=html_body,
        anchor_pairs=anchor_pairs,
    )

    hits = []
    for brand in claimed:
        if not sender_matches_brand_family(brand, allowlist, sender_email, sender_domain):
            hits.append(brand)

    return sorted(set(hits))



def detect_sender_display_spoofing(header_value: str):
    header = str(header_value or "").strip()
    emails = extract_emails_from_header(header)

    if len(emails) >= 2:
        display_email = emails[0]
        actual_email = emails[-1]
        if display_email != actual_email:
            return True, {
                "display_email": display_email,
                "actual_email": actual_email,
                "display_domain": display_email.split("@", 1)[1],
                "actual_domain": actual_email.split("@", 1)[1],
            }

    m = re.search(
        r'^\s*"?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"?\s*<\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*>',
        header,
        flags=re.IGNORECASE
    )
    if m:
        display_email = m.group(1).lower()
        actual_email = m.group(2).lower()
        if display_email != actual_email:
            return True, {
                "display_email": display_email,
                "actual_email": actual_email,
                "display_domain": display_email.split("@", 1)[1],
                "actual_domain": actual_email.split("@", 1)[1],
            }

    return False, {}



def looks_like_google_docs_theme(combined_text: str) -> bool:
    text = (combined_text or "").lower()
    phrases = [
        "google docs", "google drive", "shared document", "shared file",
        "view document", "open document", "shared with you"
    ]
    return any(p in text for p in phrases)



def looks_like_gov_claim(display_name: str, combined_text: str) -> bool:
    text = normalize_brand_text(f"{display_name or ''} {combined_text or ''}")
    if not text:
        return False

    edu_terms = [
        "university", "college", "school", "campus",
        "đại học", "cao đẳng", "học kỳ", "sinh viên", "ký túc xá", "fpt",
    ]
    if any(term in text for term in edu_terms):
        return False

    strong_gov_terms = [
        "government", "government of", "ministry of", "department of",
        "tax authority", "social security administration", "public service portal",
        "chính phủ", "cơ quan nhà nước", "dịch vụ công", "ủy ban nhân dân",
        "bo cong an", "bo y te", "bo giao duc", "tong cuc thue",
        "cuc thue", "so thuế", "bao hiem xa hoi", "hai quan",
    ]
    return any(term in text for term in strong_gov_terms)


def is_government_domain(domain: str) -> bool:
    domain = (domain or "").lower().strip()
    return (
        domain == "gov"
        or domain == "gov.vn"
        or domain.endswith(".gov")
        or domain.endswith(".gov.vn")
    )



def collect_from_related_domain_mismatches(email_dict: Dict) -> List[Dict]:
    from_domain = get_domain_from_email_header(email_dict.get("sender", ""))
    checks = {
        "Sender": get_domain_from_email_header(email_dict.get("sender_header", "")),
    }
    mismatches = []
    for header_name, domain in checks.items():
        if from_domain and domain and not related_domains(from_domain, domain):
            mismatches.append(
                {"header": header_name, "from_domain": from_domain, "other_domain": domain}
            )
    return mismatches



def classify_brand_relationship(
    claimed_brands: List[str],
    sender_domain: str,
    url_hosts: List[str],
    allowlist: Dict[str, Dict[str, set]],
    sender_email: str = "",
    claimed_identities: Optional[List[Dict]] = None,
) -> Dict:
    claimed_identities = list(claimed_identities or [])
    if not claimed_identities:
        claimed_identities = [{"brand": brand, "primary": True, "score": 0, "strength": "unknown"} for brand in claimed_brands]

    ordered_claims = []
    seen = set()
    for item in claimed_identities:
        brand = (item.get("brand") or "").strip().lower()
        if brand and brand not in seen:
            seen.add(brand)
            ordered_claims.append(brand)
    for brand in claimed_brands:
        brand = (brand or "").strip().lower()
        if brand and brand not in seen:
            seen.add(brand)
            ordered_claims.append(brand)

    result = {
        "claimed_brands": ordered_claims,
        "claimed_identity_details": claimed_identities,
        "primary_claimed_brands": [item["brand"] for item in claimed_identities if item.get("primary")],
        "strong_claimed_brands": [item["brand"] for item in claimed_identities if item.get("strength") in {"strong", "very_strong"}],
        "sender_match_brands": [],
        "click_match_brands": [],
        "sender_miss_brands": [],
        "click_miss_brands": [],
        "has_sender_mismatch": False,
        "has_click_mismatch": False,
        "has_any_mismatch": False,
        "identity_conflict_level": "none",
    }

    if not ordered_claims:
        return result

    url_hosts = [h for h in url_hosts if h]

    for brand in ordered_claims:
        sender_ok = sender_matches_brand_family(brand, allowlist, sender_email, sender_domain)
        click_ok = link_matches_brand_family(brand, allowlist, url_hosts)

        if sender_ok:
            result["sender_match_brands"].append(brand)
        else:
            result["sender_miss_brands"].append(brand)

        if url_hosts:
            if click_ok:
                result["click_match_brands"].append(brand)
            else:
                result["click_miss_brands"].append(brand)

    result["has_sender_mismatch"] = bool(result["sender_miss_brands"])
    result["has_click_mismatch"] = bool(result["click_miss_brands"])
    result["has_any_mismatch"] = bool(result["sender_miss_brands"] or result["click_miss_brands"])

    sender_is_freemail = is_freemail_domain(sender_domain)
    strong_claim = bool(result["strong_claimed_brands"] or result["primary_claimed_brands"])

    if result["has_sender_mismatch"] and (sender_is_freemail or result["has_click_mismatch"] or strong_claim):
        result["identity_conflict_level"] = "high"
    elif result["has_sender_mismatch"] or result["has_click_mismatch"]:
        result["identity_conflict_level"] = "medium"
    else:
        result["identity_conflict_level"] = "low"

    return result
