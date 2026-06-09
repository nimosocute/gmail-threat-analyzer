from concurrent.futures import ThreadPoolExecutor
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import pandas as pd
from email.utils import parseaddr

from constants import (
    ANON_DOMAIN_HINTS,
    ARCHIVE_EXTENSIONS,
    BEC_HINTS,
    BTC_RE,
    EMAIL_RE,
    EMOTION_KEYWORDS,
    IP_RE,
    LEAKED_PASSWORD_HINTS,
    LOGINISH_KEYWORDS,
    PAYPAL_DOMAINS,
    QR_PHISH_HINTS,
    REDIRECTOR_DOMAINS,
    RULE_CATALOG,
    GENERIC_REPLYTO_TITLES_OK,
    RTL_OVERRIDE_RE,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    URGENT_KEYWORDS,
    ZERO_WIDTH_RE,
)
from core.attachment_utils import attachment_looks_phishy, has_dangerous_attachment
from core.attack_types import detect_attack_types, likely_thread_hijack
from core.auth_utils import header_contains_plusall_hint, summarize_authenticated_identity
from core.brand_utils import (
    classify_brand_relationship,
    collect_from_related_domain_mismatches,
    detect_sender_display_spoofing,
    extract_claimed_identities,
    infer_claimed_brands,
    is_freemail_domain,
    match_click_brands,
    match_sender_brands,
    is_government_domain,
    looks_like_google_docs_theme,
    looks_like_gov_claim,
)
from core.feed_utils import get_brand_allowlist, load_all_feeds
from core.online_intel import collect_online_brand_intel
from core.parser_utils import (
    extract_emails_from_header,
    get_email_address,
    get_domain_from_email_header,
    strip_html_to_text,
)
from core.url_utils import (
    clean_url_candidate,
    domain_matches_any,
    extract_urls_from_text,
    has_bad_unicode,
    has_mixed_scripts,
    hostname_from_url,
    is_google_docs_like_url,
    is_google_redirect_fraud,
    is_hex_ip_hostname,
    is_ip_hostname,
    is_private_ip,
    looks_like_visible_url,
    nested_redirect_depth,
    related_domains,
    remove_urls_from_text,
    tld_from_host,
    unwrap_redirect_url,
)


def email_has_only_urls(visible_text: str, urls: List[str]) -> bool:
    non_url_text = remove_urls_from_text(visible_text)
    return bool(urls) and len(non_url_text) <= 3


def is_legit_google_internal_flow(url: str) -> bool:
    host = hostname_from_url(url)
    if not host:
        return False

    host = host.lower()
    low = (url or "").lower()

    if host != "accounts.google.com":
        return False

    trusted_prefixes = (
        "continue=https://myaccount.google.com/",
        "continue=http://myaccount.google.com/",
        "continue=https://accounts.google.com/",
        "continue=http://accounts.google.com/",
        "continue=https://security.google.com/",
        "continue=http://security.google.com/",
    )
    return any(x in low for x in trusted_prefixes)


def is_known_trusted_brand_click_host(
    host: str,
    sender_domain: str,
    return_path_domain: str,
) -> bool:
    if not host:
        return False

    host = host.lower()
    sender_domain = (sender_domain or "").lower()
    return_path_domain = (return_path_domain or "").lower()

    if sender_domain and related_domains(host, sender_domain):
        return True
    if return_path_domain and related_domains(host, return_path_domain):
        return True

    google_hosts = {
        "accounts.google.com",
        "myaccount.google.com",
        "notifications.google.com",
        "security.google.com",
    }
    if host in google_hosts and (
        sender_domain.endswith(".google.com")
        or sender_domain == "accounts.google.com"
        or return_path_domain.endswith(".google.com")
    ):
        return True

    facebook_hosts = {"facebook.com", "www.facebook.com", "m.facebook.com"}
    if host in facebook_hosts and (
        sender_domain.endswith("facebookmail.com")
        or return_path_domain.endswith("facebookmail.com")
    ):
        return True

    if domain_matches_any(host, PAYPAL_DOMAINS) and (
        domain_matches_any(sender_domain, PAYPAL_DOMAINS)
        or domain_matches_any(return_path_domain, PAYPAL_DOMAINS)
    ):
        return True

    return False


def build_mismatched_anchors(anchor_pairs: List[Tuple[str, str]]) -> List[Dict]:
    mismatched_anchor = []

    for href, visible in anchor_pairs:
        visible = (visible or "").strip()
        if not looks_like_visible_url(visible):
            continue

        real_href = unwrap_redirect_url(clean_url_candidate(href))
        visible_urls = extract_urls_from_text(visible)
        if not visible_urls:
            continue

        visible_host = hostname_from_url(visible_urls[0])
        real_host = hostname_from_url(real_href)

        if real_host and visible_host and not related_domains(real_host, visible_host):
            mismatched_anchor.append(
                {
                    "text": visible,
                    "href": real_href,
                    "visible_host": visible_host,
                    "real_host": real_host,
                    "reason": "domain_mismatch",
                }
            )
            continue

        if visible_host and real_href and not real_host and real_href not in visible_urls:
            mismatched_anchor.append(
                {
                    "text": visible,
                    "href": real_href,
                    "visible_host": visible_host,
                    "real_host": "",
                    "reason": "opaque_or_relative_href",
                }
            )

    return mismatched_anchor


def _canonical_url_key(url: str) -> str:
    cleaned = clean_url_candidate(url)
    if not cleaned:
        return ""
    host = hostname_from_url(cleaned)
    if not host:
        return cleaned.lower()
    try:
        parsed = urlsplit(cleaned)
        path = parsed.path or ""
        query = parsed.query or ""
        return f"{host.lower()}|{path}|{query}"
    except Exception:
        return cleaned.lower()


def normalize_urls_for_scoring(urls: List[str]) -> List[str]:
    best: Dict[str, str] = {}
    for raw in urls or []:
        cleaned = clean_url_candidate(raw)
        if not cleaned:
            continue
        key = _canonical_url_key(cleaned)
        if not key:
            continue
        current = best.get(key)
        if current is None:
            best[key] = cleaned
            continue
        if current.lower().startswith("http://") and cleaned.lower().startswith("https://"):
            best[key] = cleaned
    return list(best.values())


def analyze_email(email_dict: Dict, enable_online_checks: bool = True) -> Tuple[int, str, List[str], Dict]:
    feeds = load_all_feeds()
    raw_score = 0.0
    issues: List[str] = []
    evidence: Dict = {}
    fired_rules: List[Dict] = []
    bucket_scores: Dict[str, float] = {
        "identity": 0.0,
        "auth": 0.0,
        "behavior": 0.0,
        "meta": 0.0,
        "feed": 0.0,
        "trust": 0.0,
        "other": 0.0,
    }
    semantic_index: Dict[str, int] = {}
    evidence["duplicate_rules_suppressed"] = []

    def infer_bucket(symbol: str) -> str:
        if symbol.startswith("META_"):
            return "meta"
        if symbol.startswith(("PHISHED_", "DBL_", "URIBL_", "RBL_", "RECEIVED_")) or symbol in {"PH_SURBL_MULTI", "URIBL_DBL_PHISH", "DBL_ABUSE_PHISH"}:
            return "feed"
        if symbol.startswith("TRUSTLIST_") or symbol in {"TRUSTED_BRAND_AUTH", "DKIM_VALID", "DMARC_PASS", "AUTH_ALIGNMENT_STRONG_PASS"}:
            return "trust"
        if symbol.startswith(("SPF_", "DKIM_", "DMARC_", "AUTH_", "ARC_", "R_SPF_", "R_DKIM_")) or symbol in {"VIOLATED_DIRECT_SPF", "DNS_BRAND_NO_DMARC", "AUTH_ALIGNMENT_FAIL"}:
            return "auth"
        if symbol.startswith(("URL_", "URI_", "HFILTER_", "GOOG_", "FORM_", "PHISH_ATTACH", "PAYPAL_", "GOOGLE_DOCS_")) or symbol in {
            "SOCIAL_ENGINEERING_LANGUAGE", "PHISH_EMOTION", "GPT_PHISHING", "LEAKED_PASSWORD_SCAM", "REDIRECTOR_URL_ONLY",
            "HAS_ANON_DOMAIN", "VISIBLE_TEXT_URL_MISMATCH", "FUZZY_HTML_PHISHING_MISMATCH", "HACKED_WP_PHISHING", "PHISHING"
        }:
            return "behavior"
        if symbol in {
            "HEADER_FROM_DIFFERENT_DOMAINS", "FORGED_SENDER", "FROM_NEQ_DISPLAY_NAME", "BRAND_IMPERSONATION", "SPOOF_DISPLAY_NAME",
            "FREEMAIL_BRAND_ABUSE", "CLICK_DOMAIN_OFF_BRAND", "FROM_MISSP_REPLYTO", "REPLYTO_DOM_NEQ_FROM_DOM", "SPOOF_REPLYTO",
            "REPLYTO_WITHOUT_TO_CC", "REPLYTO_EQ_TO_ADDR", "REPLYTO_EMAIL_HAS_TITLE", "REPLYTO_UNPARSEABLE", "FREEMAIL_REPLYTO_NEQ_FROM",
            "SPOOFED_FREEMAIL", "BAD_FROM_HEADER", "FROM_PAYPAL_SPOOF", "FROM_GOV_SPOOF"
        }:
            return "identity"
        return "other"

    def add_rule(
        symbol: str,
        reason: str,
        details=None,
        score_override: Optional[float] = None,
        bucket: Optional[str] = None,
        semantic_key: Optional[str] = None,
    ):
        nonlocal raw_score
        meta = RULE_CATALOG.get(symbol, {"score": 0.0, "support": "custom", "description": ""})
        delta = float(meta["score"] if score_override is None else score_override)
        chosen_bucket = bucket or infer_bucket(symbol)
        key = semantic_key or symbol
        if key in semantic_index:
            evidence.setdefault("duplicate_rules_suppressed", []).append(
                {
                    "rule": symbol,
                    "semantic_key": key,
                    "reason": reason,
                    "delta": delta,
                }
            )
            return
        semantic_index[key] = len(fired_rules)
        raw_score += delta
        bucket_scores[chosen_bucket] = bucket_scores.get(chosen_bucket, 0.0) + delta
        fired_rules.append(
            {
                "rule": symbol,
                "delta": delta,
                "reason": reason,
                "support": meta.get("support", "custom"),
                "description": meta.get("description", ""),
                "details": details,
                "bucket": chosen_bucket,
                "semantic_key": key,
            }
        )
        if delta > 0:
            issues.append(f"[{symbol}] {reason}")
        if details is not None:
            evidence.setdefault("rule_details", {})[symbol] = details

    subject = email_dict.get("subject", "")
    text_body = email_dict.get("body_text", "")
    html_body = email_dict.get("body_html", "")
    visible_text = text_body if text_body else strip_html_to_text(html_body)
    combined_text = f"{subject}\n{visible_text}".lower()

    sender_header = email_dict.get("sender", "")
    reply_to_header = email_dict.get("reply_to", "")
    to_header = email_dict.get("to", "")
    cc_header = email_dict.get("cc", "")
    return_path = email_dict.get("return_path", "")
    received_headers = email_dict.get("received_headers", [])

    sender_domain = get_domain_from_email_header(sender_header)
    reply_domain = get_domain_from_email_header(reply_to_header)
    return_path_domain = get_domain_from_email_header(return_path)
    sender_email = (email_dict.get("sender_email") or "").lower().strip()
    display_name, _ = parseaddr(sender_header)

    urls = normalize_urls_for_scoring(email_dict.get("urls", []))
    anchor_pairs = email_dict.get("anchor_pairs", [])
    attachments = email_dict.get("attachments", [])
    attachment_meta = email_dict.get("attachment_meta", [])
    auth = email_dict.get("auth", {})

    lower_urls = [u.lower() for u in urls]
    url_hosts = [hostname_from_url(u) for u in urls]
    clean_hosts = [h for h in url_hosts if h]
    non_url_text = remove_urls_from_text(visible_text)
    non_url_word_count = len(non_url_text.split())

    if clean_hosts:
        if any(h in feeds["phished_excluded"] or u in feeds["phished_excluded"] for h, u in zip(url_hosts, lower_urls)):
            add_rule("PHISHED_EXCLUDED", "URL nằm trong danh sách exclusion", clean_hosts[:5], score_override=0.0)
        if any(h in feeds["phished_whitelisted"] or u in feeds["phished_whitelisted"] for h, u in zip(url_hosts, lower_urls)):
            add_rule("PHISHED_WHITELISTED", "URL nằm trong whitelist ngoại lệ", clean_hosts[:5])

    spoofed_sender, spoof_info = detect_sender_display_spoofing(sender_header)
    other_from_mismatches = collect_from_related_domain_mismatches(email_dict)

    allowlist = get_brand_allowlist()

    claimed_identity_details = extract_claimed_identities(
        sender_header,
        subject,
        visible_text,
        html_body=html_body,
        anchor_pairs=anchor_pairs,
    )
    claimed_brands_all = [item["brand"] for item in claimed_identity_details]

    local_brand_rel = classify_brand_relationship(
        claimed_brands_all,
        sender_domain,
        clean_hosts,
        allowlist,
        sender_email=sender_email,
        claimed_identities=claimed_identity_details,
    )

    online_brand_intel = {}
    brand_rel = dict(local_brand_rel)
    align: Dict = {}
    sender_dns: Dict = {}
    sender_rdap: Dict = {}

    if enable_online_checks:
        online_brand_intel = collect_online_brand_intel(
            email_dict,
            sender_domain,
            return_path_domain,
            clean_hosts,
            auth,
        )
        evidence["online_brand_intel"] = online_brand_intel

        online_brand_rel = online_brand_intel.get("brand_relationship", {}) or {}
        if online_brand_rel:
            brand_rel = online_brand_rel

        align = online_brand_intel.get("auth_alignment", {}) or {}
        sender_dns = online_brand_intel.get("sender_dns", {}) or {}
        sender_rdap = online_brand_intel.get("sender_rdap", {}) or {}

    auth_identity = summarize_authenticated_identity(
        sender_domain,
        return_path_domain,
        auth,
        brand_rel=brand_rel,
    )
    if align:
        auth_identity.update(align)
    align = auth_identity

    brand_rel.setdefault("claimed_identity_details", claimed_identity_details)
    brand_rel.setdefault("primary_claimed_brands", [item["brand"] for item in claimed_identity_details if item.get("primary")])
    brand_rel.setdefault("strong_claimed_brands", [item["brand"] for item in claimed_identity_details if item.get("strength") in {"strong", "very_strong"}])

    evidence["claimed_identity_details"] = claimed_identity_details
    evidence["local_brand_relationship"] = local_brand_rel
    evidence["brand_relationship"] = brand_rel
    evidence["authenticated_identity"] = align
    evidence["suppressed_auth_rewards"] = []

    def suppress_reward(symbol: str, reason: str, details=None):
        evidence.setdefault("suppressed_auth_rewards", []).append(
            {
                "rule": symbol,
                "reason": reason,
                "details": details,
            }
        )

    display_email_hits = extract_emails_from_header(display_name)
    actual_from_email = get_email_address(sender_header)
    has_display_email_mismatch = bool(
        display_email_hits
        and actual_from_email
        and any(x != actual_from_email for x in display_email_hits)
    )

    opaque_brand_targets = []
    for href, visible in anchor_pairs:
        visible = (visible or "").strip()
        if not visible or not looks_like_visible_url(visible):
            continue

        real_href = unwrap_redirect_url(clean_url_candidate(href))
        visible_host = hostname_from_url(visible)
        real_host = hostname_from_url(real_href)

        if visible_host and real_href and not real_host:
            opaque_brand_targets.append(
                {
                    "text": visible,
                    "href": real_href,
                    "visible_host": visible_host,
                    "real_host": "",
                    "reason": "opaque_or_relative_href",
                }
            )

    mismatched_anchor = build_mismatched_anchors(anchor_pairs)

    evidence["opaque_brand_targets"] = opaque_brand_targets[:10]
    evidence["mismatched_anchor_preview"] = mismatched_anchor[:10]

    sender_known_brands = match_sender_brands(sender_email, sender_domain, allowlist=allowlist)
    click_known_brands = match_click_brands(clean_hosts, allowlist=allowlist)
    evidence["sender_known_brands"] = sender_known_brands
    evidence["click_known_brands"] = click_known_brands

    brand_hits = sorted(set(brand_rel.get("sender_miss_brands", [])))
    click_brand_miss = sorted(set(brand_rel.get("click_miss_brands", [])))
    primary_claimed_brands = brand_rel.get("primary_claimed_brands", []) or []
    strong_claim_context = bool(primary_claimed_brands or brand_rel.get("strong_claimed_brands", []))
    reply_domain_mismatch = bool(reply_domain and sender_domain and not related_domains(sender_domain, reply_domain))

    trusted_sender_brand = bool(
        brand_rel.get("sender_match_brands")
        and not brand_rel.get("sender_miss_brands")
    )
    trusted_click_brand = bool(not brand_rel.get("click_miss_brands"))
    strong_auth = bool(
        align.get("strong_pass")
        or (
            auth.get("spf") == "pass"
            and auth.get("dkim") == "pass"
            and auth.get("dmarc") == "pass"
        )
    )
    auth_weak = any(auth.get(x) in {"fail", "softfail", "none", "unknown"} for x in ("spf", "dkim", "dmarc"))

    identity_conflict = bool(
        spoofed_sender
        or bool(other_from_mismatches)
        or bool(brand_hits)
        or bool(click_brand_miss)
        or has_display_email_mismatch
        or bool(opaque_brand_targets)
        or bool(mismatched_anchor)
        or reply_domain_mismatch
    )

    sender_family_consistent = bool(sender_known_brands)
    click_family_consistent = bool(not clean_hosts or not sender_known_brands or any(b in sender_known_brands for b in click_known_brands))
    trusted_sender_envelope = bool(
        strong_auth
        and sender_family_consistent
        and click_family_consistent
        and not spoofed_sender
        and not other_from_mismatches
        and not has_display_email_mismatch
        and not reply_domain_mismatch
        and not opaque_brand_targets
        and not mismatched_anchor
    )

    hard_trusted_brand = bool(
        (
            trusted_sender_brand
            and trusted_click_brand
            and strong_auth
            and not identity_conflict
            and bool(primary_claimed_brands or claimed_brands_all)
        )
        or trusted_sender_envelope
    )
    evidence["trusted_sender_envelope"] = trusted_sender_envelope
    evidence["hard_trusted_brand"] = hard_trusted_brand
    evidence["identity_conflict"] = identity_conflict
    evidence["auth_weak"] = auth_weak

    trusted_identity_flow = bool(hard_trusted_brand or trusted_sender_envelope)
    evidence["trusted_identity_flow"] = trusted_identity_flow

    suppress_auth_rewards = bool(
        align.get("auth_is_not_brand_proof")
        or (
            not hard_trusted_brand
            and not trusted_sender_envelope
            and (
                identity_conflict
                or (
                    claimed_brands_all
                    and is_freemail_domain(sender_domain)
                    and bool(brand_hits)
                )
            )
        )
    )

    brand_identity_gate = bool(brand_hits and not trusted_identity_flow)

    if spoofed_sender or other_from_mismatches:
        details = {
            "display_spoof": spoof_info if spoofed_sender else {},
            "from_related_mismatches": other_from_mismatches,
        }
        add_rule("HEADER_FROM_DIFFERENT_DOMAINS", "From hiển thị và domain liên quan không đồng nhất", details, bucket="identity", semantic_key="from_identity_conflict")
        add_rule("FORGED_SENDER", "From hiển thị và domain liên quan không đồng nhất", details, bucket="identity", semantic_key="from_identity_conflict")

    if has_display_email_mismatch:
        add_rule(
            "FROM_NEQ_DISPLAY_NAME",
            "Display name chứa email khác email thực sự trong From",
            {
                "display_name": display_name,
                "display_emails": display_email_hits,
                "actual": actual_from_email,
            },
            bucket="identity",
        )

    if brand_identity_gate:
        add_rule(
            "BRAND_IMPERSONATION",
            f"Tên/ngữ cảnh email đang claim brand nhưng sender domain không khớp: {', '.join(brand_hits)}",
            {
                "sender_header": sender_header,
                "display_name": display_name,
                "sender_domain": sender_domain,
                "sender_email": sender_email,
                "claimed_brands": claimed_brands_all,
                "primary_claimed_brands": primary_claimed_brands,
                "sender_miss_brands": brand_rel.get("sender_miss_brands", []),
                "claimed_identity_details": claimed_identity_details[:5],
                "trusted_identity_flow": trusted_identity_flow,
            },
            bucket="identity",
        )

    if spoofed_sender or brand_identity_gate:
        add_rule(
            "SPOOF_DISPLAY_NAME",
            f"Tên người gửi gợi ý giả mạo: {', '.join(brand_hits) if brand_identity_gate else 'email hiển thị khác email thật'}",
            {
                "display_name": display_name,
                "sender_header": sender_header,
                "sender_domain": sender_domain,
                "brand_hits": brand_hits,
                "spoof_info": spoof_info,
                "trusted_identity_flow": trusted_identity_flow,
            },
            bucket="identity",
            semantic_key="display_brand_spoof",
        )

    if is_freemail_domain(sender_domain) and brand_rel.get("sender_miss_brands") and not trusted_identity_flow:
        add_rule(
            "FREEMAIL_BRAND_ABUSE",
            f"Sender là freemail nhưng đang claim brand khác: {', '.join(brand_rel.get('sender_miss_brands', []))}",
            {
                "sender_email": sender_email,
                "sender_domain": sender_domain,
                "claimed_brands": claimed_brands_all,
                "primary_claimed_brands": primary_claimed_brands,
                "brand_relationship": brand_rel,
                "authenticated_identity": align,
            },
            bucket="identity",
        )

    if opaque_brand_targets and (brand_hits or claimed_brands_all) and not trusted_identity_flow:
        add_rule(
            "CLICK_DOMAIN_OFF_BRAND",
            "Link hiển thị như domain brand thật nhưng href thật là opaque/relative target",
            {
                "claimed_brands": claimed_brands_all,
                "sender_domain": sender_domain,
                "sender_email": sender_email,
                "opaque_brand_targets": opaque_brand_targets[:5],
                "trusted_identity_flow": trusted_identity_flow,
            },
            bucket="identity",
            semantic_key="click_off_brand",
        )

    if reply_to_header:
        parsed_name, parsed_addr = parseaddr(reply_to_header)
        benign_replyto_title = bool(
            parsed_name
            and parsed_addr
            and sender_domain
            and reply_domain
            and related_domains(sender_domain, reply_domain)
            and parsed_name.strip().lower() in GENERIC_REPLYTO_TITLES_OK
        )
        if parsed_name and parsed_addr and not benign_replyto_title:
            add_rule("REPLYTO_EMAIL_HAS_TITLE", "Reply-To chứa title/display name", {"reply_to": reply_to_header})
        if not parsed_addr and EMAIL_RE.search(reply_to_header):
            add_rule("REPLYTO_UNPARSEABLE", "Reply-To parse lỗi hoặc format bất thường", {"reply_to": reply_to_header})

    if sender_domain and reply_domain and not related_domains(sender_domain, reply_domain):
        add_rule(
            "FROM_MISSP_REPLYTO",
            f"Reply-To khác domain From ({sender_domain} ↔ {reply_domain})",
            {"from": sender_domain, "reply_to": reply_domain},
            bucket="identity",
            semantic_key="replyto_offdomain",
        )
        add_rule(
            "REPLYTO_DOM_NEQ_FROM_DOM",
            f"Reply-To khác domain From ({sender_domain} ↔ {reply_domain})",
            {"from": sender_domain, "reply_to": reply_domain},
            score_override=0.0,
            bucket="identity",
            semantic_key="replyto_offdomain",
        )
        add_rule(
            "SPOOF_REPLYTO",
            f"Reply-To khác domain From ({sender_domain} ↔ {reply_domain})",
            {"from": sender_domain, "reply_to": reply_domain},
            bucket="identity",
            semantic_key="replyto_offdomain",
        )

    has_to_or_cc = bool(extract_emails_from_header(to_header) or extract_emails_from_header(cc_header))
    if reply_to_header and not has_to_or_cc:
        add_rule(
            "REPLYTO_WITHOUT_TO_CC",
            "Có Reply-To nhưng To/Cc trống hoặc bất thường",
            {"reply_to": reply_to_header, "to": to_header, "cc": cc_header},
        )

    reply_to_email = get_email_address(reply_to_header)
    to_emails = extract_emails_from_header(to_header)
    if reply_to_email and reply_to_email in [x.lower() for x in to_emails]:
        add_rule("REPLYTO_EQ_TO_ADDR", "Reply-To trùng đúng địa chỉ To", {"reply_to": reply_to_email, "to": to_emails})

    if (
        sender_domain
        and reply_domain
        and is_freemail_domain(reply_domain)
        and not is_freemail_domain(sender_domain)
        and not related_domains(sender_domain, reply_domain)
    ):
        add_rule("FREEMAIL_REPLYTO_NEQ_FROM", "Reply-To là freemail và lệch với From domain", {"from": sender_domain, "reply_to": reply_domain})

    if auth.get("spf") == "unknown" and auth.get("dkim") == "unknown" and auth.get("dmarc") in {"unknown", "none"}:
        add_rule("AUTH_NA", "Không thấy rõ SPF/DKIM/DMARC", auth)

    if auth.get("spf") in {"fail", "softfail", "unknown"} and auth.get("dkim") in {"fail", "unknown"} and auth.get("dmarc") in {"fail", "none", "unknown"}:
        add_rule("AUTH_NA_OR_FAIL", "Không có cơ chế auth nào pass rõ ràng", auth)

    if auth.get("spf") == "fail":
        add_rule("SPF_FAIL", "SPF fail", auth, bucket="auth", semantic_key="spf_fail")
        add_rule("R_SPF_FAIL", "SPF fail", auth, bucket="auth", semantic_key="spf_fail")
    elif auth.get("spf") == "softfail":
        add_rule("SPF_SOFTFAIL", "SPF softfail", auth)

    if auth.get("spf") in {"fail", "softfail"} and len(received_headers) <= 1:
        add_rule(
            "VIOLATED_DIRECT_SPF",
            "SPF softfail/fail và Received chain nghèo nàn",
            {"auth": auth, "received_count": len(received_headers)},
        )

    if auth.get("dkim") == "fail":
        add_rule("DKIM_INVALID", "DKIM invalid/fail", auth, bucket="auth", semantic_key="dkim_fail")
        add_rule("R_DKIM_REJECT", "DKIM fail", auth, bucket="auth", semantic_key="dkim_fail")
    elif auth.get("dkim") == "pass":
        if suppress_auth_rewards:
            suppress_reward(
                "DKIM_VALID",
                "Không thưởng DKIM vì DKIM chỉ xác thực domain gửi thật, không xác thực brand đang bị claim",
                {
                    "auth": auth,
                    "claimed_brands": claimed_brands_all,
                    "brand_relationship": brand_rel,
                    "spoof_info": spoof_info,
                    "authenticated_identity": align,
                },
            )
        else:
            add_rule("DKIM_VALID", "DKIM pass", auth)

    if auth.get("arc") == "fail":
        add_rule("ARC_REJECT", "ARC fail", auth)

    if auth.get("dmarc") == "fail":
        add_rule("DMARC_FAIL", "DMARC fail", auth)
        add_rule("DMARC_POLICY_SOFTFAIL", "DMARC fail", auth)
    elif auth.get("dmarc") == "pass":
        if suppress_auth_rewards:
            suppress_reward(
                "DMARC_PASS",
                "Không thưởng DMARC vì DMARC pass đang align cho domain gửi thật chứ không chứng minh danh tính brand bị claim",
                {
                    "auth": auth,
                    "claimed_brands": claimed_brands_all,
                    "brand_relationship": brand_rel,
                    "spoof_info": spoof_info,
                    "authenticated_identity": align,
                },
            )
        else:
            add_rule("DMARC_PASS", "DMARC pass", auth, bucket="trust")
    elif auth.get("dmarc") == "none":
        if spoofed_sender or (sender_domain and reply_domain and not related_domains(sender_domain, reply_domain)):
            add_rule("DMARC_MISSING", "Thiếu DMARC / không thấy bằng chứng DMARC trong ngữ cảnh giả mạo", auth)

    if enable_online_checks:
        if (
            brand_rel.get("sender_match_brands")
            and not brand_rel.get("sender_miss_brands")
            and not brand_rel.get("click_miss_brands")
        ):
            add_rule(
                "TRUSTLIST_BRAND_DOMAIN_MATCH",
                f"Sender domain khớp trust list: {', '.join(brand_rel['sender_match_brands'])}",
                brand_rel,
            )

        if brand_rel.get("click_match_brands") and not brand_rel.get("click_miss_brands"):
            add_rule(
                "TRUSTLIST_CLICKDOMAIN_MATCH",
                f"Click domain khớp trust list: {', '.join(brand_rel['click_match_brands'])}",
                brand_rel,
            )

        if brand_rel.get("sender_miss_brands") and online_brand_intel.get("claimed_brands") and not trusted_identity_flow:
            add_rule(
                "TRUSTLIST_BRAND_DOMAIN_MISS",
                f"Claim brand nhưng sender domain lệch trust list: {', '.join(brand_rel['sender_miss_brands'])}",
                {**brand_rel, "trusted_identity_flow": trusted_identity_flow},
            )

        if brand_rel.get("click_miss_brands") and clean_hosts:
            click_miss_gate = bool(
                mismatched_anchor
                or brand_hits
                or (reply_domain and sender_domain and not related_domains(sender_domain, reply_domain))
                or any(auth.get(x) in {"fail", "softfail", "none", "unknown"} for x in ("spf", "dkim", "dmarc"))
                or any((href or "").lower().startswith("rid=") for href, _ in anchor_pairs)
            )
            if click_miss_gate and not trusted_sender_envelope and not hard_trusted_brand:
                add_rule(
                    "CLICK_DOMAIN_OFF_BRAND",
                    f"Claim brand nhưng click domain lệch trust list: {', '.join(brand_rel['click_miss_brands'])}",
                    {**brand_rel, "gate": "strict"},
                )

        if align.get("strong_pass"):
            if suppress_auth_rewards:
                suppress_reward(
                    "AUTH_ALIGNMENT_STRONG_PASS",
                    "Không thưởng auth alignment vì align này chỉ đúng cho domain gửi thật, không đúng với brand đang claim",
                    {
                        "align": align,
                        "claimed_brands": claimed_brands_all,
                        "brand_relationship": brand_rel,
                        "sender_domain": sender_domain,
                    },
                )
            else:
                add_rule("AUTH_ALIGNMENT_STRONG_PASS", "SPF/DKIM/DMARC align mạnh", align, bucket="trust")

        if align.get("clear_fail"):
            add_rule("AUTH_ALIGNMENT_FAIL", "SPF/DKIM/DMARC không align rõ ràng", align)

        if (
            sender_domain
            and brand_rel.get("sender_match_brands")
            and not brand_rel.get("sender_miss_brands")
        ):
            if not sender_dns.get("has_dmarc", False):
                add_rule("DNS_BRAND_NO_DMARC", f"Domain sender không có DMARC: {sender_domain}", sender_dns)

        days_old = sender_rdap.get("days_old")
        trusted_rdap_exempt = bool(
            sender_domain and (
                trusted_identity_flow
                or related_domains(sender_domain, "google.com")
                or related_domains(sender_domain, "facebookmail.com")
                or domain_matches_any(sender_domain, PAYPAL_DOMAINS)
            )
        )
        if sender_domain:
            if sender_rdap.get("ok") and isinstance(days_old, int):
                if days_old <= 30:
                    add_rule("RDAP_NEW_DOMAIN", f"Domain rất mới ({days_old} ngày): {sender_domain}", sender_rdap)
                elif days_old <= 180:
                    add_rule("RDAP_RECENT_DOMAIN", f"Domain còn mới ({days_old} ngày): {sender_domain}", sender_rdap)
            elif not trusted_rdap_exempt:
                add_rule("RDAP_NO_DATA", f"Không lấy được dữ liệu RDAP cho {sender_domain}", sender_rdap)

        if (
            brand_rel.get("sender_match_brands")
            and not brand_rel.get("sender_miss_brands")
            and not brand_rel.get("click_miss_brands")
            and strong_auth
            and sender_domain
            and not is_freemail_domain(sender_domain)
        ):
            add_rule(
                "TRUSTED_BRAND_AUTH",
                "Brand hợp lệ và auth tốt",
                {"sender_domain": sender_domain, "auth_alignment": align, "brand_relationship": brand_rel},
            )

    freemail_sus = False
    if sender_domain and is_freemail_domain(sender_domain):
        freemail_sus = (
            bool(brand_hits)
            or bool(opaque_brand_targets)
            or bool(mismatched_anchor)
            or has_display_email_mismatch
            or bool(reply_domain and not related_domains(sender_domain, reply_domain))
            or any(auth.get(x) in {"fail", "softfail", "none", "unknown"} for x in ("spf", "dkim", "dmarc"))
        )

    if freemail_sus:
        add_rule(
            "SPOOFED_FREEMAIL",
            f"Freemail sender có dấu hiệu giả mạo / không align ({sender_domain})",
            {
                "sender_domain": sender_domain,
                "reply_domain": reply_domain,
                "auth": auth,
                "brand_hits": brand_hits,
                "opaque_brand_targets": opaque_brand_targets[:5],
                "mismatched_anchor": mismatched_anchor[:5],
                "display_email_hits": display_email_hits,
                "actual_from_email": actual_from_email,
                "primary_claimed_brands": primary_claimed_brands,
                "claimed_identity_details": claimed_identity_details[:5],
                "authenticated_identity": align,
            },
            bucket="meta",
        )

    if header_contains_plusall_hint(email_dict.get("headers_preview", "")):
        add_rule("R_SPF_PLUSALL", "Có dấu hiệu SPF +all", True)

    matched_keywords = [kw for kw in URGENT_KEYWORDS if kw in combined_text]
    if matched_keywords and not hard_trusted_brand and (identity_conflict or auth_weak or bool(brand_hits) or reply_domain_mismatch):
        add_rule(
            "SOCIAL_ENGINEERING_LANGUAGE",
            f"Từ khóa thúc ép / đe dọa: {', '.join(sorted(set(matched_keywords))[:6])}",
            sorted(set(matched_keywords)),
        )
        add_rule(
            "PHISH_EMOTION",
            f"Từ ngữ tạo áp lực/cảm xúc: {', '.join(sorted(set(matched_keywords))[:6])}",
            sorted(set(matched_keywords)),
        )

    gpt_gate_brand = bool(brand_hits)
    gpt_gate_auth = any(auth.get(x) in {"fail", "softfail", "none", "unknown"} for x in ("spf", "dkim", "dmarc"))
    gpt_gate_reply = bool(reply_domain and sender_domain and not related_domains(sender_domain, reply_domain))
    gpt_gate_link = bool(mismatched_anchor)
    gpt_gate_opaque = any((href or "").lower().startswith("rid=") for href, _ in anchor_pairs)
    gpt_gate_click_miss = bool(brand_rel.get("click_miss_brands"))

    if (
        not hard_trusted_brand
        and any(k in combined_text for k in EMOTION_KEYWORDS)
        and (gpt_gate_brand or gpt_gate_auth or gpt_gate_reply or gpt_gate_link or gpt_gate_opaque or gpt_gate_click_miss)
    ):
        add_rule(
            "GPT_PHISHING",
            "Heuristic nội dung có vẻ phishing kiểu social engineering (đã gated)",
            {
                "emotion": [k for k in EMOTION_KEYWORDS if k in combined_text][:10],
                "gates": {
                    "brand_mismatch": gpt_gate_brand,
                    "auth_weak": gpt_gate_auth,
                    "reply_mismatch": gpt_gate_reply,
                    "anchor_mismatch": gpt_gate_link,
                    "opaque_target": gpt_gate_opaque,
                    "click_miss": gpt_gate_click_miss,
                },
            },
        )

    leaked_password_gate = bool(any(k in combined_text for k in LEAKED_PASSWORD_HINTS) and BTC_RE.search(combined_text))
    if leaked_password_gate and not hard_trusted_brand:
        add_rule(
            "LEAKED_PASSWORD_SCAM",
            "Mẫu sextortion / leaked password scam + BTC wallet",
            {
                "gate": "keyword_and_btc",
                "hard_trusted_brand": hard_trusted_brand,
                "trusted_identity_flow": trusted_identity_flow,
            },
        )
    elif leaked_password_gate and hard_trusted_brand:
        evidence.setdefault("suppressed_behavior_rules", []).append(
            {
                "rule": "LEAKED_PASSWORD_SCAM",
                "reason": "Bỏ qua vì đây là mail brand hợp lệ đã pass auth mạnh và identity không conflict",
            }
        )

    content_behavior_gate_pre = bool(not hard_trusted_brand and (identity_conflict or auth_weak or bool(brand_hits) or reply_domain_mismatch))
    if len(urls) == 1 and non_url_word_count <= 12 and content_behavior_gate_pre:
        add_rule("BODY_SINGLE_URI", "Nội dung gần như xoay quanh 1 URL duy nhất", {"url": urls[0], "non_url_word_count": non_url_word_count}, bucket="behavior", semantic_key="single_url_mintext")
        add_rule("HFILTER_URL_ONELINE", "Body có rất ít text và xoay quanh 1 URL", {"url": urls[0], "non_url_word_count": non_url_word_count}, bucket="behavior", semantic_key="single_url_mintext")

    if len(urls) >= 1 and non_url_word_count <= 3 and len(non_url_text) <= 30 and content_behavior_gate_pre:
        add_rule("BODY_URI_ONLY", "Body gần như chỉ chứa URL", {"urls": urls[:3], "non_url_text": non_url_text}, bucket="behavior", semantic_key="url_only_body")

    if email_has_only_urls(visible_text, urls) and content_behavior_gate_pre:
        add_rule("HFILTER_URL_ONLY", "Body gần như chỉ có URL", {"urls": urls[:3], "non_url_text": non_url_text}, bucket="behavior", semantic_key="url_only_body")

    redirector_urls = []
    nested_redirects = []
    anon_domains = []
    suspicious_urls = []
    ip_links = []
    private_ip_links = []
    hex_ip_links = []
    punycode_links = []
    weird_links = []
    dotcn_links = []
    loginish_links = []
    at_symbol_links = []
    multiple_at_links = []
    bad_unicode_links = []
    mixed_charset_links = []
    rtl_links = []
    zwsp_links = []
    excessive_dots_links = []
    no_tld_links = []
    user_long_links = []
    user_very_long_links = []
    very_long_urls = []
    backslash_links = []
    numeric_ip_user_links = []
    suspicious_tld_links = []
    homograph_links = []
    wordpress_links = []
    short_links = []
    google_redirect_abuse = []

    for url in urls:
        host = hostname_from_url(url)
        if not host:
            if "://" in url and "." not in re.sub(r"^.*://", "", url).split("/")[0]:
                no_tld_links.append(url)
            continue

        trusted_internal_url = bool(
            hard_trusted_brand
            and (
                is_known_trusted_brand_click_host(host, sender_domain, return_path_domain)
                or is_legit_google_internal_flow(url)
            )
        )

        parsed = re.match(r"^[a-z]+://([^/]+)", url, flags=re.IGNORECASE)
        netloc = parsed.group(1) if parsed else ""
        username = ""
        if "@" in netloc:
            username = netloc.split("@", 1)[0]

        if username:
            if len(username) > 40:
                user_long_links.append(url)
            if len(username) > 100:
                user_very_long_links.append(url)

        if username and is_ip_hostname(host):
            numeric_ip_user_links.append(url)

        if is_ip_hostname(host):
            ip_links.append(url)
            if is_private_ip(host):
                private_ip_links.append(url)

        if is_hex_ip_hostname(host):
            hex_ip_links.append(url)

        if host in SHORTENER_DOMAINS:
            short_links.append(url)

        if "xn--" in host:
            punycode_links.append(url)

        if has_bad_unicode(url):
            bad_unicode_links.append(url)

        if ZERO_WIDTH_RE.search(url):
            zwsp_links.append(url)

        if RTL_OVERRIDE_RE.search(url):
            rtl_links.append(url)

        if has_mixed_scripts(host) or ("xn--" in host and any(ord(c) > 127 for c in host)):
            mixed_charset_links.append(url)
            homograph_links.append(url)

        if host.count(".") >= 4 and not trusted_internal_url:
            excessive_dots_links.append(url)

        if host.endswith(".cn"):
            dotcn_links.append(url)

        if (host.count("-") >= 3 or len(host) > 35) and not trusted_internal_url:
            weird_links.append(url)

        if username or "@" in netloc:
            at_symbol_links.append(url)
            if url.count("@") >= 2:
                multiple_at_links.append(url)

        if any(k in url.lower() for k in LOGINISH_KEYWORDS) and not trusted_internal_url:
            loginish_links.append(url)

        if len(url) > 250 and not trusted_internal_url:
            very_long_urls.append(url)

        if "\\" in url:
            backslash_links.append(url)

        if tld_from_host(host) in SUSPICIOUS_TLDS:
            suspicious_tld_links.append(url)

        is_fraud, target = is_google_redirect_fraud(url)
        if host in REDIRECTOR_DOMAINS:
            redirector_urls.append(url)
        elif is_fraud and not is_legit_google_internal_flow(url):
            redirector_urls.append(url)

        if is_fraud and not is_legit_google_internal_flow(url):
            google_redirect_abuse.append({"redirector": url, "target": target})

        if nested_redirect_depth(url) >= 2 and not trusted_internal_url:
            nested_redirects.append(url)

        if any(hint in host for hint in ANON_DOMAIN_HINTS):
            anon_domains.append(url)

        if "wp-" in url.lower() or "/wp-content/" in url.lower() or "/wp-admin/" in url.lower():
            wordpress_links.append(url)

        if (
            not trusted_internal_url
            and any([
                username,
                "@" in netloc,
                "\\" in url,
                len(host) > 35,
                "xn--" in host,
                host.count("-") >= 3,
                any(k in url.lower() for k in LOGINISH_KEYWORDS),
            ])
        ):
            suspicious_urls.append(url)

    if ip_links:
        add_rule("URL_IP_LITERAL", f"URL dùng IP trực tiếp ({len(ip_links)})", ip_links[:5], bucket="behavior", semantic_key="ip_literal_url")
        add_rule("URL_NUMERIC_IP", f"URL dùng IP trực tiếp ({len(ip_links)})", ip_links[:5], bucket="behavior", semantic_key="ip_literal_url")

    if private_ip_links:
        add_rule("URL_NUMERIC_PRIVATE_IP", f"URL dùng private IP ({len(private_ip_links)})", private_ip_links[:5])

    if hex_ip_links:
        add_rule("URI_HEX_IP", f"URL dùng IP encode kiểu hex ({len(hex_ip_links)})", hex_ip_links[:5])
        add_rule("R_SUSPICIOUS_URL", f"URL dùng IP encode kiểu hex ({len(hex_ip_links)})", hex_ip_links[:5])

    if short_links:
        add_rule("SHORTENER_URL", f"Dùng dịch vụ rút gọn link ({len(short_links)})", short_links[:5])

    if zwsp_links:
        add_rule("ZERO_WIDTH_SPACE_URL", f"URL có zero width space ({len(zwsp_links)})", zwsp_links[:5], bucket="behavior", semantic_key="zero_width_url")
        add_rule("URL_ZERO_WIDTH_SPACES", f"URL có zero width space ({len(zwsp_links)})", zwsp_links[:5], bucket="behavior", semantic_key="zero_width_url")

    if mixed_charset_links:
        add_rule("R_MIXED_CHARSET_URL", f"URL dùng mixed scripts/charset ({len(mixed_charset_links)})", mixed_charset_links[:5])

    if rtl_links:
        add_rule("URL_RTL_OVERRIDE", f"URL chứa ký tự RTL override ({len(rtl_links)})", rtl_links[:5])

    if homograph_links:
        add_rule("URL_HOMOGRAPH_ATTACK", f"URL có dấu hiệu homograph ({len(homograph_links)})", homograph_links[:5])

    if punycode_links and not homograph_links:
        add_rule("PUNYCODE_URL", f"URL có punycode ({len(punycode_links)})", punycode_links[:5])

    if weird_links:
        add_rule("WEIRD_LONG_DOMAIN", "Có domain URL dài hoặc nhiều dấu gạch nối bất thường", weird_links[:5])

    if at_symbol_links:
        add_rule("URL_USER_PASSWORD", f"URL có user field / @ trong netloc ({len(at_symbol_links)})", at_symbol_links[:5])
        add_rule(
            "URI_PHISH",
            "URL có pattern thường gặp trong phishing (login/verify/@/account...)",
            {"loginish_links": loginish_links[:5], "at_symbol_links": at_symbol_links[:5]},
        )

    if multiple_at_links:
        add_rule("URL_MULTIPLE_AT_SIGNS", f"URL có nhiều @ ({len(multiple_at_links)})", multiple_at_links[:5])

    if user_long_links:
        add_rule("URL_USER_LONG", f"User field URL dài ({len(user_long_links)})", user_long_links[:5])

    if user_very_long_links:
        add_rule("URL_USER_VERY_LONG", f"User field URL rất dài ({len(user_very_long_links)})", user_very_long_links[:5])

    if numeric_ip_user_links:
        add_rule("URL_NUMERIC_IP_USER", f"URL dùng IP + user field ({len(numeric_ip_user_links)})", numeric_ip_user_links[:5])

    if suspicious_tld_links:
        add_rule("URL_SUSPICIOUS_TLD", f"URL dùng TLD đáng ngờ ({len(suspicious_tld_links)})", suspicious_tld_links[:5])

    if bad_unicode_links:
        add_rule("URL_BAD_UNICODE", f"URL chứa Unicode bất thường ({len(bad_unicode_links)})", bad_unicode_links[:5])

    if very_long_urls:
        add_rule("URL_VERY_LONG", f"URL rất dài ({len(very_long_urls)})", very_long_urls[:5])

    if backslash_links:
        add_rule("URL_BACKSLASH_PATH", f"URL có backslash ({len(backslash_links)})", backslash_links[:5])

    if excessive_dots_links:
        add_rule("URL_EXCESSIVE_DOTS", f"Hostname có quá nhiều dấu chấm ({len(excessive_dots_links)})", excessive_dots_links[:5])

    if no_tld_links:
        add_rule("URL_NO_TLD", f"URL không có TLD hợp lệ ({len(no_tld_links)})", no_tld_links[:5])

    if nested_redirects:
        add_rule("URL_REDIRECTOR_NESTED", f"Redirector lồng nhau ({len(nested_redirects)})", nested_redirects[:5])

    if google_redirect_abuse:
        add_rule("GOOG_REDIR_FRAUD", "Lạm dụng Google redirect để chuyển sang domain ngoài", google_redirect_abuse[:5])

    brand_or_urgency_context = bool(brand_hits or matched_keywords)
    if dotcn_links and (brand_or_urgency_context or loginish_links):
        add_rule("URI_DOTCN_SPOOF", "Có URL .cn trong ngữ cảnh dễ liên quan giả mạo thương hiệu / login", dotcn_links[:5])

    if redirector_urls and email_has_only_urls(visible_text, urls) and not hard_trusted_brand:
        add_rule("REDIRECTOR_URL_ONLY", "Nội dung gần như chỉ có redirector URL", redirector_urls[:5])

    if (redirector_urls or google_redirect_abuse) and (not hard_trusted_brand or identity_conflict or auth_weak):
        add_rule("PHISHING", "Có redirector URL / pattern phished URL", {"redirectors": redirector_urls[:5], "google": google_redirect_abuse[:5]}, bucket="behavior", semantic_key="redirector_pattern")

    if suspicious_urls:
        add_rule("R_SUSPICIOUS_URL", f"URL có pattern đáng ngờ ({len(suspicious_urls)})", suspicious_urls[:5])

    if anon_domains:
        add_rule("HAS_ANON_DOMAIN", f"URL dùng domain che giấu/relay ({len(anon_domains)})", anon_domains[:5])

    if (redirector_urls or anon_domains or ip_links or homograph_links or short_links) and (matched_keywords or brand_hits):
        add_rule(
            "SUSPICIOUS_URL_IN_SUSPICIOUS_MESSAGE",
            "Mail đáng ngờ và chứa URL đáng ngờ",
            {"urls": suspicious_urls[:5], "keywords": matched_keywords[:6], "brands": brand_hits},
        )

    if mismatched_anchor:
        add_rule("VISIBLE_TEXT_URL_MISMATCH", f"Text hiển thị của link không khớp domain thật ({len(mismatched_anchor)})", mismatched_anchor[:5], bucket="behavior", semantic_key="anchor_mismatch")
        add_rule("FUZZY_HTML_PHISHING_MISMATCH", f"Text hiển thị của link không khớp domain thật ({len(mismatched_anchor)})", mismatched_anchor[:5], bucket="behavior", semantic_key="anchor_mismatch")

    google_docs_like_urls = [u for u in urls if is_google_docs_like_url(u)]
    if google_docs_like_urls and looks_like_google_docs_theme(combined_text):
        if mismatched_anchor or redirector_urls or len(urls) == 1 or (reply_domain and sender_domain and not related_domains(sender_domain, reply_domain)):
            add_rule("GOOGLE_DOCS_PHISH", "Mail mang theme Google Docs/Drive theo pattern đáng ngờ", google_docs_like_urls[:5], bucket="behavior", semantic_key="google_docs_theme")
            add_rule("PHISHING", "Google Docs/Drive theme đáng ngờ", google_docs_like_urls[:5], bucket="behavior", semantic_key="google_docs_theme")

    if wordpress_links and (matched_keywords or loginish_links or brand_hits):
        add_rule("HACKED_WP_PHISHING", "Có dấu hiệu phishing từ hạ tầng WordPress", wordpress_links[:5])

    dangerous_files = has_dangerous_attachment(attachments)
    phishy_attach = [f for f in attachments if attachment_looks_phishy(f)]
    obfuscated_archives = []
    double_ext = []
    bad_unicode_files = []
    encrypted_archives = []
    generic_split_rar = []
    archive_like_names = []
    bad_attachment_mime = []
    pdf_suspicious = []
    pdf_javascript = []
    pdf_encrypted = []

    for item in attachment_meta:
        filename = item["filename"]
        ctype = item["content_type"]
        lower_name = filename.lower()
        ext = "." + lower_name.split(".")[-1] if "." in lower_name else ""

        if has_bad_unicode(filename) or ZERO_WIDTH_RE.search(filename) or RTL_OVERRIDE_RE.search(filename):
            bad_unicode_files.append(filename)

        if re.search(r"\.(pdf|doc|docx|xls|xlsx|txt)\.(exe|scr|js|vbs|bat|cmd|lnk)$", lower_name):
            double_ext.append(filename)

        if ext in ARCHIVE_EXTENSIONS:
            archive_like_names.append(filename)
            if any(token in lower_name for token in ["password", "protected", "encrypted", "enc"]):
                encrypted_archives.append(filename)
            if any(token in lower_name for token in ["__", "..", " ", "%20", "invoice", "scan", "document", "secure"]) or has_bad_unicode(filename):
                obfuscated_archives.append(filename)

        if re.search(r"\.(r\d{2}|\d{3}|001|002|003)$", lower_name):
            generic_split_rar.append(filename)

        if ctype and "." in lower_name:
            guessed_bad = {
                ".exe": "application/octet-stream",
                ".js": "application/javascript",
                ".html": "text/html",
            }
            if ext in guessed_bad and guessed_bad[ext] != ctype:
                bad_attachment_mime.append({"filename": filename, "content_type": ctype})

        pdf_info = item.get("pdf", {})
        if pdf_info.get("is_pdf"):
            if pdf_info.get("javascript"):
                pdf_javascript.append(filename)
            if pdf_info.get("encrypted"):
                pdf_encrypted.append(filename)
            if pdf_info.get("suspicious"):
                pdf_suspicious.append(filename)

    if dangerous_files:
        add_rule("MIME_BAD_EXTENSION", f"Có file đính kèm extension nguy hiểm ({len(dangerous_files)})", dangerous_files[:5])

    if double_ext:
        add_rule("MIME_DOUBLE_BAD_EXTENSION", f"File đính kèm có double extension ({len(double_ext)})", double_ext[:5])

    if bad_unicode_files:
        add_rule("MIME_BAD_UNICODE", f"Tên file đính kèm có Unicode/ẩn bất thường ({len(bad_unicode_files)})", bad_unicode_files[:5])

    if obfuscated_archives:
        add_rule("MIME_OBFUSCATED_ARCHIVE", f"Archive có dấu hiệu obfuscation ({len(obfuscated_archives)})", obfuscated_archives[:5])

    if encrypted_archives:
        add_rule("MIME_ENCRYPTED_ARCHIVE", f"Archive mã hóa hoặc ám chỉ protected ({len(encrypted_archives)})", encrypted_archives[:5])

    if dangerous_files and obfuscated_archives:
        add_rule(
            "MIME_BAD_EXT_IN_OBFUSCATED_ARCHIVE",
            "Archive vừa obfuscation vừa chứa extension nguy hiểm",
            {"dangerous": dangerous_files[:5], "obfuscated": obfuscated_archives[:5]},
        )

    if generic_split_rar and any(f.lower().endswith((".exe", ".scr", ".js")) for f in attachments):
        add_rule(
            "MIME_EXE_IN_GEN_SPLIT_RAR",
            "Có split RAR generic và file thực thi",
            {"split_parts": generic_split_rar[:5], "attachments": attachments[:5]},
        )

    if len(archive_like_names) >= 2 and any(name.lower().endswith(tuple(ARCHIVE_EXTENSIONS)) for name in archive_like_names):
        add_rule("MIME_ARCHIVE_IN_ARCHIVE", "Có nhiều archive đáng ngờ trong cùng mail", archive_like_names[:5])

    if bad_attachment_mime:
        add_rule("MIME_BAD_ATTACHMENT", "MIME type file đính kèm không tự nhiên", bad_attachment_mime[:5])

    if pdf_suspicious:
        add_rule("PDF_SUSPICIOUS", f"PDF có dấu hiệu đáng ngờ ({len(pdf_suspicious)})", pdf_suspicious[:5])

    if pdf_encrypted:
        add_rule("PDF_ENCRYPTED", f"PDF có Encrypt ({len(pdf_encrypted)})", pdf_encrypted[:5])

    if pdf_javascript:
        add_rule("PDF_JAVASCRIPT", f"PDF có JavaScript ({len(pdf_javascript)})", pdf_javascript[:5])

    if dangerous_files or phishy_attach:
        add_rule(
            "PHISH_ATTACH",
            f"Có attachment nguy hiểm / giống mẫu phishing ({len(set(dangerous_files + phishy_attach))})",
            list(dict.fromkeys(dangerous_files + phishy_attach))[:5],
        )

    html_lower = (html_body or "").lower()
    if "<form" in html_lower or 'type="password"' in html_lower or "type='password'" in html_lower:
        add_rule("FORM_FRAUD", "Email chứa HTML form / password field có thể nhằm thu thập thông tin", True, bucket="behavior", semantic_key="html_form_credential")
        add_rule("PHISHING", "Email chứa HTML form/password field", True, bucket="behavior", semantic_key="html_form_credential")

    if len(received_headers) == 1:
        rh = received_headers[0].lower()
        if any(x in rh for x in ["unknown", "localhost", "[127.0.0.1]", "helo=", "dynamic", "pppoe"]):
            add_rule("ONCE_RECEIVED_STRICT", "Chỉ có 1 Received và pattern đáng ngờ", received_headers[:1])

    joined_received = "\n".join(received_headers).lower()
    if "helo=" in joined_received and not re.search(r"helo=[A-Za-z0-9.-]+\.[A-Za-z]{2,}", joined_received):
        add_rule("HFILTER_HELO_NOT_FQDN", "HELO không phải FQDN", received_headers[:3])

    if re.search(r"helo=(?:\[)?(?:\d{1,3}\.){3}\d{1,3}(?:\])?", joined_received):
        add_rule("HFILTER_HELO_BADIP", "HELO dùng IP thay vì hostname", received_headers[:3])

    if "unknown" in joined_received or "no rdns" in joined_received or "rdns none" in joined_received:
        add_rule("RDNS_NONE", "Có dấu hiệu thiếu RDNS", received_headers[:3])
        add_rule("HFILTER_HOSTNAME_UNKNOWN", "Hostname không xác định", received_headers[:3])

    if sender_domain and is_freemail_domain(sender_domain) and any(w in combined_text for w in LOGINISH_KEYWORDS) and len(received_headers) <= 1:
        add_rule(
            "ABUSE_FROM_INJECTOR",
            "Freemail + login lure + đường truyền header nghèo nàn",
            {"sender_domain": sender_domain, "received_count": len(received_headers)},
        )

    matched_openphish = [u for u in lower_urls if u in feeds["openphish"] or hostname_from_url(u) in feeds["openphish"]]
    matched_phishtank = [u for u in lower_urls if u in feeds["phishtank"] or hostname_from_url(u) in feeds["phishtank"]]
    matched_dbl_phish = [u for u in lower_urls if hostname_from_url(u) in feeds["dbl_phish"]]
    matched_dbl_abuse = [u for u in lower_urls if hostname_from_url(u) in feeds["dbl_abuse_phish"]]
    matched_uribl_black = [u for u in lower_urls if hostname_from_url(u) in feeds["uribl_black"]]
    matched_uribl_grey = [u for u in lower_urls if hostname_from_url(u) in feeds["uribl_grey"]]

    sender_in_drop = sender_domain in feeds["spamhaus_drop"] or return_path_domain in feeds["spamhaus_drop"]
    sender_in_blocklistde = sender_domain in feeds["blocklistde"] or return_path_domain in feeds["blocklistde"]
    recv_drop = any(IP_RE.search(h or "") and any(ip in feeds["spamhaus_drop"] for ip in IP_RE.findall(h)) for h in received_headers)
    recv_block = any(IP_RE.search(h or "") and any(ip in feeds["blocklistde"] for ip in IP_RE.findall(h)) for h in received_headers)

    if matched_openphish:
        add_rule("PHISHED_OPENPHISH", "URL khớp feed OpenPhish", matched_openphish[:5])
    if matched_phishtank:
        add_rule("PHISHED_PHISHTANK", "URL khớp feed PhishTank", matched_phishtank[:5])
    if matched_dbl_phish:
        add_rule("DBL_PHISH", "Domain khớp feed DBL phish", matched_dbl_phish[:5])
        add_rule("URIBL_DBL_PHISH", "Domain/URL nằm trong blocklist phishing", matched_dbl_phish[:5])
    if matched_dbl_abuse:
        add_rule("DBL_ABUSE_PHISH", "Domain khớp feed abused legit phish", matched_dbl_abuse[:5])
    if matched_uribl_black:
        add_rule("URIBL_BLACK", "Domain khớp URIBL black", matched_uribl_black[:5])
    if matched_uribl_grey:
        add_rule("URIBL_GREY", "Domain khớp URIBL grey", matched_uribl_grey[:5])
    if matched_dbl_phish or matched_openphish or matched_phishtank:
        add_rule(
            "PH_SURBL_MULTI",
            "Domain/URL bị nhiều feed phishing đánh dấu",
            {"dbl": matched_dbl_phish[:5], "openphish": matched_openphish[:5], "phishtank": matched_phishtank[:5]},
        )
    if sender_in_drop:
        add_rule("RBL_SPAMHAUS_DROP", "From/Return-Path nằm trong Spamhaus DROP feed", {"sender_domain": sender_domain, "return_path_domain": return_path_domain})
    if recv_drop:
        add_rule("RECEIVED_SPAMHAUS_DROP", "Received chain có IP nằm trong Spamhaus DROP feed", received_headers[:3])
    if sender_in_blocklistde:
        add_rule("RBL_BLOCKLISTDE", "From/Return-Path nằm trong Blocklist.de feed", {"sender_domain": sender_domain, "return_path_domain": return_path_domain})
    if recv_block:
        add_rule("RECEIVED_BLOCKLISTDE", "Received chain có IP nằm trong Blocklist.de feed", received_headers[:3])

    if not sender_domain:
        add_rule("BAD_FROM_HEADER", "Header From bất thường hoặc không parse được email thật", sender_header)

    paypal_theme = any(k in combined_text for k in ["paypal", "webscr", "billing agreement", "payment sent", "invoice"])
    paypal_bad_sender = paypal_theme and sender_domain and not domain_matches_any(sender_domain, PAYPAL_DOMAINS)
    paypal_bad_urls = [u for u in urls if "paypal" in u.lower() and not domain_matches_any(hostname_from_url(u), PAYPAL_DOMAINS)]
    if paypal_bad_sender or paypal_bad_urls:
        add_rule("FROM_PAYPAL_SPOOF", "Email mang chủ đề PayPal nhưng sender/link không thuộc PayPal", {"sender_domain": sender_domain, "bad_urls": paypal_bad_urls[:5]}, bucket="identity", semantic_key="paypal_spoof")
        add_rule("PHISHING", "Email mang chủ đề PayPal nhưng sender/link không thuộc PayPal", {"sender_domain": sender_domain, "bad_urls": paypal_bad_urls[:5]}, bucket="behavior", semantic_key="paypal_spoof")

    risk_tokens = [k for k in ["limited", "confirm", "verify", "suspended", "security alert", "unauthorized"] if k in combined_text]
    if paypal_theme and risk_tokens and not hard_trusted_brand and (paypal_bad_sender or paypal_bad_urls or identity_conflict or auth_weak):
        add_rule("PAYPAL_PHISH_06", "Heuristic PayPal-themed phishing variant", {"tokens": risk_tokens[:5]}, bucket="behavior")
    if paypal_theme and (len(risk_tokens) >= 2 or paypal_bad_urls) and not hard_trusted_brand and (paypal_bad_sender or paypal_bad_urls or identity_conflict or auth_weak):
        add_rule("PAYPAL_PHISH_07", "Heuristic PayPal-themed phishing variant mạnh hơn", {"tokens": risk_tokens[:5], "urls": paypal_bad_urls[:3]}, bucket="behavior")

    if looks_like_gov_claim(display_name, combined_text):
        if sender_domain and not is_government_domain(sender_domain):
            add_rule("FROM_GOV_SPOOF", f"Người gửi có vẻ mạo danh cơ quan nhà nước nhưng domain không phải gov ({sender_domain})", {"sender_domain": sender_domain, "display_name": display_name}, bucket="identity", semantic_key="gov_spoof")
            add_rule("PHISHING", "Email có vẻ mạo danh cơ quan nhà nước", {"sender_domain": sender_domain, "display_name": display_name}, bucket="behavior", semantic_key="gov_spoof")

    if (
        (brand_hits or spoofed_sender)
        and (reply_domain and sender_domain and not related_domains(sender_domain, reply_domain))
        and (loginish_links or mismatched_anchor or redirector_urls)
    ):
        add_rule(
            "META_CREDENTIAL_THEFT",
            "Brand spoof + Reply-To lệch + URL/login lure",
            {
                "brand_hits": brand_hits,
                "reply_domain": reply_domain,
                "sender_domain": sender_domain,
            },
        )

    if brand_hits and is_freemail_domain(sender_domain) and (
        strong_claim_context
        or spoofed_sender
        or has_display_email_mismatch
        or bool(brand_rel.get("click_miss_brands"))
        or bool(mismatched_anchor)
        or bool(opaque_brand_targets)
        or align.get("sender_authenticated")
        or auth_weak
    ):
        add_rule(
            "META_BRAND_SPOOF_HIGH",
            "Brand spoof mức cao: freemail thật nhưng claim brand khác, hoặc link hiển thị đánh lừa người dùng",
            {
                "brand_hits": brand_hits,
                "sender_domain": sender_domain,
                "auth": auth,
                "brand_relationship": brand_rel,
                "mismatched_anchor": mismatched_anchor[:5],
                "opaque_brand_targets": opaque_brand_targets[:5],
                "spoof_info": spoof_info,
                "display_email_hits": display_email_hits,
                "actual_from_email": actual_from_email,
            },
        )

    if mismatched_anchor and (redirector_urls or short_links or google_redirect_abuse):
        add_rule(
            "META_LINK_SWAP",
            "Link hiển thị khác link thật + redirector/shortener",
            {"mismatch": mismatched_anchor[:5], "redirectors": redirector_urls[:5], "shorteners": short_links[:5]},
        )

    if (dangerous_files or phishy_attach or pdf_suspicious) and any(k in combined_text for k in ["invoice", "payment", "bill", "statement", "quotation", "document"]):
        add_rule("META_ATTACHMENT_TRAP", "Attachment lure + chủ đề tài liệu/thanh toán", {"attachments": attachments[:5], "subject": subject})

    if looks_like_gov_claim(display_name, combined_text) and sender_domain and not is_government_domain(sender_domain) and auth.get("dmarc") in {"fail", "none", "unknown"}:
        add_rule("META_GOV_SPOOF", "Gov claim + non-gov domain + auth yếu", {"display_name": display_name, "sender_domain": sender_domain, "auth": auth})

    qr_hits = [k for k in QR_PHISH_HINTS if k in combined_text]
    if qr_hits and (pdf_suspicious or len(urls) <= 1 or any(k in combined_text for k in LOGINISH_KEYWORDS)):
        add_rule("META_QR_PHISH", "Có dấu hiệu QR phishing", {"qr_hits": qr_hits, "urls": urls[:3], "attachments": attachments[:3]})

    if pdf_suspicious and (len(urls) <= 1 or any(k in combined_text for k in LOGINISH_KEYWORDS) or qr_hits):
        add_rule("META_PDF_PHISH", "PDF đáng ngờ + call to action login/verify/scan", {"pdf": pdf_suspicious[:5], "urls": urls[:3]})

    if any(k in combined_text for k in BEC_HINTS) and not urls and not attachments and (reply_domain and sender_domain and not related_domains(sender_domain, reply_domain)):
        add_rule("META_BEC", "Nội dung có dấu hiệu BEC / payment fraud", {"subject": subject, "reply_domain": reply_domain, "sender_domain": sender_domain})

    if likely_thread_hijack(subject, visible_text, urls, attachments):
        add_rule("META_THREAD_HIJACK", "Tiêu đề dạng thread nhưng body ngắn và có lure", {"subject": subject, "urls": urls[:3], "attachments": attachments[:3]})

    if hard_trusted_brand:
        severe_symbols = {
            "BRAND_IMPERSONATION", "CLICK_DOMAIN_OFF_BRAND", "VISIBLE_TEXT_URL_MISMATCH", "FORM_FRAUD", "PHISH_ATTACH",
            "PHISHED_OPENPHISH", "PHISHED_PHISHTANK", "DBL_PHISH", "URIBL_DBL_PHISH", "GOOG_REDIR_FRAUD", "URL_IP_LITERAL",
            "URL_HOMOGRAPH_ATTACK", "META_BRAND_SPOOF_HIGH", "META_CREDENTIAL_THEFT", "FROM_GOV_SPOOF", "FROM_PAYPAL_SPOOF"
        }
        severe_hits = {r["rule"] for r in fired_rules if r["rule"] in severe_symbols}
        if not severe_hits:
            capped = min(raw_score, 2.5)
            if capped != raw_score:
                evidence["trusted_brand_score_cap"] = {"before": round(raw_score, 2), "after": round(capped, 2)}
                raw_score = capped

    if brand_hits and is_freemail_domain(sender_domain) and strong_claim_context:
        spoof_floor = 22.0 if (has_display_email_mismatch or spoofed_sender or bool(click_brand_miss) or bool(mismatched_anchor) or bool(opaque_brand_targets) or align.get("sender_authenticated")) else 16.0
        if raw_score < spoof_floor:
            evidence["brand_spoof_floor"] = {"before": round(raw_score, 2), "after": round(spoof_floor, 2)}
            raw_score = spoof_floor

    raw_score = max(0.0, raw_score)
    scaled_score = min(100, int(round(raw_score * 4.0)))

    if scaled_score >= 85:
        label = "🛑 CỰC KỲ NGUY HIỂM"
    elif scaled_score >= 70:
        label = "🚨 NGUY HIỂM"
    elif scaled_score >= 35:
        label = "⚠️ ĐÁNG NGỜ"
    else:
        label = "✅ TẠM AN TOÀN"

    evidence["all_urls"] = urls
    evidence["url_debug"] = email_dict.get("url_debug", {})
    evidence["fired_rules"] = fired_rules
    evidence["sender_domain"] = sender_domain
    evidence["sender_email"] = sender_email
    evidence["reply_domain"] = reply_domain
    evidence["return_path_domain"] = return_path_domain
    evidence["claimed_brands_all"] = claimed_brands_all
    evidence["bucket_scores"] = {k: round(v, 2) for k, v in bucket_scores.items()}
    evidence["raw_score"] = round(raw_score, 2)
    evidence["scaled_score"] = scaled_score
    evidence["feed_stats"] = {k: len(v) for k, v in feeds.items()}
    evidence["attachment_meta"] = attachment_meta
    evidence["top_rules"] = [r["rule"] for r in sorted(fired_rules, key=lambda x: x["delta"], reverse=True)[:8]]

    evidence["attack_types"] = detect_attack_types(scaled_score, evidence)
    high_hits = len([r for r in fired_rules if r["delta"] >= 4])
    evidence["confidence"] = "High" if scaled_score >= 70 or high_hits >= 3 else "Medium" if scaled_score >= 35 else "Low"

    return scaled_score, label, issues, evidence



def _scan_one_email_row(em: Dict, enable_online_checks: bool) -> Dict:
    sc, lbl, iss, ev = analyze_email(em, enable_online_checks=enable_online_checks)
    return {
        "ID": em["id"],
        "Fetch order": em.get("fetch_order", 0),
        "gmail_msgid": em.get("gmail_msgid", ""),
        "gmail_thrid": em.get("gmail_thrid", ""),
        "Thời gian": em["date"],
        "Trạng thái": lbl,
        "Điểm": sc,
        "Raw score": ev.get("raw_score", 0),
        "Confidence": ev.get("confidence", "Low"),
        "Attack type": ", ".join(ev.get("attack_types", [])),
        "Người gửi": em["sender"],
        "Reply-To": em["reply_to"],
        "Tiêu đề": em["subject"],
        "Số URL": len(em["urls"]),
        "Số file đính kèm": len(em["attachments"]),
        "Rules kích hoạt": ", ".join([r["rule"] for r in ev.get("fired_rules", [])]),
        "Chi tiết vi phạm": " | ".join(iss),
    }

def scan_all_emails(emails_data: List[Dict], enable_online_checks: bool):
    rows = []

    if emails_data:
        max_workers = min(8, len(emails_data), max(2, (os.cpu_count() or 4)))
        if len(emails_data) <= 2:
            max_workers = 1

        if max_workers <= 1:
            for em in emails_data:
                rows.append(_scan_one_email_row(em, enable_online_checks=enable_online_checks))
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for row in executor.map(lambda em: _scan_one_email_row(em, enable_online_checks=enable_online_checks), emails_data):
                    rows.append(row)

    if not rows:
        return pd.DataFrame(columns=[
            "ID", "Fetch order", "gmail_msgid", "gmail_thrid", "Thời gian", "Trạng thái", "Điểm", "Raw score", "Confidence", "Attack type",
            "Người gửi", "Reply-To", "Tiêu đề", "Số URL", "Số file đính kèm",
            "Rules kích hoạt", "Chi tiết vi phạm"
        ])

    # Giữ nguyên thứ tự fetch từ mailbox để frontend bind đúng hàng hơn.
    return pd.DataFrame(rows).sort_values(by=["Fetch order"], ascending=[True])