import re
from typing import Dict, List, Optional

from core.url_utils import related_domains


AUTH_RESULTS = ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")



def auth_summary(msg) -> Dict[str, str]:
    auth_results = " | ".join(msg.get_all("Authentication-Results", []))
    received_spf = " | ".join(msg.get_all("Received-SPF", []))
    raw = f"{auth_results} | {received_spf}".lower()

    def extract_result(name: str) -> str:
        m = re.search(
            rf"\b{name}=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            raw,
            flags=re.IGNORECASE,
        )
        if m:
            return m.group(1).lower()
        return "unknown"

    spf = extract_result("spf")
    dkim = extract_result("dkim")
    dmarc = extract_result("dmarc")
    arc = extract_result("arc")

    if spf == "unknown":
        low = received_spf.lower()
        for token in AUTH_RESULTS:
            if token in low:
                spf = token
                break

    if dmarc == "unknown" and "dmarc=" not in raw:
        dmarc = "none"

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "arc": arc,
        "raw": auth_results if auth_results else received_spf,
    }



def parse_auth_domains(auth: Dict) -> Dict[str, List[str]]:
    raw = (auth.get("raw") or "").lower()

    dkim_domains = set(re.findall(r"header\.d=([a-z0-9.\-]+\.[a-z]{2,})", raw))
    dkim_domains.update(re.findall(r"header\.i=@?([a-z0-9.\-]+\.[a-z]{2,})", raw))

    spf_domains = set()
    for value in re.findall(r"smtp\.mailfrom=([^;\s]+)", raw):
        cleaned = value.strip().strip("<>").lower()
        if "@" in cleaned:
            cleaned = cleaned.rsplit("@", 1)[1]
        if re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", cleaned):
            spf_domains.add(cleaned)

    from_domains = set(re.findall(r"header\.from=([a-z0-9.\-]+\.[a-z]{2,})", raw))

    return {
        "dkim_domains": sorted(dkim_domains),
        "spf_domains": sorted(spf_domains),
        "from_domains": sorted(from_domains),
    }



def _collect_authenticated_domains(parsed: Dict[str, List[str]], return_path_domain: str) -> List[str]:
    out = set()
    for key in ("dkim_domains", "spf_domains", "from_domains"):
        for domain in parsed.get(key, []):
            if domain:
                out.add(domain)
    if return_path_domain:
        out.add(return_path_domain.lower())
    return sorted(out)



def compute_auth_alignment(sender_domain: str, return_path_domain: str, auth: Dict) -> Dict:
    sender_domain = (sender_domain or "").lower().strip()
    return_path_domain = (return_path_domain or "").lower().strip()
    parsed = parse_auth_domains(auth)
    dkim_aligned = any(related_domains(sender_domain, d) for d in parsed["dkim_domains"])
    spf_aligned = any(related_domains(sender_domain, d) for d in parsed["spf_domains"])
    from_aligned = any(related_domains(sender_domain, d) for d in parsed["from_domains"])
    return_path_aligned = related_domains(sender_domain, return_path_domain) if sender_domain and return_path_domain else False

    sender_authenticated = bool(
        (auth.get("dkim") == "pass" and dkim_aligned)
        or (auth.get("spf") == "pass" and (spf_aligned or return_path_aligned))
        or (auth.get("dmarc") == "pass" and from_aligned)
    )

    strong = (
        auth.get("dmarc") == "pass"
        and (
            (auth.get("dkim") == "pass" and dkim_aligned)
            or (auth.get("spf") == "pass" and (spf_aligned or return_path_aligned))
        )
    )

    fail = (
        auth.get("dmarc") in {"fail", "none", "unknown"}
        and auth.get("dkim") in {"fail", "unknown"}
        and auth.get("spf") in {"fail", "softfail", "unknown"}
    )

    return {
        "parsed": parsed,
        "dkim_aligned": dkim_aligned,
        "spf_aligned": spf_aligned,
        "from_aligned": from_aligned,
        "return_path_aligned": return_path_aligned,
        "sender_authenticated": sender_authenticated,
        "strong_pass": strong,
        "clear_fail": fail,
        "authenticated_domains": _collect_authenticated_domains(parsed, return_path_domain),
        "auth_scope": "sender_domain_only",
        "auth_validates_sender_only": sender_authenticated,
        "does_not_validate_claimed_brand_directly": True,
    }



def summarize_authenticated_identity(
    sender_domain: str,
    return_path_domain: str,
    auth: Dict,
    brand_rel: Optional[Dict] = None,
) -> Dict:
    brand_rel = brand_rel or {}
    align = compute_auth_alignment(sender_domain, return_path_domain, auth)

    sender_miss = brand_rel.get("sender_miss_brands", []) or []
    sender_match = brand_rel.get("sender_match_brands", []) or []
    primary_claims = brand_rel.get("primary_claimed_brands", []) or brand_rel.get("claimed_brands", []) or []

    claim_matches_authenticated_sender = bool(primary_claims and not sender_miss and sender_match)
    auth_is_not_brand_proof = bool(align.get("sender_authenticated") and sender_miss)
    trustworthy_for_claimed_brand = bool(align.get("strong_pass") and claim_matches_authenticated_sender)

    align.update(
        {
            "sender_domain": (sender_domain or "").lower().strip(),
            "return_path_domain": (return_path_domain or "").lower().strip(),
            "primary_claimed_brands": primary_claims,
            "claim_matches_authenticated_sender": claim_matches_authenticated_sender,
            "auth_is_not_brand_proof": auth_is_not_brand_proof,
            "trustworthy_for_claimed_brand": trustworthy_for_claimed_brand,
            "authenticated_domain_count": len(align.get("authenticated_domains", [])),
        }
    )
    return align



def header_contains_plusall_hint(headers_preview: str) -> bool:
    joined = (headers_preview or "").lower()
    return "+all" in joined and "spf" in joined
