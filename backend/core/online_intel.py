from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List

from config import ONLINE_LOOKUP_TIMEOUT
from core.auth_utils import compute_auth_alignment
from core.brand_utils import classify_brand_relationship
from core.feed_utils import get_brand_allowlist

try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver
except Exception:
    dns = None


@lru_cache(maxsize=512)
def get_domain_dns_profile(domain: str) -> Dict:
    out = {
        "domain": domain,
        "has_mx": False,
        "has_spf": False,
        "has_dmarc": False,
        "spf_records": [],
        "dmarc_records": [],
        "error": "",
    }

    if not domain or dns is None:
        return out

    try:
        mx = dns.resolver.resolve(domain, "MX")
        out["has_mx"] = bool(mx)
    except Exception:
        pass

    try:
        txt = dns.resolver.resolve(domain, "TXT")
        spf = []
        for r in txt:
            val = b"".join(r.strings).decode("utf-8", errors="ignore")
            if val.lower().startswith("v=spf1"):
                spf.append(val)
        if spf:
            out["has_spf"] = True
            out["spf_records"] = spf[:5]
    except Exception:
        pass

    try:
        txt = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = []
        for r in txt:
            val = b"".join(r.strings).decode("utf-8", errors="ignore")
            if val.lower().startswith("v=dmarc1"):
                dmarc.append(val)
        if dmarc:
            out["has_dmarc"] = True
            out["dmarc_records"] = dmarc[:5]
    except Exception:
        pass

    return out


@lru_cache(maxsize=512)
def get_domain_rdap_profile(domain: str) -> Dict:
    out = {
        "domain": domain,
        "ok": False,
        "registrar": "",
        "created": "",
        "updated": "",
        "days_old": None,
        "error": "",
    }

    if not domain or requests is None:
        return out

    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=ONLINE_LOOKUP_TIMEOUT)
        if resp.status_code != 200:
            out["error"] = f"HTTP {resp.status_code}"
            return out

        data = resp.json()
        out["ok"] = True

        entities = data.get("entities", []) or []
        registrar = ""
        for ent in entities:
            roles = [r.lower() for r in ent.get("roles", [])]
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if isinstance(vcard, list) and len(vcard) >= 2:
                    for item in vcard[1]:
                        if len(item) >= 4 and item[0] == "fn":
                            registrar = str(item[3])
                            break
        out["registrar"] = registrar

        created = ""
        updated = ""
        for ev in data.get("events", []) or []:
            action = (ev.get("eventAction") or "").lower()
            date = ev.get("eventDate") or ""
            if action in {"registration", "registered"} and not created:
                created = date
            if action in {"last changed", "last update of rdap database", "expiration"} and not updated:
                updated = date

        out["created"] = created
        out["updated"] = updated

        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                out["days_old"] = max(0, (now - dt).days)
            except Exception:
                pass

        return out

    except Exception as e:
        out["error"] = str(e)
        return out


def collect_online_brand_intel(
    email_dict: Dict,
    sender_domain: str,
    return_path_domain: str,
    url_hosts: List[str],
    auth: Dict,
) -> Dict:
    from core.brand_utils import infer_claimed_brands

    allowlist = get_brand_allowlist()
    sender_email = (email_dict.get("sender_email") or "").lower().strip()

    claimed_brands = infer_claimed_brands(
        email_dict.get("sender", ""),
        email_dict.get("subject", ""),
        email_dict.get("body_preview", ""),
        html_body=email_dict.get("body_html", ""),
        anchor_pairs=email_dict.get("anchor_pairs", []),
    )

    brand_rel = classify_brand_relationship(
        claimed_brands,
        sender_domain,
        url_hosts,
        allowlist,
        sender_email=sender_email,
    )

    align = compute_auth_alignment(sender_domain, return_path_domain, auth)
    sender_dns = get_domain_dns_profile(sender_domain) if sender_domain else {}
    sender_rdap = get_domain_rdap_profile(sender_domain) if sender_domain else {}

    click_intel = []
    for host in sorted(set(url_hosts[:10])):
        click_intel.append(
            {
                "host": host,
                "dns": get_domain_dns_profile(host),
                "rdap": get_domain_rdap_profile(host),
            }
        )

    return {
        "claimed_brands": claimed_brands,
        "brand_relationship": brand_rel,
        "auth_alignment": align,
        "sender_dns": sender_dns,
        "sender_rdap": sender_rdap,
        "click_intel": click_intel,
    }