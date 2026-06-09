import csv
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

from config import BRAND_ALLOWLIST_PATH
from constants import DEFAULT_BRAND_ALLOWLIST_ROWS, FEED_FILES
from core.url_utils import clean_url_candidate, hostname_from_url


@lru_cache(maxsize=128)
def _load_text_feed_cached(path_str: str, mtime: float) -> tuple:
    path = Path(path_str)
    if not path.exists():
        return tuple()

    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return tuple(out)


def load_text_feed(path_str: str) -> List[str]:
    return list(_load_text_feed_cached(path_str, get_file_mtime(path_str)))


@lru_cache(maxsize=16)
def _load_all_feeds_cached(feed_signature: tuple) -> Dict[str, frozenset]:
    feeds: Dict[str, frozenset] = {}
    for name, path_str, _mtime in feed_signature:
        items = set()
        for line in load_text_feed(path_str):
            line = line.strip()
            if "://" in line:
                host = hostname_from_url(line)
                if host:
                    items.add(host)
                items.add(clean_url_candidate(line).lower())
            else:
                items.add(line.lower())
        feeds[name] = frozenset(items)
    return feeds


def load_all_feeds() -> Dict[str, frozenset]:
    feed_signature = tuple(
        (name, str(path), get_file_mtime(str(path)))
        for name, path in sorted(FEED_FILES.items())
    )
    return _load_all_feeds_cached(feed_signature)


def ensure_default_brand_allowlist():
    if BRAND_ALLOWLIST_PATH.exists():
        return
    with open(BRAND_ALLOWLIST_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerows(DEFAULT_BRAND_ALLOWLIST_ROWS)


def get_file_mtime(path_str: str) -> float:
    try:
        return Path(path_str).stat().st_mtime
    except Exception:
        return 0.0


@lru_cache(maxsize=16)
def _load_brand_allowlist_cached(path_str: str, file_mtime: float) -> tuple:
    path = Path(path_str)
    data: Dict[str, Dict[str, set]] = {}

    if not path.exists():
        return tuple()

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(1024)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            brand = (row.get("brand") or "").strip().lower()
            usage = (row.get("usage") or "").strip().lower()
            match_type = (row.get("match_type") or "domain").strip().lower()
            value = (row.get("value") or "").strip().lower()
            aliases_raw = (row.get("aliases") or "").strip().lower()

            if not brand or not usage or not value:
                continue

            if usage not in {"sender", "link"}:
                continue

            if match_type not in {"domain", "exact_domain", "exact_email"}:
                match_type = "domain"

            bucket = data.setdefault(
                brand,
                {
                    "sender_domain": set(),
                    "sender_exact_domain": set(),
                    "sender_exact_email": set(),
                    "link_domain": set(),
                    "link_exact_domain": set(),
                    "aliases": set(),
                },
            )

            if usage == "sender":
                if match_type == "domain":
                    bucket["sender_domain"].add(value)
                elif match_type == "exact_domain":
                    bucket["sender_exact_domain"].add(value)
                elif match_type == "exact_email":
                    bucket["sender_exact_email"].add(value)
            elif usage == "link":
                if match_type == "domain":
                    bucket["link_domain"].add(value)
                else:
                    bucket["link_exact_domain"].add(value)

            bucket["aliases"].add(brand)

            if aliases_raw:
                for alias in re.split(r"[|,;]", aliases_raw):
                    alias = alias.strip().lower()
                    if alias:
                        bucket["aliases"].add(alias)

    for brand, bucket in data.items():
        bucket.setdefault("sender_domain", set())
        bucket.setdefault("sender_exact_domain", set())
        bucket.setdefault("sender_exact_email", set())
        bucket.setdefault("link_domain", set())
        bucket.setdefault("link_exact_domain", set())
        bucket.setdefault("aliases", set()).add(brand)

    frozen = []
    for brand, bucket in data.items():
        frozen.append(
            (
                brand,
                {
                    "sender_domain": tuple(sorted(bucket["sender_domain"])),
                    "sender_exact_domain": tuple(sorted(bucket["sender_exact_domain"])),
                    "sender_exact_email": tuple(sorted(bucket["sender_exact_email"])),
                    "link_domain": tuple(sorted(bucket["link_domain"])),
                    "link_exact_domain": tuple(sorted(bucket["link_exact_domain"])),
                    "aliases": tuple(sorted(bucket["aliases"])),
                },
            )
        )
    return tuple(frozen)


def load_brand_allowlist(path_str: str, file_mtime: float) -> Dict[str, Dict[str, set]]:
    raw = _load_brand_allowlist_cached(path_str, file_mtime)
    out: Dict[str, Dict[str, set]] = {}
    for brand, bucket in raw:
        out[brand] = {
            "sender_domain": set(bucket["sender_domain"]),
            "sender_exact_domain": set(bucket["sender_exact_domain"]),
            "sender_exact_email": set(bucket["sender_exact_email"]),
            "link_domain": set(bucket["link_domain"]),
            "link_exact_domain": set(bucket["link_exact_domain"]),
            "aliases": set(bucket["aliases"]),
        }
    return out


def get_brand_allowlist() -> Dict[str, Dict[str, set]]:
    return load_brand_allowlist(
        str(BRAND_ALLOWLIST_PATH),
        get_file_mtime(str(BRAND_ALLOWLIST_PATH)),
    )


import re

ensure_default_brand_allowlist()