"""Context-aware recommendation engine for affiliate solutions.

Maps detected vulnerabilities to affiliate solutions with basic A/B testing support.
"""
from typing import Any, Dict, List, Optional
import itertools
import hashlib
from urllib.parse import urlparse

from config.affiliates import (
    AFFILIATE_LINKS,
    VULNERABILITY_TO_SOLUTIONS,
    AB_VARIANTS,
    DEFAULT_DISCLOSURE,
)


def _normalize_vuln_key(vuln_type: str) -> str:
    return vuln_type.lower().replace(" ", "_").replace("-", "_")


def _detect_site_profile(url: Optional[str], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Lightweight heuristics to tailor recommendations."""
    profile = {"is_wordpress": False, "is_ecommerce": False, "size": "small"}

    if url:
        lowered = url.lower()
        if "wp-" in lowered or "wordpress" in lowered:
            profile["is_wordpress"] = True
        if any(token in lowered for token in ["/cart", "/checkout", "shop.", "store."]):
            profile["is_ecommerce"] = True

    # Check vulnerability details for hints
    for vuln in vulnerabilities:
        details = vuln.get("details", {}) or {}
        detail_str = str(details).lower()
        if "wp-content" in detail_str or "wp-admin" in detail_str:
            profile["is_wordpress"] = True
        if "checkout" in detail_str or "cart" in detail_str:
            profile["is_ecommerce"] = True

    return profile


def _choose_ab_variant(ab_key: Optional[str]) -> Optional[str]:
    if not ab_key or ab_key not in AB_VARIANTS:
        return None
    variants = AB_VARIANTS[ab_key]
    # Deterministic rotate based on hash for consistency per session
    idx = int(hashlib.md5(ab_key.encode()).hexdigest(), 16) % len(variants)
    return variants[idx]


def _build_solution_entry(solution_key: str, vuln_type: str, cta: str, priority: int, profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    affiliate = AFFILIATE_LINKS.get(solution_key)
    if not affiliate:
        return None

    # Filter context
    if profile.get("is_wordpress") is False and solution_key == "wordfence":
        return None

    entry = {
        "solution_key": solution_key,
        "name": affiliate.get("name", solution_key.title()),
        "url": affiliate["url"],
        "description": affiliate.get("description", "Recommended fix"),
        "badges": affiliate.get("badges", []),
        "tier": affiliate.get("tier", ""),
        "commission": affiliate.get("commission", ""),
        "cta": cta,
        "priority": priority,
        "vulnerability": vuln_type,
        "disclosure": DEFAULT_DISCLOSURE,
    }
    return entry


def build_recommendations(
    vulnerabilities: List[Dict[str, Any]],
    url: Optional[str] = None,
    ab_variant: Optional[str] = None,
) -> Dict[str, Any]:
    """Return recommendations and disclosure text."""
    profile = _detect_site_profile(url, vulnerabilities)

    candidates: List[Dict[str, Any]] = []
    seen = set()

    for vuln in vulnerabilities:
        vuln_key = _normalize_vuln_key(vuln.get("type", ""))
        solutions = VULNERABILITY_TO_SOLUTIONS.get(vuln_key, [])
        for sol in solutions:
            sol_key = sol["solution"]
            chosen_variant = _choose_ab_variant(ab_variant) if ab_variant else None
            final_key = chosen_variant or sol_key
            entry = _build_solution_entry(final_key, vuln.get("type", ""), sol.get("cta", "Fix now"), sol.get("priority", 99), profile)
            if not entry:
                continue
            dedupe_key = (final_key, vuln_key)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            candidates.append(entry)

    # Add general upsell for our services if nothing else
    if not any(c["solution_key"] == "freelance_services" for c in candidates):
        entry = _build_solution_entry(
            "freelance_services",
            "General Hardening",
            "Book our team to fix and harden everything",
            priority=99,
            profile=profile,
        )
        if entry:
            candidates.append(entry)

    sorted_candidates = sorted(candidates, key=lambda c: (c["priority"], c.get("tier", "z")))

    return {
        "disclosure": DEFAULT_DISCLOSURE,
        "profile": profile,
        "items": sorted_candidates,
    }
