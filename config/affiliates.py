"""Centralized affiliate configuration and vulnerability-to-solution mapping.

Notes:
- Replace placeholder affiliate IDs (e.g., YOUR_ID) with real tracking codes.
- UTM parameters default to source=vulnscan and medium=recommendation.
- Designed to be imported by recommendation_engine.
"""
from typing import Dict, List

AFFILIATE_LINKS: Dict[str, Dict[str, str]] = {
    "cloudflare": {
        "name": "Cloudflare",
        "url": "https://www.cloudflare.com/partners/?ref=YOUR_ID&utm_source=vulnscan&utm_medium=recommendation&utm_campaign=ssl",
        "commission": "$50-300 per sale",
        "tier": "primary",
        "description": "Free SSL, CDN, and DDoS protection with easy setup",
        "badges": ["Top Pick", "Free Tier"],
    },
    "namecheap_ssl": {
        "name": "Namecheap SSL",
        "url": "https://www.namecheap.com/affiliates/?aff=YOUR_ID&utm_source=vulnscan&utm_medium=recommendation",
        "commission": "20-25% per sale",
        "tier": "secondary",
        "description": "Affordable SSL certificates with strong brand trust",
        "badges": ["Budget Friendly"],
    },
    "letsencrypt": {
        "name": "Let's Encrypt",
        "url": "https://letsencrypt.org/",
        "commission": "Free (credibility)",
        "tier": "free",
        "description": "Completely free SSL certificates backed by major sponsors",
        "badges": ["Free", "Trusted"],
    },
    "sucuri": {
        "name": "Sucuri",
        "url": "https://sucuri.net/affiliate-program/?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "$50-210 per sale",
        "tier": "primary",
        "description": "Website firewall + malware removal. Great for XSS/headers issues.",
        "badges": ["WAF", "Malware Cleanup"],
    },
    "wordfence": {
        "name": "Wordfence",
        "url": "https://www.wordfence.com/affiliates/?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "20% recurring",
        "tier": "secondary",
        "description": "Leading WordPress security plugin with firewall + malware scan",
        "badges": ["WordPress"],
    },
    "hackerone": {
        "name": "HackerOne",
        "url": "https://www.hackerone.com/contact?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "Referral / partnership",
        "tier": "service",
        "description": "Bug bounty program setup for continuous security testing",
        "badges": ["Enterprise"],
    },
    "bugcrowd": {
        "name": "Bugcrowd",
        "url": "https://www.bugcrowd.com/contact/?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "Referral",
        "tier": "service",
        "description": "Managed crowdsourced security testing",
        "badges": ["Enterprise"],
    },
    "bluehost": {
        "name": "Bluehost",
        "url": "https://www.bluehost.com/track/YOUR_ID/?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "$65+ per sale",
        "tier": "hosting",
        "description": "Reliable hosting with free SSL and support",
        "badges": ["Hosting"],
    },
    "siteground": {
        "name": "SiteGround",
        "url": "https://www.siteground.com/go/YOUR_ID?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "$50-100 per sale",
        "tier": "hosting",
        "description": "Performance-focused hosting with strong security defaults",
        "badges": ["Hosting", "Performance"],
    },
    "wpengine": {
        "name": "WP Engine",
        "url": "https://shareasale.com/r.cfm?b=394686&u=YOUR_ID&m=41388&utm_source=vulnscan&utm_medium=recommendation",
        "commission": "$200+ per sale",
        "tier": "premium",
        "description": "Managed WordPress hosting with enterprise-grade security",
        "badges": ["Managed WP"],
    },
    "bunnycdn": {
        "name": "BunnyCDN",
        "url": "https://bunnycdn.com/partners?ref=YOUR_ID&utm_source=vulnscan&utm_medium=recommendation",
        "commission": "20% recurring",
        "tier": "cdn",
        "description": "Affordable CDN to accelerate and secure assets",
        "badges": ["CDN"],
    },
    "qualys_ssl": {
        "name": "Qualys SSL Labs",
        "url": "https://www.ssllabs.com/ssltest/",
        "commission": "Free (credibility)",
        "tier": "trust",
        "description": "Free SSL test to validate your fixes",
        "badges": ["Validation"],
    },
    "freelance_services": {
        "name": "Book Our Team",
        "url": "https://calendly.com/your-calendly/30min?utm_source=vulnscan&utm_medium=recommendation",
        "commission": "Direct booking",
        "tier": "service",
        "description": "Book our team to fix and harden your site end-to-end",
        "badges": ["Done-For-You"],
    },
}

VULNERABILITY_TO_SOLUTIONS: Dict[str, List[Dict[str, str]]] = {
    "no_https": [
        {"solution": "letsencrypt", "priority": 1, "cta": "Start free SSL with Let's Encrypt"},
        {"solution": "cloudflare", "priority": 2, "cta": "Enable Cloudflare SSL + CDN"},
        {"solution": "namecheap_ssl", "priority": 3, "cta": "Buy a trusted SSL from Namecheap"},
        {"solution": "sucuri", "priority": 4, "cta": "Add Sucuri WAF with SSL"},
    ],
    "missing_hsts": [
        {"solution": "cloudflare", "priority": 1, "cta": "Enforce HSTS with Cloudflare"},
        {"solution": "sucuri", "priority": 2, "cta": "Lock down transport security"},
    ],
    "missing_csp": [
        {"solution": "sucuri", "priority": 1, "cta": "Deploy Sucuri WAF to enforce CSP"},
        {"solution": "cloudflare", "priority": 2, "cta": "Add Cloudflare WAF rules"},
        {"solution": "wordfence", "priority": 3, "cta": "Harden WordPress with Wordfence"},
        {"solution": "freelance_services", "priority": 4, "cta": "Have us configure CSP for you"},
    ],
    "xss_vulnerability": [
        {"solution": "sucuri", "priority": 1, "cta": "Block XSS with Sucuri firewall"},
        {"solution": "cloudflare", "priority": 2, "cta": "Enable Cloudflare WAF managed rules"},
        {"solution": "wordfence", "priority": 3, "cta": "WordPress? Install Wordfence"},
        {"solution": "freelance_services", "priority": 4, "cta": "Let us patch and harden"},
    ],
    "exposed_env_file": [
        {"solution": "freelance_services", "priority": 1, "cta": "Urgent: book us to rotate secrets"},
        {"solution": "hackerone", "priority": 2, "cta": "Set up bounty intake"},
        {"solution": "bugcrowd", "priority": 3, "cta": "Crowdsourced testing program"},
    ],
    "directory_listing": [
        {"solution": "freelance_services", "priority": 1, "cta": "We can lock this down fast"},
        {"solution": "bluehost", "priority": 2, "cta": "Move to managed hosting with better defaults"},
        {"solution": "siteground", "priority": 3, "cta": "Upgrade hosting security"},
    ],
    "missing_security_headers": [
        {"solution": "cloudflare", "priority": 1, "cta": "Auto-set headers via Cloudflare"},
        {"solution": "sucuri", "priority": 2, "cta": "Managed firewall to enforce headers"},
        {"solution": "freelance_services", "priority": 3, "cta": "Let us configure headers correctly"},
    ],
}

AB_VARIANTS = {
    "ssl_primary": ["cloudflare", "namecheap_ssl"],
    "waf_stack": ["sucuri", "cloudflare"],
}

DEFAULT_DISCLOSURE = (
    "Affiliate Disclosure: We may earn a commission if you purchase through these links, "
    "at no extra cost to you. We always list free or low-cost fixes first."
)
