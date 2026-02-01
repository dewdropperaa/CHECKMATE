"""Freelance booking configuration for in-house services."""
from typing import List, Dict

SERVICE_PACKAGES: List[Dict[str, str]] = [
    {
        "name": "Security Audit",
        "price": "$500-2000",
        "description": "Full penetration test, comprehensive report, remediation roadmap, 1-hour consultation",
        "cta": "Book Audit"
    },
    {
        "name": "Fix It For Me",
        "price": "$1000-5000",
        "description": "We fix all vulnerabilities, implement headers and SSL, and include 30 days of support",
        "cta": "Schedule Fix"
    },
    {
        "name": "Security Monitoring",
        "price": "$200-500/month",
        "description": "Weekly automated scans, immediate alerts, monthly reports, priority support",
        "cta": "Start Monitoring"
    },
    {
        "name": "White-Label Partnership",
        "price": "$1000-5000/month",
        "description": "Agencies resell our scanner while we power the tech and support",
        "cta": "Partner With Us"
    },
]

CALENDLY_LINK = "https://calendly.com/your-calendly/30min?utm_source=vulnscan&utm_medium=recommendation"
