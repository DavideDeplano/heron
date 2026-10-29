"""Phishing indicators scoring functions."""

import re

from heron.models import ParsedEmail


W_REPLY_TO_MISMATCH = 2
W_AUTH_FAIL = 2
W_BRAND_MISMATCH = 3
W_PUNYCODE_LINK = 3
W_IP_LINK = 3
W_KEYWORD = 1
BRANDS = ["paypal", "microsoft", "amazon"]
KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

_IP_URL_RE = re.compile("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")


def keyword_score(email: ParsedEmail) -> int:
    """Assign one point for each keyword found in the email."""
    return sum(W_KEYWORD for kw in KEYWORDS if kw in email.text)


def link_score(email: ParsedEmail) -> int:
    """Assign points for links to IP addresses or punycode domain."""
    # links that look bad
    s = 0
    for u in email.links:
        if re.match(_IP_URL_RE, u):
            s = s + W_IP_LINK  # ip address url, very bad
        if "xn--" in u:  # punycode
            s = s + W_PUNYCODE_LINK
    return s


def brand_score(email: ParsedEmail) -> int:
    """Assign points when the sender says paypal/microsoft/amazon but domain
    is weird"""
    s = 0
    low = email.sender.lower()
    for brand in BRANDS:
        if brand in low and f"{brand}.com" not in low:
            s = s + W_BRAND_MISMATCH
    return s


def auth_score(email: ParsedEmail) -> int:
    """Assign points when SPF or DMARC failed."""
    if "spf=fail" in email.auth_results or "dmarc=fail" in email.auth_results:
         return W_AUTH_FAIL
    return 0


def reply_to_score(email: ParsedEmail) -> int:
    """Assign points when sender and reply-to fiels mismatch."""
    if (email.from_domain and email.reply_to_domain
        and email.from_domain != email.reply_to_domain):
        return W_REPLY_TO_MISMATCH
    return 0