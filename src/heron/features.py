"""Phishing indicators scoring functions."""

import re

from heron.parser import sender_domain


W_REPLY_TO_MISMATCH = 2
W_AUTH_FAIL = 2
W_BRAND_MISMATCH = 3
W_PUNYCODE_LINK = 3
W_IP_LINK = 3
W_KEYWORD = 1
BRANDS = ["paypal", "microsoft", "amazon"]
KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

_URL_RE = re.compile("https?://[^\\s\"'<>]+")
_IP_URL_RE = re.compile("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")


def keyword_score(raw):
    """Assign one point for each keyword found in the email."""
    low = raw.lower()
    return sum(W_KEYWORD for kw in KEYWORDS if kw in low)


def link_score(raw):
    """Assign points for links to IP addresses or punycode domain."""
    # links that look bad
    s = 0
    urls = re.findall(_URL_RE, raw)
    for u in urls:
        if re.match(_IP_URL_RE, u):
            s = s + W_IP_LINK  # ip address url, very bad
        if "xn--" in u:  # punycode
            s = s + W_PUNYCODE_LINK
    return s


def brand_score(frm):
    """Assign points when the sender says paypal/microsoft/amazon but domain
    is weird"""
    s = 0
    for brand in BRANDS:
        if brand in frm.lower() and f"{brand}.com" not in frm.lower():
            s = s + W_BRAND_MISMATCH
    return s


def auth_score(raw):
    """Assign points when SPF or DMARC failed."""
    low = raw.lower()
    if "spf=fail" in low or "dmarc=fail" in low:
         return W_AUTH_FAIL
    return 0


def reply_to_score(frm, reply_to):
    """Assign points when sender and reply-to fiels mismatch."""
    from_domain = sender_domain(frm)
    reply_domain = sender_domain(reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        return W_REPLY_TO_MISMATCH
    return 0