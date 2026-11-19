import re
import os
import sys

KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

BRANDS = ["paypal", "microsoft", "amazon"]

W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2
PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

URL_RE = re.compile("https?://[^\\s\"'<>]+")
IP_URL_RE = re.compile("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")

def header(raw, name):
    """Return the value of the first "name:" header line, or "?" if there is none."""
    match = re.search(name + ": (.*)", raw)
    if match is None:
        return "?"
    return match.group(1)

def sender_domain(address):
    """Return the domain of an email address, or None if there is no @."""
    match = re.search("@([a-zA-Z0-9.-]+)", address)
    if match is None:
        return None
    return match.group(1)

def keyword_score(raw):
    """One point for each pressure keyword found anywhere in the message."""
    low = raw.lower()
    return sum(W_KEYWORD for kw in KEYWORDS if kw in low)

def link_score(raw):
    """Points for links to a bare IP address or to a punycode domain."""
    s = 0
    for url in URL_RE.findall(raw):
        if IP_URL_RE.match(url):
            s = s + W_IP_LINK
        if "xn--" in url:
            s = s + W_PUNYCODE_LINK
    return s

def brand_score(frm):
    """Points when the sender name claims a brand but the address is elewhere."""
    low = frm.lower()
    return sum(W_BRAND_MISMATCH for brand in BRANDS
               if brand in low and brand + ".com" not in low)

def auth_score(raw):
    """Points when SPF or DMARC failed."""
    low = raw.lower()
    if "spf=fail" in low or "dmarc=fail" in low:
        return W_AUTH_FAIL
    return 0

def reply_to_score(frm, reply_to):
    """Points when replies go to a different domain than the sender's."""
    from_domain = sender_domain(frm)
    reply_domain = sender_domain(reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        return W_REPLY_TO_MISMATCH
    return 0

def score_email(raw):
    """Sum the points of every indicator for one raw message."""
    frm = header(raw, "From")
    return (keyword_score(raw) + link_score(raw) + brand_score(frm)
            + auth_score(raw) + reply_to_score(frm, header(raw, "Reply-To")))

def verdict_for(score):
    """Map a score to a verdict."""
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "ok"

def check_mail(folder):
    """Score every .eml file in folder; return (file name, verdict, score) tuples."""
    verdicts = []
    for fn in os.listdir(folder):
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        s = score_email(raw)
        verdicts.append((fn, verdict_for(s), s))
    return verdicts

def report(verdicts):
    """Print the verdicts and save them to results.txt."""
    print("checked", len(verdicts), "mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    with open("results.txt", "w", encoding="utf-8") as out:
        out.write(str(verdicts))
    print("flagged:", [v[0] for v in verdicts if v[1] == "PHISHING"])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python triage.py <folder-with-eml-files>", file=sys.stderr)
        sys.exit(2)
    try:
        report(check_mail(sys.argv[1]))
    except FileNotFoundError:
        print("error: no such folder:", sys.argv[1], file=sys.stderr)
        sys.exit(2)