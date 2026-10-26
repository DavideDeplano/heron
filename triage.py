import re
import os
import sys

# Points added by each indicator, and the score thresholds of each verdict.
W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2
PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

BRANDS = ["paypal", "microsoft", "amazon"]

KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

def header(raw, name):
    """Return the value of the first "name:" header line, or "?" if there is none."""
    match = re.search(name + ": (.*)", raw)
    if match is None:
        return "?"
    return match.group(1)

def sender_domain(address):
    """Return the email address domain or None if '@' is missing"""
    match = re.search("@([a-zA-Z0-9.-]+)", address)
    if match is None:
        return None
    return match.group(1)

def verdict_for(score):
    """Map a score to a verdict"""
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "ok"

def check_mail(folder):
    """Score every mail file in the given folder.
    Return (file name, verdict, score) tuples."""
    
    scores = {}
    verdicts = []
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        s = 0
        
        frm = header(raw, "From")

        low = raw.lower()
        for kw in KEYWORDS:
            if kw in low:
                s = s + W_KEYWORD
        # links that look bad
        urls = re.findall("https?://[^\\s\"'<>]+", raw)
        for u in urls:
            if re.match("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", u):
                s = s + W_IP_LINK  
            if "xn--" in u:
                s = s + W_PUNYCODE_LINK
        
        # sender says paypal/microsoft/amazon but domain is weird
        for brand in BRANDS:
            if brand in frm.lower() and f"{brand}.com" not in frm.lower():
                s = s + W_BRAND_MISMATCH
 
        if "spf=fail" in low or "dmarc=fail" in low:
            s = s + W_AUTH_FAIL
        # reply-to different from from
        
        from_domain = sender_domain(frm)
        reply_domain = sender_domain(header(raw, "Reply-To"))
        if from_domain and reply_domain and from_domain != reply_domain:
            s = s + W_REPLY_TO_MISMATCH
        
        scores[fn] = s
        verdicts.append((fn, verdict_for(s), s))

        return verdicts

def report(verdicts):
    """Print the verdicts and save them to results.txt"""
    print("checked", len(verdicts), "mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    with open("results.txt", "w", encoding="utf-8") as out:
        out.write(str(verdicts))
    print("flagged:", [v[0] for v in verdicts if v[1] == "PHISHING"])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python triage.py <folder-with-eml-files>", file=sys.stderr)
        sys.exit(2)
    try:
        check_mail(sys.argv[1])
        verdicts = check_mail(sys.argv[1])
        report(verdicts)
    except FileNotFoundError:
        print("error: no such folder:", sys.argv[1], file=sys.stderr)
        sys.exit(2)
    