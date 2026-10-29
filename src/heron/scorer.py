"""Compute the indicators scores and the classification outcome."""

from email import message_from_string, policy

from heron.features import (auth_score, brand_score, keyword_score, link_score,
                            reply_to_score)


PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

def score_email(raw):
    """Computes the score based on the indicators, given an email message."""
    msg = message_from_string(raw, policy=policy.default)
    frm = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    score = (keyword_score(raw) + link_score(raw) + brand_score(frm) +
             auth_score(raw) +  reply_to_score(frm, reply_to))
    return score


def compute_verdict(score):
    """Map a score to a verdict."""
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    elif score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "ok"