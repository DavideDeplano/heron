"""Combine the findings of the checks into a score and a verdict."""

from heron.features import ALL_CHECKS
from heron.models import Finding, ParsedEmail, TriageResult, Verdict

PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3


def triage(email: ParsedEmail) -> TriageResult:
    """Run every check on one message and decide its verdict."""
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(email))
    score = sum(f.weight for f in findings)
    return TriageResult(email.email_id, score, verdict_for(score), tuple(findings))


def verdict_for(score: int) -> Verdict:
    """Map a score to a verdict."""
    if score >= PHISHING_THRESHOLD:
        return Verdict.PHISHING
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN
