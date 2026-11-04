"""Compute the indicators scores and the classification outcome."""

from typing import Callable

from heron.features import (auth_score, brand_score, keyword_score, link_score,
                            reply_to_score)
from heron.models import ParsedEmail, TriageResult, Verdict


PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

ALL_CHECKS: tuple[Callable[[ParsedEmail], int], ...] = (
    keyword_score,
    link_score,
    brand_score,
    auth_score,
    reply_to_score
)


def triage(email: ParsedEmail) -> TriageResult:
    """Compute the score of the email and return the verdict.

    Parameters
    ----------
    email : ParsedEmail
        The parsed email to be scored.

    Returns
    -------
    TriageResult
        The result of the triage, including the email ID, score, and verdict.
    """
    score = sum(check(email) for check in ALL_CHECKS)
    return TriageResult(
        email_id=email.email_id,
        score=score,
        verdict=compute_verdict(score)
    )


def compute_verdict(score: int) -> Verdict:
    """Compute the verdict based on the score.

    Parameters
    ----------
    score : int
        The score of the email.

    Returns
    -------
    Verdict
        The verdict of the email based on the score.
    """
    if score >= PHISHING_THRESHOLD:
        return Verdict.PHISHING
    elif score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    else:
        return Verdict.BENIGN