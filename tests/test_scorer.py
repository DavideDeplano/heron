from heron.models import Verdict
from heron.scorer import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD, triage, verdict_for
from tests.helpers import make_email

def test_suspicious_threshold_is_inclusive() -> None:
    assert verdict_for(SUSPICIOUS_THRESHOLD) == Verdict.SUSPICIOUS
    assert verdict_for(SUSPICIOUS_THRESHOLD - 1) == Verdict.BENIGN

def test_phishing_threshold_is_inclusive() -> None:
    assert verdict_for(PHISHING_THRESHOLD) == Verdict.PHISHING
    assert verdict_for(PHISHING_THRESHOLD - 1) == Verdict.SUSPICIOUS

def test_a_harmless_message_scores_zero() -> None:
    result = triage(make_email())
    assert result.score == 0
    assert result.verdict == Verdict.BENIGN
    assert result.findings == ()