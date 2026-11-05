from heron.features import W_REPLY_TO_MISMATCH, W_URGENCY, check_reply_to, check_urgency
from tests.helpers import make_email

def test_urgency_fires_once_for_many_keywords() -> None:
    email = make_email(text="urgent: verify your password immediately")
    findings = check_urgency(email)
    assert [f.code for f in findings] == ["urgency"]
    assert findings[0].weight == W_URGENCY
def test_urgency_is_silent_without_keywords() -> None:
    assert check_urgency(make_email()) == []

def test_reply_to_fires_for_another_domain() -> None:
    email = make_email(reply_to_domain="mail-verify.net")
    findings = check_reply_to(email)
    assert [(f.code, f.weight) for f in findings] == [("reply_to_mismatch", W_REPLY_TO_MISMATCH)]
def test_reply_to_is_silent_when_a_domain_is_missing() -> None:
    assert check_reply_to(make_email(reply_to_domain=None)) == []
    assert check_reply_to(make_email(from_domain=None, reply_to_domain="x.example")) == []