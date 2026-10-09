from pathlib import Path

import pytest
from pydantic import ValidationError

from heron.config import Settings


@pytest.fixture(autouse=True)
def no_env_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)


def test_defaults_work_without_any_configuration() -> None:
    settings = Settings()
    assert (settings.db, settings.log_level) == (None, "INFO")


def test_values_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERON_DB", "verdicts.db")
    monkeypatch.setenv("HERON_LOG_LEVEL", "DEBUG")
    settings = Settings()
    assert (settings.db, settings.log_level) == ("verdicts.db", "DEBUG")


def test_the_secret_is_hidden_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-real-key")
    settings = Settings()
    assert "not-a-real-key" not in repr(settings)
    assert settings.gemini_api_key is not None
    assert settings.gemini_api_key.get_secret_value() == "not-a-real-key"


def test_a_bad_value_fails_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERON_LOG_LEVEL", "LOUD")
    with pytest.raises(ValidationError):
        Settings()
