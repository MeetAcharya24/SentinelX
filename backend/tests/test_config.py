from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_defaults_need_no_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("APP_ENV", "GROQ_API_KEY", "THREAT_INTEL_API_KEY", "LOG_LEVEL", "CORS_ORIGINS"):
        monkeypatch.delenv(name, raising=False)

    settings = Settings(_env_file=None)

    assert settings.app_env == "development"
    assert settings.llm_configured is False
    assert settings.threat_intel_configured is False
    assert settings.cors_origin_list == ["http://localhost:3000"]


def test_blank_api_keys_are_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "   ")
    monkeypatch.setenv("THREAT_INTEL_API_KEY", "")

    settings = Settings(_env_file=None)

    assert settings.groq_api_key is None
    assert settings.threat_intel_api_key is None


def test_api_key_is_never_shown_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "gsk_super_secret")

    settings = Settings(_env_file=None)

    assert settings.llm_configured is True
    assert "gsk_super_secret" not in repr(settings)


def test_cors_origins_split_on_commas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000, https://sentinelx.example ,")

    settings = Settings(_env_file=None)

    assert settings.cors_origin_list == ["http://localhost:3000", "https://sentinelx.example"]


def test_log_level_is_case_insensitive_and_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    assert Settings(_env_file=None).log_level == "debug"

    monkeypatch.setenv("LOG_LEVEL", "chatty")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_data_dir_defaults_to_the_repository_data_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATA_DIR", raising=False)

    settings = Settings(_env_file=None)

    assert settings.data_dir.name == "data"
    assert (settings.data_dir.parent / ".env.example").is_file()


def test_data_dir_can_be_overridden(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    assert Settings(_env_file=None).data_dir == tmp_path


def test_model_dir_defaults_to_the_ignored_artifacts_folder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MODEL_DIR", raising=False)

    settings = Settings(_env_file=None)

    assert settings.model_dir.parts[-3:] == ("backend", "artifacts", "network")


def test_model_dir_can_be_overridden(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))

    assert Settings(_env_file=None).model_dir == tmp_path


def test_values_load_from_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=production\nUNRELATED_FRONTEND_VAR=1\n", encoding="utf-8")

    settings = Settings(_env_file=env_file)

    assert settings.app_env == "production"
