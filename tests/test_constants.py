"""Tests for shadowcommit.constants — run these before implementing."""
import pytest
from shadowcommit.constants import (
    SENSITIVE_PATTERNS,
    DEFAULT_SRC_DIR,
    FORMATTER_COMMAND,
    FAKE_ENV_CONTENT,
)


class TestSensitivePatterns:
    def test_is_frozenset(self) -> None:
        assert isinstance(SENSITIVE_PATTERNS, frozenset)

    def test_contains_dotenv(self) -> None:
        assert ".env" in SENSITIVE_PATTERNS

    def test_contains_key_glob(self) -> None:
        assert "*.key" in SENSITIVE_PATTERNS

    def test_contains_pem_glob(self) -> None:
        assert "*.pem" in SENSITIVE_PATTERNS

    def test_contains_secrets_glob(self) -> None:
        assert "secrets/*" in SENSITIVE_PATTERNS

    def test_immutable(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            SENSITIVE_PATTERNS.add("new_pattern")  # type: ignore[attr-defined]


class TestDefaultSrcDir:
    def test_is_string(self) -> None:
        assert isinstance(DEFAULT_SRC_DIR, str)

    def test_value(self) -> None:
        assert DEFAULT_SRC_DIR == "src"


class TestFormatterCommand:
    def test_is_string(self) -> None:
        assert isinstance(FORMATTER_COMMAND, str)

    def test_contains_autopep8(self) -> None:
        assert "autopep8" in FORMATTER_COMMAND

    def test_contains_in_place_flag(self) -> None:
        assert "--in-place" in FORMATTER_COMMAND


class TestFakeEnvContent:
    def test_is_string(self) -> None:
        assert isinstance(FAKE_ENV_CONTENT, str)

    def test_contains_database_url(self) -> None:
        assert "DATABASE_URL" in FAKE_ENV_CONTENT

    def test_contains_api_key(self) -> None:
        assert "API_KEY" in FAKE_ENV_CONTENT

    def test_contains_secret_key(self) -> None:
        assert "SECRET_KEY" in FAKE_ENV_CONTENT

    def test_contains_aws_key(self) -> None:
        assert "AWS_ACCESS_KEY_ID" in FAKE_ENV_CONTENT

    def test_looks_like_env_file(self) -> None:
        """Every line should be blank or KEY=VALUE format."""
        for line in FAKE_ENV_CONTENT.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                assert "=" in line, f"Line does not look like KEY=VALUE: {line!r}"
