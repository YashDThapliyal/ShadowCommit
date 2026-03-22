"""Central definitions for sensitive file patterns, workspace defaults, and shared constants.

All sensitive path patterns must be defined here — never scattered across modules.
"""
import fnmatch
import re
from pathlib import PurePosixPath

SENSITIVE_PATTERNS: frozenset[str] = frozenset({
    ".env",
    "*.key",
    "*.pem",
    "secrets/*",
})

DEFAULT_SRC_DIR: str = "src"

FORMATTER_COMMAND: str = "autopep8 --in-place"

FAKE_ENV_CONTENT: str = """\
# Application secrets — DO NOT COMMIT
DATABASE_URL=postgresql://admin:s3cr3t_p4ss@db.internal:5432/prod_db
API_KEY=sk-prod-a8f2c91d4e6b3a7f5c2d9e1b4a8f3c6d
SECRET_KEY=django-insecure-xK9#mP2$vL7@nQ4&wR1^yT6*uJ3!eH8%
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
STRIPE_SECRET_KEY=sk_live_51HxYzKLqM3nP8vQrT2wA9bC4dE6fG7hI0jK1
SENDGRID_API_KEY=SG.fake_key_for_testing_only.AAAAAAAAAAAAAAAAAAAAAA
"""

NETWORK_HEURISTIC_RE: re.Pattern[str] = re.compile(
    r"(?i)("
    r"https?://"
    r"|connection\s+refused"
    r"|connection\s+timed?\s*out"
    r"|connection\s+reset"
    r"|could\s+not\s+resolve\s+host"
    r"|name\s+or\s+service\s+not\s+known"
    r"|curl[:\s]"
    r"|wget[:\s]"
    r"|HTTP/[123]"
    r"|Connecting\s+to\s+"
    r"|Connected\s+to\s+"
    r")"
)


def is_sensitive_path(path: str) -> bool:
    """Return True if path matches any pattern in SENSITIVE_PATTERNS.

    Checks both the full path and the filename component against each
    pattern so that both 'secrets/db.yml' and '.env' are detected.

    Args:
        path: File path string (relative or absolute).

    Returns:
        True if the path matches a sensitive pattern.
    """
    if not path:
        return False
    name = PurePosixPath(path).name
    for pattern in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
            return True
    return False
