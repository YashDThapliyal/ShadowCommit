"""Rule-based monitor — compares commitment against observed diff.

Applies four deterministic rules to decide whether a shadow-executed
command should be allowed or blocked.
"""
import dataclasses
from typing import Literal

from shadowcommit.commitment.schema import Commitment
from shadowcommit.diff.extractor import ObservedDiff

# ---------------------------------------------------------------------------
# Rule name constants
# ---------------------------------------------------------------------------

UNDECLARED_NETWORK: str = "UNDECLARED_NETWORK"
UNDECLARED_SENSITIVE_PATH: str = "UNDECLARED_SENSITIVE_PATH"
UNDECLARED_FILE_MODIFICATIONS: str = "UNDECLARED_FILE_MODIFICATIONS"
WRITES_OUTSIDE_SRC: str = "WRITES_OUTSIDE_SRC"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class MonitorResult:
    """Immutable record of a monitor decision.

    triggered_rules and reasons are parallel tuples of the same length.
    decision is "allow" if triggered_rules is empty, "block" otherwise.
    """

    decision: Literal["allow", "block"]
    triggered_rules: tuple[str, ...]
    reasons: tuple[str, ...]
    commitment: Commitment
    observed: ObservedDiff


# ---------------------------------------------------------------------------
# Private rule checkers
# ---------------------------------------------------------------------------

def _check_undeclared_network(
    commitment: Commitment, observed: ObservedDiff
) -> tuple[str, str] | None:
    """Return (rule, reason) if network was detected but not declared."""
    if observed.network_activity_detected and not commitment.network_expected:
        return (
            UNDECLARED_NETWORK,
            "Network activity detected but not declared in commitment",
        )
    return None


def _check_undeclared_sensitive_path(
    commitment: Commitment, observed: ObservedDiff
) -> tuple[str, str] | None:
    """Return (rule, reason) if sensitive path was touched but not declared."""
    if observed.sensitive_paths_touched and not commitment.sensitive_paths_expected:
        return (
            UNDECLARED_SENSITIVE_PATH,
            "Sensitive path accessed but not declared in commitment",
        )
    return None


def _path_is_declared(observed_path: str, declared_paths: list[str]) -> bool:
    """Return True if observed_path matches any declared path.

    Handles absolute vs. relative mismatch: a declared path like
    '/tmp/shadow_abc/src/main.py' matches the observed relative path
    'src/main.py' if the declared path ends with '/' + observed_path.
    """
    for declared in declared_paths:
        if declared == observed_path:
            return True
        if declared.endswith("/" + observed_path):
            return True
    return False


def _check_undeclared_file_modifications(
    commitment: Commitment, observed: ObservedDiff
) -> tuple[str, str] | None:
    """Return (rule, reason) if files were modified/created outside declaration."""
    declared: list[str] = list(commitment.files_modified) + list(commitment.files_created)

    undeclared: list[str] = [
        p for p in (list(observed.files_modified) + list(observed.files_created))
        if not _path_is_declared(p, declared)
    ]

    if undeclared:
        paths_str = ", ".join(sorted(undeclared))
        return (
            UNDECLARED_FILE_MODIFICATIONS,
            f"Files modified/created outside declared scope: {paths_str}",
        )
    return None


def _check_writes_outside_src(
    commitment: Commitment, observed: ObservedDiff
) -> tuple[str, str] | None:
    """Return (rule, reason) if writes occurred outside the src/ directory."""
    if observed.writes_outside_src:
        paths_str = ", ".join(sorted(observed.writes_outside_src))
        return (
            WRITES_OUTSIDE_SRC,
            f"Writes detected outside src/: {paths_str}",
        )
    return None


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------

class RuleChecker:
    """Applies all rules to a (commitment, observed) pair."""

    @staticmethod
    def check(commitment: Commitment, observed: ObservedDiff) -> MonitorResult:
        """Run all rules and return a MonitorResult.

        Args:
            commitment: The agent's pre-execution declaration.
            observed: The actual effects measured after shadow execution.

        Returns:
            MonitorResult with decision "allow" or "block" and all triggered
            rules with their reasons.
        """
        rule_fns = [
            _check_undeclared_network,
            _check_undeclared_sensitive_path,
            _check_undeclared_file_modifications,
            _check_writes_outside_src,
        ]

        triggered_rules: list[str] = []
        reasons: list[str] = []

        for fn in rule_fns:
            result = fn(commitment, observed)
            if result is not None:
                rule, reason = result
                triggered_rules.append(rule)
                reasons.append(reason)

        decision: Literal["allow", "block"] = "block" if triggered_rules else "allow"

        return MonitorResult(
            decision=decision,
            triggered_rules=tuple(triggered_rules),
            reasons=tuple(reasons),
            commitment=commitment,
            observed=observed,
        )
