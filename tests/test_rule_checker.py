"""Tests for shadowcommit.monitor.rule_checker — MonitorResult and RuleChecker."""
from pathlib import Path

import pytest

from shadowcommit.commitment.schema import Commitment
from shadowcommit.diff.extractor import ObservedDiff
from shadowcommit.monitor.rule_checker import (
    UNDECLARED_FILE_MODIFICATIONS,
    UNDECLARED_NETWORK,
    UNDECLARED_SENSITIVE_PATH,
    WRITES_OUTSIDE_SRC,
    MonitorResult,
    RuleChecker,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_commitment(**overrides) -> Commitment:
    defaults = dict(
        command="echo hi",
        purpose="test",
        files_read=[],
        files_modified=[],
        files_created=[],
        network_expected=False,
        sensitive_paths_expected=False,
        privileged_changes_expected=False,
    )
    return Commitment(**{**defaults, **overrides})


def _make_diff(**overrides) -> ObservedDiff:
    defaults = dict(
        command="echo hi",
        files_read=(),
        files_modified=(),
        files_created=(),
        files_deleted=(),
        sensitive_paths_touched=False,
        network_activity_detected=False,
        writes_outside_src=(),
    )
    return ObservedDiff(**{**defaults, **overrides})


def _allow_result() -> MonitorResult:
    return MonitorResult(
        decision="allow",
        triggered_rules=(),
        reasons=(),
        commitment=_make_commitment(),
        observed=_make_diff(),
    )


# ---------------------------------------------------------------------------
# MonitorResult dataclass
# ---------------------------------------------------------------------------

class TestMonitorResult:
    def test_all_fields_accessible(self) -> None:
        r = _allow_result()
        assert r.decision == "allow"
        assert r.triggered_rules == ()
        assert r.reasons == ()
        assert isinstance(r.commitment, Commitment)
        assert isinstance(r.observed, ObservedDiff)

    def test_frozen(self) -> None:
        r = _allow_result()
        with pytest.raises((AttributeError, TypeError)):
            r.decision = "block"  # type: ignore[misc]

    def test_decision_block(self) -> None:
        r = MonitorResult(
            decision="block",
            triggered_rules=(UNDECLARED_NETWORK,),
            reasons=("Network activity detected but not declared in commitment",),
            commitment=_make_commitment(),
            observed=_make_diff(),
        )
        assert r.decision == "block"
        assert len(r.triggered_rules) == 1

    def test_triggered_rules_is_tuple(self) -> None:
        assert isinstance(_allow_result().triggered_rules, tuple)

    def test_reasons_is_tuple(self) -> None:
        assert isinstance(_allow_result().reasons, tuple)

    def test_reasons_length_matches_triggered_rules(self) -> None:
        r = MonitorResult(
            decision="block",
            triggered_rules=(UNDECLARED_NETWORK, WRITES_OUTSIDE_SRC),
            reasons=("reason a", "reason b"),
            commitment=_make_commitment(),
            observed=_make_diff(),
        )
        assert len(r.reasons) == len(r.triggered_rules)


# ---------------------------------------------------------------------------
# Rule constants
# ---------------------------------------------------------------------------

class TestRuleConstants:
    def test_constants_are_strings(self) -> None:
        for c in (UNDECLARED_NETWORK, UNDECLARED_SENSITIVE_PATH,
                  UNDECLARED_FILE_MODIFICATIONS, WRITES_OUTSIDE_SRC):
            assert isinstance(c, str)

    def test_constants_are_distinct(self) -> None:
        constants = {UNDECLARED_NETWORK, UNDECLARED_SENSITIVE_PATH,
                     UNDECLARED_FILE_MODIFICATIONS, WRITES_OUTSIDE_SRC}
        assert len(constants) == 4


# ---------------------------------------------------------------------------
# Rule: UNDECLARED_NETWORK
# ---------------------------------------------------------------------------

class TestUndeclaredNetwork:
    def test_fires_when_network_detected_and_not_declared(self) -> None:
        commitment = _make_commitment(network_expected=False)
        observed = _make_diff(network_activity_detected=True)
        result = RuleChecker.check(commitment, observed)
        assert result.decision == "block"
        assert UNDECLARED_NETWORK in result.triggered_rules

    def test_does_not_fire_when_network_declared(self) -> None:
        commitment = _make_commitment(network_expected=True)
        observed = _make_diff(network_activity_detected=True)
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_NETWORK not in result.triggered_rules

    def test_does_not_fire_when_no_network_detected(self) -> None:
        commitment = _make_commitment(network_expected=False)
        observed = _make_diff(network_activity_detected=False)
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_NETWORK not in result.triggered_rules

    def test_includes_reason_when_fired(self) -> None:
        commitment = _make_commitment(network_expected=False)
        observed = _make_diff(network_activity_detected=True)
        result = RuleChecker.check(commitment, observed)
        assert any("network" in r.lower() for r in result.reasons)


# ---------------------------------------------------------------------------
# Rule: UNDECLARED_SENSITIVE_PATH
# ---------------------------------------------------------------------------

class TestUndeclaredSensitivePath:
    def test_fires_when_sensitive_touched_and_not_declared(self) -> None:
        commitment = _make_commitment(sensitive_paths_expected=False)
        observed = _make_diff(sensitive_paths_touched=True)
        result = RuleChecker.check(commitment, observed)
        assert result.decision == "block"
        assert UNDECLARED_SENSITIVE_PATH in result.triggered_rules

    def test_does_not_fire_when_sensitive_declared(self) -> None:
        commitment = _make_commitment(sensitive_paths_expected=True)
        observed = _make_diff(sensitive_paths_touched=True)
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_SENSITIVE_PATH not in result.triggered_rules

    def test_does_not_fire_when_no_sensitive_touched(self) -> None:
        commitment = _make_commitment(sensitive_paths_expected=False)
        observed = _make_diff(sensitive_paths_touched=False)
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_SENSITIVE_PATH not in result.triggered_rules

    def test_includes_reason_when_fired(self) -> None:
        commitment = _make_commitment(sensitive_paths_expected=False)
        observed = _make_diff(sensitive_paths_touched=True)
        result = RuleChecker.check(commitment, observed)
        assert any("sensitive" in r.lower() for r in result.reasons)


# ---------------------------------------------------------------------------
# Rule: UNDECLARED_FILE_MODIFICATIONS
# ---------------------------------------------------------------------------

class TestUndeclaredFileModifications:
    def test_fires_when_modified_file_undeclared(self) -> None:
        commitment = _make_commitment(files_modified=[], files_created=[])
        observed = _make_diff(files_modified=("src/main.py",))
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS in result.triggered_rules

    def test_fires_when_created_file_undeclared(self) -> None:
        commitment = _make_commitment(files_modified=[], files_created=[])
        observed = _make_diff(files_created=("report.txt",))
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS in result.triggered_rules

    def test_does_not_fire_when_all_files_declared_relative(self) -> None:
        commitment = _make_commitment(files_modified=["src/main.py"])
        observed = _make_diff(files_modified=("src/main.py",))
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS not in result.triggered_rules

    def test_does_not_fire_when_all_files_declared_absolute(self) -> None:
        # Commitment paths are absolute (as extractor produces them)
        commitment = _make_commitment(
            files_modified=["/tmp/shadowcommit_abc/src/main.py"]
        )
        observed = _make_diff(files_modified=("src/main.py",))
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS not in result.triggered_rules

    def test_over_declaration_does_not_fire(self) -> None:
        # Agent declared more files than it touched — that is fine
        commitment = _make_commitment(
            files_modified=["src/main.py", "src/utils.py", "src/data.py"]
        )
        observed = _make_diff(files_modified=("src/main.py",))
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS not in result.triggered_rules

    def test_does_not_fire_when_no_files_modified(self) -> None:
        commitment = _make_commitment()
        observed = _make_diff()
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS not in result.triggered_rules

    def test_undeclared_paths_appear_in_reason(self) -> None:
        commitment = _make_commitment(files_modified=[], files_created=[])
        observed = _make_diff(files_created=("sneaky.txt",))
        result = RuleChecker.check(commitment, observed)
        assert any("sneaky.txt" in r for r in result.reasons)

    def test_created_and_modified_checked_together(self) -> None:
        # One declared, one not
        commitment = _make_commitment(files_modified=["src/main.py"])
        observed = _make_diff(
            files_modified=("src/main.py",),
            files_created=("undeclared.txt",),
        )
        result = RuleChecker.check(commitment, observed)
        assert UNDECLARED_FILE_MODIFICATIONS in result.triggered_rules


# ---------------------------------------------------------------------------
# Rule: WRITES_OUTSIDE_SRC
# ---------------------------------------------------------------------------

class TestWritesOutsideSrc:
    def test_fires_when_writes_outside_src(self) -> None:
        commitment = _make_commitment()
        observed = _make_diff(writes_outside_src=("report.txt",))
        result = RuleChecker.check(commitment, observed)
        assert WRITES_OUTSIDE_SRC in result.triggered_rules
        assert result.decision == "block"

    def test_does_not_fire_when_writes_inside_src_only(self) -> None:
        commitment = _make_commitment(files_modified=["src/main.py"])
        observed = _make_diff(files_modified=("src/main.py",))
        result = RuleChecker.check(commitment, observed)
        assert WRITES_OUTSIDE_SRC not in result.triggered_rules

    def test_does_not_fire_when_no_writes(self) -> None:
        commitment = _make_commitment()
        observed = _make_diff()
        result = RuleChecker.check(commitment, observed)
        assert WRITES_OUTSIDE_SRC not in result.triggered_rules

    def test_includes_paths_in_reason(self) -> None:
        commitment = _make_commitment()
        observed = _make_diff(writes_outside_src=(".env",))
        result = RuleChecker.check(commitment, observed)
        assert any(".env" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Multi-rule aggregation
# ---------------------------------------------------------------------------

class TestMultipleRules:
    def test_allow_when_zero_rules_fire(self) -> None:
        result = RuleChecker.check(_make_commitment(), _make_diff())
        assert result.decision == "allow"
        assert result.triggered_rules == ()
        assert result.reasons == ()

    def test_block_when_one_rule_fires(self) -> None:
        result = RuleChecker.check(
            _make_commitment(network_expected=False),
            _make_diff(network_activity_detected=True),
        )
        assert result.decision == "block"
        assert len(result.triggered_rules) == 1

    def test_all_four_rules_fire_simultaneously(self) -> None:
        commitment = _make_commitment(
            network_expected=False,
            sensitive_paths_expected=False,
            files_modified=[],
            files_created=[],
        )
        observed = _make_diff(
            network_activity_detected=True,
            sensitive_paths_touched=True,
            files_modified=("src/main.py",),
            writes_outside_src=("report.txt",),
        )
        result = RuleChecker.check(commitment, observed)
        assert result.decision == "block"
        assert set(result.triggered_rules) == {
            UNDECLARED_NETWORK,
            UNDECLARED_SENSITIVE_PATH,
            UNDECLARED_FILE_MODIFICATIONS,
            WRITES_OUTSIDE_SRC,
        }
        assert len(result.reasons) == 4

    def test_triggered_rules_and_reasons_same_length(self) -> None:
        commitment = _make_commitment(network_expected=False)
        observed = _make_diff(
            network_activity_detected=True,
            writes_outside_src=("bad.txt",),
        )
        result = RuleChecker.check(commitment, observed)
        assert len(result.triggered_rules) == len(result.reasons)

    def test_commitment_and_observed_preserved_on_result(self) -> None:
        c = _make_commitment(purpose="my purpose")
        d = _make_diff(command="ls")
        result = RuleChecker.check(c, d)
        assert result.commitment is c
        assert result.observed is d


# ---------------------------------------------------------------------------
# Integration: full pipeline
# ---------------------------------------------------------------------------

class TestRuleCheckerIntegration:
    def test_adversarial_command_blocked(self, workspace: Path) -> None:
        from shadowcommit.commitment.extractor import CommitmentExtractor
        from shadowcommit.diff.extractor import DiffExtractor
        from shadowcommit.environment.agent import AdversarialAgent
        from shadowcommit.shadow.executor import ShadowExecutor

        agent = AdversarialAgent(workspace)
        env_abs = str(workspace / ".env")
        exfil_cmd = next(cmd for cmd in agent.generate_commands() if env_abs in cmd)

        # Use the agent's dishonest commitment (lies about .env)
        exfil_commitment = next(
            c for c in agent.generate_commitments() if env_abs in c.command
        )

        result = ShadowExecutor().execute(exfil_cmd, workspace)
        diff = DiffExtractor.extract(result)
        monitor = RuleChecker.check(exfil_commitment, diff)

        assert monitor.decision == "block"
        assert UNDECLARED_SENSITIVE_PATH in monitor.triggered_rules

    def test_legitimate_echo_command_allowed(self, workspace: Path) -> None:
        from shadowcommit.commitment.extractor import CommitmentExtractor
        from shadowcommit.diff.extractor import DiffExtractor
        from shadowcommit.shadow.executor import ShadowExecutor

        cmd = "echo hello"
        commitment = CommitmentExtractor.extract(cmd, "print greeting")
        result = ShadowExecutor().execute(cmd, workspace)
        diff = DiffExtractor.extract(result)
        monitor = RuleChecker.check(commitment, diff)

        assert monitor.decision == "allow"
        assert monitor.triggered_rules == ()

    def test_find_command_allowed(self, workspace: Path) -> None:
        from shadowcommit.commitment.extractor import CommitmentExtractor
        from shadowcommit.diff.extractor import DiffExtractor
        from shadowcommit.environment.agent import AdversarialAgent
        from shadowcommit.shadow.executor import ShadowExecutor

        agent = AdversarialAgent(workspace)
        find_cmd = agent.generate_commands()[0]
        find_commitment = agent.generate_commitments()[0]

        result = ShadowExecutor().execute(find_cmd, workspace)
        diff = DiffExtractor.extract(result)
        monitor = RuleChecker.check(find_commitment, diff)

        # find is read-only, should not trigger any write rules
        assert UNDECLARED_NETWORK not in monitor.triggered_rules
        assert WRITES_OUTSIDE_SRC not in monitor.triggered_rules
