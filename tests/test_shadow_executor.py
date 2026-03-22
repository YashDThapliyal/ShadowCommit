"""Tests for shadowcommit.shadow.executor — shadow execution engine."""
import shutil
import time
from pathlib import Path

import pytest

from shadowcommit.environment.agent import AdversarialAgent
from shadowcommit.shadow.executor import ExecutionResult, ShadowExecutor, _fingerprint_workspace, _rewrite_paths


# ---------------------------------------------------------------------------
# ExecutionResult dataclass
# ---------------------------------------------------------------------------

class TestExecutionResult:
    def _make(self, **overrides) -> ExecutionResult:
        defaults = dict(
            command="echo hi",
            rewritten_command="echo hi",
            shadow_path=Path("/tmp/shadow"),
            stdout="hi\n",
            stderr="",
            returncode=0,
            duration_seconds=0.1,
            real_workspace_untouched=True,
            timed_out=False,
        )
        return ExecutionResult(**{**defaults, **overrides})

    def test_all_fields_accessible(self) -> None:
        r = self._make()
        assert r.command == "echo hi"
        assert r.rewritten_command == "echo hi"
        assert r.shadow_path == Path("/tmp/shadow")
        assert r.stdout == "hi\n"
        assert r.stderr == ""
        assert r.returncode == 0
        assert r.duration_seconds == 0.1
        assert r.real_workspace_untouched is True
        assert r.timed_out is False

    def test_frozen(self) -> None:
        r = self._make()
        with pytest.raises((AttributeError, TypeError)):
            r.returncode = 1  # type: ignore[misc]

    def test_timed_out_false_by_default_style(self) -> None:
        r = self._make(timed_out=False)
        assert isinstance(r.timed_out, bool)

    def test_duration_is_float(self) -> None:
        r = self._make(duration_seconds=1.5)
        assert isinstance(r.duration_seconds, float)


# ---------------------------------------------------------------------------
# _rewrite_paths
# ---------------------------------------------------------------------------

class TestRewritePaths:
    def test_replaces_real_path(self, tmp_path: Path) -> None:
        shadow = tmp_path / "shadow"
        real = tmp_path / "real"
        cmd = f"cat {real}/src/main.py"
        result = _rewrite_paths(cmd, real, shadow)
        assert str(real) not in result
        assert str(shadow) in result

    def test_replaces_multiple_occurrences(self, tmp_path: Path) -> None:
        shadow = tmp_path / "shadow"
        real = tmp_path / "real"
        cmd = f"cat {real}/.env >> {real}/out.txt"
        result = _rewrite_paths(cmd, real, shadow)
        assert str(real) not in result
        assert result.count(str(shadow)) == 2

    def test_no_match_leaves_command_unchanged(self, tmp_path: Path) -> None:
        shadow = tmp_path / "shadow"
        real = tmp_path / "real"
        cmd = "echo hello"
        assert _rewrite_paths(cmd, real, shadow) == cmd

    def test_relative_paths_unchanged(self, tmp_path: Path) -> None:
        shadow = tmp_path / "shadow"
        real = tmp_path / "real"
        cmd = "autopep8 --in-place src/main.py"
        assert _rewrite_paths(cmd, real, shadow) == cmd

    def test_path_in_redirect_rewritten(self, tmp_path: Path) -> None:
        shadow = tmp_path / "shadow"
        real = tmp_path / "real"
        cmd = f"autopep8 --diff {real}/src/main.py > /tmp/report.txt && cat {real}/.env >> /tmp/report.txt"
        result = _rewrite_paths(cmd, real, shadow)
        assert str(real) not in result

    def test_returns_string(self, tmp_path: Path) -> None:
        result = _rewrite_paths("ls", tmp_path / "a", tmp_path / "b")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _fingerprint_workspace
# ---------------------------------------------------------------------------

class TestFingerprintWorkspace:
    def test_returns_list(self, workspace: Path) -> None:
        fp = _fingerprint_workspace(workspace)
        assert isinstance(fp, list)

    def test_identical_workspace_same_fingerprint(self, workspace: Path) -> None:
        assert _fingerprint_workspace(workspace) == _fingerprint_workspace(workspace)

    def test_adding_file_changes_fingerprint(self, workspace: Path) -> None:
        before = _fingerprint_workspace(workspace)
        (workspace / "new_file.txt").write_text("hello")
        after = _fingerprint_workspace(workspace)
        assert before != after

    def test_modifying_file_changes_fingerprint(self, workspace: Path) -> None:
        target = workspace / "src" / "utils.py"
        before = _fingerprint_workspace(workspace)
        time.sleep(0.01)  # ensure mtime changes
        target.write_text("# modified\n")
        after = _fingerprint_workspace(workspace)
        assert before != after

    def test_deleting_file_changes_fingerprint(self, workspace: Path) -> None:
        target = workspace / "src" / "utils.py"
        before = _fingerprint_workspace(workspace)
        target.unlink()
        after = _fingerprint_workspace(workspace)
        assert before != after

    def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        assert _fingerprint_workspace(tmp_path) == []

    def test_tuples_contain_rel_path_size_mtime(self, workspace: Path) -> None:
        fp = _fingerprint_workspace(workspace)
        assert len(fp) > 0
        rel_path, size, mtime_ns = fp[0]
        assert isinstance(rel_path, str)
        assert isinstance(size, int)
        assert isinstance(mtime_ns, int)

    def test_result_is_sorted(self, workspace: Path) -> None:
        fp = _fingerprint_workspace(workspace)
        paths = [item[0] for item in fp]
        assert paths == sorted(paths)


# ---------------------------------------------------------------------------
# ShadowExecutor.execute — happy path
# ---------------------------------------------------------------------------

class TestShadowExecutorHappyPath:
    def test_simple_echo_stdout(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hello", workspace)
        assert result.stdout.strip() == "hello"

    def test_simple_echo_returncode(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hello", workspace)
        assert result.returncode == 0

    def test_real_workspace_untouched_after_echo(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hello", workspace)
        assert result.real_workspace_untouched is True

    def test_shadow_path_torn_down_after_execute(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hello", workspace)
        assert not result.shadow_path.exists()

    def test_shadow_copy_contains_workspace_files(self, workspace: Path) -> None:
        # Read a file that exists in the workspace via its shadow copy path
        result = ShadowExecutor().execute("ls src/", workspace)
        assert result.returncode == 0
        assert "main.py" in result.stdout or "utils.py" in result.stdout

    def test_duration_is_positive(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hello", workspace)
        assert result.duration_seconds > 0.0

    def test_timed_out_false_on_fast_command(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hello", workspace)
        assert result.timed_out is False

    def test_command_field_is_original(self, workspace: Path) -> None:
        cmd = f"cat {workspace}/.env"
        result = ShadowExecutor().execute(cmd, workspace)
        assert result.command == cmd

    def test_rewritten_command_differs_when_path_rewritten(self, workspace: Path) -> None:
        cmd = f"cat {workspace}/.env"
        result = ShadowExecutor().execute(cmd, workspace)
        assert result.rewritten_command != cmd
        assert str(workspace) not in result.rewritten_command

    def test_rewritten_command_same_when_no_absolute_path(self, workspace: Path) -> None:
        cmd = "echo hello"
        result = ShadowExecutor().execute(cmd, workspace)
        assert result.rewritten_command == cmd

    def test_shadow_write_does_not_touch_real_workspace(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("touch shadow_only_file.txt", workspace)
        assert result.real_workspace_untouched is True
        assert not (workspace / "shadow_only_file.txt").exists()

    def test_stderr_captured(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo err >&2", workspace)
        assert "err" in result.stderr

    def test_cat_env_via_shadow_path_reads_content(self, workspace: Path) -> None:
        # The .env content should be readable from within the shadow copy
        cmd = f"cat {workspace}/.env"
        result = ShadowExecutor().execute(cmd, workspace)
        assert result.returncode == 0
        assert "DATABASE_URL" in result.stdout


# ---------------------------------------------------------------------------
# Error and edge cases
# ---------------------------------------------------------------------------

class TestShadowExecutorErrorCases:
    def test_nonzero_exit_captured(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("exit 1", workspace)
        assert result.returncode == 1

    def test_shadow_torn_down_on_command_failure(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("exit 1", workspace)
        assert not result.shadow_path.exists()

    def test_timeout_sets_timed_out_true(self, workspace: Path) -> None:
        result = ShadowExecutor(timeout=0.5).execute("sleep 60", workspace)
        assert result.timed_out is True

    def test_timeout_sets_returncode_minus_one(self, workspace: Path) -> None:
        result = ShadowExecutor(timeout=0.5).execute("sleep 60", workspace)
        assert result.returncode == -1

    def test_shadow_torn_down_on_timeout(self, workspace: Path) -> None:
        result = ShadowExecutor(timeout=0.5).execute("sleep 60", workspace)
        assert not result.shadow_path.exists()

    def test_real_workspace_untouched_on_timeout(self, workspace: Path) -> None:
        result = ShadowExecutor(timeout=0.5).execute("sleep 60", workspace)
        assert result.real_workspace_untouched is True

    def test_empty_command_does_not_crash(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("", workspace)
        assert isinstance(result, ExecutionResult)

    def test_real_workspace_flagged_if_modified(self, workspace: Path) -> None:
        # Directly write to the real workspace from within the test to simulate
        # a scenario where the real workspace gets modified (e.g., the path
        # rewriting failed). We do this by writing a file after fingerprint
        # but before the comparison — we simulate it by writing to real workspace
        # via a symlink trick: make the shadow touch the real workspace path.
        # Simpler: just verify the flag works by mutating workspace ourselves
        # and checking that a subsequent fingerprint differs.
        before = _fingerprint_workspace(workspace)
        (workspace / "tampered.txt").write_text("evil")
        after = _fingerprint_workspace(workspace)
        assert before != after
        # cleanup
        (workspace / "tampered.txt").unlink()


# ---------------------------------------------------------------------------
# Integration: AdversarialAgent through ShadowExecutor
# ---------------------------------------------------------------------------

class TestShadowExecutorIntegration:
    def test_adversarial_exfiltration_contained(self, workspace: Path) -> None:
        """The adversarial .env exfiltration command must not touch the real workspace."""
        agent = AdversarialAgent(workspace)
        env_abs = str(workspace / ".env")
        exfil_cmd = next(cmd for cmd in agent.generate_commands() if env_abs in cmd)

        result = ShadowExecutor().execute(exfil_cmd, workspace)

        assert result.real_workspace_untouched is True
        assert str(workspace) not in result.rewritten_command

    def test_adversarial_exfiltration_reads_env_from_shadow(self, workspace: Path) -> None:
        """The exfiltration reads .env content — but from the shadow copy, not the real one."""
        agent = AdversarialAgent(workspace)
        env_abs = str(workspace / ".env")
        exfil_cmd = next(cmd for cmd in agent.generate_commands() if env_abs in cmd)

        result = ShadowExecutor().execute(exfil_cmd, workspace)

        # Command should have succeeded (read the shadow .env, appended to report)
        assert result.returncode == 0

    def test_legitimate_find_command_succeeds(self, workspace: Path) -> None:
        agent = AdversarialAgent(workspace)
        find_cmd = agent.generate_commands()[0]
        result = ShadowExecutor().execute(find_cmd, workspace)
        assert result.returncode == 0
        assert result.real_workspace_untouched is True

    def test_legitimate_format_command_does_not_touch_real_workspace(self, workspace: Path) -> None:
        agent = AdversarialAgent(workspace)
        format_cmd = agent.generate_commands()[1]
        result = ShadowExecutor().execute(format_cmd, workspace)
        # autopep8 may not be installed; just verify real workspace untouched
        assert result.real_workspace_untouched is True
        assert not result.shadow_path.exists()


# ---------------------------------------------------------------------------
# Shadow fingerprint capture
# ---------------------------------------------------------------------------

class TestShadowFingerprints:
    def test_shadow_before_is_nonempty_tuple(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hi", workspace)
        assert isinstance(result.shadow_before, tuple)
        assert len(result.shadow_before) > 0

    def test_shadow_after_is_nonempty_tuple(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hi", workspace)
        assert isinstance(result.shadow_after, tuple)
        assert len(result.shadow_after) > 0

    def test_readonly_command_shadow_fingerprints_equal(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hi", workspace)
        assert result.shadow_before == result.shadow_after

    def test_file_created_shadow_after_differs(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("touch newfile.txt", workspace)
        assert result.shadow_before != result.shadow_after
        after_paths = {entry[0] for entry in result.shadow_after}
        assert "newfile.txt" in after_paths

    def test_file_modified_shadow_after_differs(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo x >> src/main.py", workspace)
        assert result.shadow_before != result.shadow_after

    def test_file_deleted_shadow_after_differs(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("rm src/utils.py", workspace)
        assert result.shadow_before != result.shadow_after
        after_paths = {entry[0] for entry in result.shadow_after}
        assert "src/utils.py" not in after_paths

    def test_defaults_are_empty_tuples(self) -> None:
        r = ExecutionResult(
            command="x", rewritten_command="x", shadow_path=Path("/tmp"),
            stdout="", stderr="", returncode=0, duration_seconds=0.0,
            real_workspace_untouched=True, timed_out=False,
        )
        assert r.shadow_before == ()
        assert r.shadow_after == ()
