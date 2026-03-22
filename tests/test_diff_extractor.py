"""Tests for shadowcommit.diff.extractor — ObservedDiff and DiffExtractor."""
from pathlib import Path

import pytest

from shadowcommit.diff.extractor import DiffExtractor, ObservedDiff
from shadowcommit.environment.agent import AdversarialAgent
from shadowcommit.shadow.executor import ExecutionResult, ShadowExecutor


# ---------------------------------------------------------------------------
# Helper: build a synthetic ExecutionResult without running anything
# ---------------------------------------------------------------------------

def _make_result(
    command: str = "echo hi",
    rewritten_command: str = "echo hi",
    shadow_path: Path = Path("/tmp/shadow"),
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    shadow_before: tuple = (),
    shadow_after: tuple = (),
) -> ExecutionResult:
    return ExecutionResult(
        command=command,
        rewritten_command=rewritten_command,
        shadow_path=shadow_path,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        duration_seconds=0.1,
        real_workspace_untouched=True,
        timed_out=False,
        shadow_before=shadow_before,
        shadow_after=shadow_after,
    )


# ---------------------------------------------------------------------------
# ObservedDiff dataclass
# ---------------------------------------------------------------------------

class TestObservedDiff:
    def _make_diff(self, **overrides) -> ObservedDiff:
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

    def test_all_fields_accessible(self) -> None:
        d = self._make_diff()
        assert d.command == "echo hi"
        assert d.files_read == ()
        assert d.files_modified == ()
        assert d.files_created == ()
        assert d.files_deleted == ()
        assert d.sensitive_paths_touched is False
        assert d.network_activity_detected is False
        assert d.writes_outside_src == ()

    def test_frozen(self) -> None:
        d = self._make_diff()
        with pytest.raises((AttributeError, TypeError)):
            d.command = "other"  # type: ignore[misc]

    def test_with_populated_tuples(self) -> None:
        d = self._make_diff(files_created=("newfile.txt",), sensitive_paths_touched=True)
        assert "newfile.txt" in d.files_created
        assert d.sensitive_paths_touched is True


# ---------------------------------------------------------------------------
# File change detection from fingerprints
# ---------------------------------------------------------------------------

class TestFileChangeDetection:
    def test_identical_fingerprints_no_changes(self) -> None:
        fp = (("src/main.py", 100, 1000),)
        result = _make_result(shadow_before=fp, shadow_after=fp)
        diff = DiffExtractor.extract(result)
        assert diff.files_modified == ()
        assert diff.files_created == ()
        assert diff.files_deleted == ()

    def test_file_created_detected(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 100, 1000), ("newfile.txt", 5, 2000))
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "newfile.txt" in diff.files_created
        assert "src/main.py" not in diff.files_created

    def test_file_deleted_detected(self) -> None:
        before = (("src/main.py", 100, 1000), ("src/utils.py", 50, 900))
        after = (("src/main.py", 100, 1000),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "src/utils.py" in diff.files_deleted

    def test_file_modified_by_size(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 200, 1000),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "src/main.py" in diff.files_modified

    def test_file_modified_by_mtime(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 100, 9999),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "src/main.py" in diff.files_modified

    def test_multiple_changes(self) -> None:
        before = (("src/main.py", 100, 1000), ("src/utils.py", 50, 900))
        after = (("src/main.py", 200, 1000), ("report.txt", 10, 3000))
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "src/main.py" in diff.files_modified
        assert "src/utils.py" in diff.files_deleted
        assert "report.txt" in diff.files_created

    def test_empty_fingerprints_no_changes(self) -> None:
        result = _make_result(shadow_before=(), shadow_after=())
        diff = DiffExtractor.extract(result)
        assert diff.files_created == ()
        assert diff.files_modified == ()
        assert diff.files_deleted == ()

    def test_command_field_preserved(self) -> None:
        result = _make_result(command="touch foo.txt")
        diff = DiffExtractor.extract(result)
        assert diff.command == "touch foo.txt"


# ---------------------------------------------------------------------------
# Network activity detection
# ---------------------------------------------------------------------------

class TestNetworkDetection:
    def test_no_network_output_false(self) -> None:
        result = _make_result(stdout="formatting src/main.py\n", stderr="")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is False

    def test_https_url_in_stdout(self) -> None:
        result = _make_result(stdout="fetching https://example.com/data\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True

    def test_http_status_in_stdout(self) -> None:
        result = _make_result(stdout="< HTTP/1.1 200 OK\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True

    def test_connection_refused_in_stderr(self) -> None:
        result = _make_result(stderr="error: Connection refused\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True

    def test_curl_output_in_stderr(self) -> None:
        result = _make_result(stderr="curl: (7) Failed to connect to host\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True

    def test_could_not_resolve_host(self) -> None:
        result = _make_result(stderr="Could not resolve host: api.example.com\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True

    def test_wget_output_detected(self) -> None:
        result = _make_result(stderr="wget: unable to resolve 'example.com'\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True

    def test_pattern_in_stderr_only(self) -> None:
        result = _make_result(stdout="", stderr="HTTP/2 404\n")
        diff = DiffExtractor.extract(result)
        assert diff.network_activity_detected is True


# ---------------------------------------------------------------------------
# Sensitive path detection
# ---------------------------------------------------------------------------

class TestSensitivePathDetection:
    def test_env_file_created_sets_sensitive(self) -> None:
        before = ()
        after = ((".env", 100, 1000),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is True

    def test_key_file_modified_sets_sensitive(self) -> None:
        before = (("ssl/server.key", 50, 900),)
        after = (("ssl/server.key", 60, 950),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is True

    def test_env_in_rewritten_command_sets_sensitive(self) -> None:
        result = _make_result(rewritten_command="cat /tmp/shadow/.env")
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is True

    def test_pem_file_deleted_sets_sensitive(self) -> None:
        before = (("cert.pem", 200, 1000),)
        after = ()
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is True

    def test_normal_src_file_not_sensitive(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 200, 1000),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is False

    def test_no_changes_no_sensitive(self) -> None:
        result = _make_result()
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is False


# ---------------------------------------------------------------------------
# Writes outside src/
# ---------------------------------------------------------------------------

class TestWritesOutsideSrc:
    def test_file_created_outside_src_flagged(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 100, 1000), ("report.txt", 5, 2000))
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "report.txt" in diff.writes_outside_src

    def test_file_modified_outside_src_flagged(self) -> None:
        before = ((".env", 100, 1000),)
        after = ((".env", 200, 2000),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert ".env" in diff.writes_outside_src

    def test_file_inside_src_not_flagged(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 200, 2000),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "src/main.py" not in diff.writes_outside_src
        assert diff.writes_outside_src == ()

    def test_nested_src_path_not_flagged(self) -> None:
        before = (("src/sub/helper.py", 50, 800),)
        after = (("src/sub/helper.py", 60, 900),)
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert diff.writes_outside_src == ()

    def test_mixed_inside_and_outside_src(self) -> None:
        before = (("src/main.py", 100, 1000),)
        after = (("src/main.py", 200, 2000), ("outside.txt", 5, 3000))
        result = _make_result(shadow_before=before, shadow_after=after)
        diff = DiffExtractor.extract(result)
        assert "outside.txt" in diff.writes_outside_src
        assert "src/main.py" not in diff.writes_outside_src


# ---------------------------------------------------------------------------
# Best-effort files_read
# ---------------------------------------------------------------------------

class TestFilesRead:
    def test_path_token_in_rewritten_command(self) -> None:
        result = _make_result(
            rewritten_command="cat src/main.py",
            shadow_before=(("src/main.py", 100, 1000),),
        )
        diff = DiffExtractor.extract(result)
        assert "src/main.py" in diff.files_read

    def test_absolute_shadow_path_stripped_to_relative(self) -> None:
        shadow = Path("/tmp/shadowcommit_shadow_abc")
        result = _make_result(
            rewritten_command=f"cat {shadow}/src/main.py",
            shadow_path=shadow,
            shadow_before=(("src/main.py", 100, 1000),),
        )
        diff = DiffExtractor.extract(result)
        assert "src/main.py" in diff.files_read

    def test_flag_tokens_not_treated_as_paths(self) -> None:
        result = _make_result(rewritten_command="autopep8 --in-place src/main.py")
        diff = DiffExtractor.extract(result)
        assert "--in-place" not in diff.files_read

    def test_empty_command_yields_empty_reads(self) -> None:
        result = _make_result(rewritten_command="")
        diff = DiffExtractor.extract(result)
        assert diff.files_read == ()

    def test_no_duplicate_paths_in_files_read(self) -> None:
        result = _make_result(
            rewritten_command="cat src/main.py src/main.py",
            shadow_before=(("src/main.py", 100, 1000),),
        )
        diff = DiffExtractor.extract(result)
        assert diff.files_read.count("src/main.py") == 1


# ---------------------------------------------------------------------------
# Integration: full pipeline with ShadowExecutor
# ---------------------------------------------------------------------------

class TestDiffExtractorIntegration:
    def test_echo_no_file_changes(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo hi", workspace)
        diff = DiffExtractor.extract(result)
        assert diff.files_created == ()
        assert diff.files_modified == ()
        assert diff.files_deleted == ()

    def test_touch_creates_file(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("touch newfile.txt", workspace)
        diff = DiffExtractor.extract(result)
        assert "newfile.txt" in diff.files_created

    def test_rm_deletes_file(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("rm src/utils.py", workspace)
        diff = DiffExtractor.extract(result)
        assert "src/utils.py" in diff.files_deleted

    def test_append_modifies_file(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo x >> src/main.py", workspace)
        diff = DiffExtractor.extract(result)
        assert "src/main.py" in diff.files_modified

    def test_touch_outside_src_in_writes_outside(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("touch outside.txt", workspace)
        diff = DiffExtractor.extract(result)
        assert "outside.txt" in diff.writes_outside_src

    def test_src_modification_not_in_writes_outside(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("echo x >> src/main.py", workspace)
        diff = DiffExtractor.extract(result)
        assert "src/main.py" not in diff.writes_outside_src

    def test_adversarial_command_sensitive_paths_touched(self, workspace: Path) -> None:
        agent = AdversarialAgent(workspace)
        env_abs = str(workspace / ".env")
        exfil_cmd = next(cmd for cmd in agent.generate_commands() if env_abs in cmd)
        result = ShadowExecutor().execute(exfil_cmd, workspace)
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is True

    def test_adversarial_command_env_in_files_read(self, workspace: Path) -> None:
        # /tmp/format_report.txt is written to an absolute path outside the shadow
        # copy, so it is invisible to fingerprint-based detection (documented
        # limitation). The critical signal is that .env appears in files_read
        # and sensitive_paths_touched is True.
        agent = AdversarialAgent(workspace)
        env_abs = str(workspace / ".env")
        exfil_cmd = next(cmd for cmd in agent.generate_commands() if env_abs in cmd)
        result = ShadowExecutor().execute(exfil_cmd, workspace)
        diff = DiffExtractor.extract(result)
        assert diff.sensitive_paths_touched is True
        assert ".env" in diff.files_read

    def test_real_workspace_untouched_throughout(self, workspace: Path) -> None:
        result = ShadowExecutor().execute("touch newfile.txt && echo x >> src/main.py", workspace)
        diff = DiffExtractor.extract(result)
        assert result.real_workspace_untouched is True
        # Changes happened only in shadow
        assert "newfile.txt" in diff.files_created
