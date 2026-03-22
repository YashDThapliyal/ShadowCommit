"""Shadow execution engine — clones the workspace, runs commands in isolation, tears down after.

The real workspace is never modified by command execution. All effects are
confined to the shadow copy, which is always torn down after execution.

Known limitations (MVP):
- Background processes spawned by a command may survive shadow teardown.
- Shell obfuscation that avoids path rewriting will not be caught here;
  Phase 5 diff comparison provides a second layer of defense.
- Fingerprinting uses mtime_ns + size; noatime mounts weaken the mtime signal
  but size and file count still detect most mutations.
"""
import dataclasses
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

# Type alias for a single fingerprint snapshot.
# Each entry is (relative_path, size_bytes, mtime_nanoseconds).
_Fingerprint = tuple[tuple[str, int, int], ...]


@dataclasses.dataclass(frozen=True)
class ExecutionResult:
    """Immutable record of a single shadow-executed command.

    Return codes -1 and -2 are sentinels:
      -1: command exceeded the configured timeout
      -2: an unexpected internal error occurred before/during execution

    shadow_before and shadow_after hold fingerprints of the shadow copy
    taken immediately before and after command execution, enabling the
    DiffExtractor (Phase 4) to measure file-level effects without needing
    the shadow directory to still exist.
    """

    command: str
    rewritten_command: str
    shadow_path: Path
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    real_workspace_untouched: bool
    timed_out: bool
    # Default () so existing test helpers that don't supply these still work.
    shadow_before: _Fingerprint = ()
    shadow_after: _Fingerprint = ()


def _rewrite_paths(command: str, real_path: Path, shadow_path: Path) -> str:
    """Replace all occurrences of real_path in command with shadow_path.

    Uses simple string replacement. Safe because workspace paths are created
    via tempfile.mkdtemp with random suffixes, making accidental collisions
    effectively impossible.

    Args:
        command: The original bash command string.
        real_path: The real workspace directory path to replace.
        shadow_path: The shadow copy path to substitute in.

    Returns:
        Command string with all real_path occurrences replaced.
    """
    return command.replace(str(real_path), str(shadow_path))


def _fingerprint_workspace(workspace_path: Path) -> list[tuple[str, int, int]]:
    """Compute a fingerprint of a workspace directory.

    Walks the entire directory tree and returns a sorted list of
    (relative_path, file_size_bytes, mtime_nanoseconds) tuples.
    An identical fingerprint before and after execution means the
    workspace was not modified.

    Args:
        workspace_path: Directory to fingerprint.

    Returns:
        Sorted list of (rel_path, size, mtime_ns) tuples for every file.
    """
    entries: list[tuple[str, int, int]] = []
    for file_path in workspace_path.rglob("*"):
        if file_path.is_file():
            stat = file_path.stat()
            rel = str(file_path.relative_to(workspace_path))
            entries.append((rel, stat.st_size, stat.st_mtime_ns))
    return sorted(entries, key=lambda t: t[0])


class ShadowExecutor:
    """Executes bash commands in an isolated shadow copy of the workspace.

    The real workspace is fingerprinted before and after execution to
    verify it was not touched. The shadow copy is fingerprinted before
    and after execution so the DiffExtractor can measure effects even
    after the shadow directory is torn down.
    """

    def __init__(self, timeout: float = 30.0) -> None:
        """Initialise the executor.

        Args:
            timeout: Maximum wall-clock seconds allowed per command.
                     Exceeded commands are killed and marked timed_out=True.
        """
        self.timeout = timeout

    def execute(self, command: str, workspace_path: Path) -> ExecutionResult:
        """Clone workspace, execute command in shadow, capture results, teardown.

        Args:
            command: Bash command string to execute (may contain absolute paths
                     pointing at workspace_path; these are rewritten to the shadow).
            workspace_path: Absolute path to the real workspace directory.

        Returns:
            ExecutionResult with all captured data. shadow_path will not exist
            on disk after this method returns.
        """
        before_fp = _fingerprint_workspace(workspace_path)
        shadow_path = Path(tempfile.mkdtemp(prefix="shadowcommit_shadow_"))

        shadow_fp_before: _Fingerprint = ()
        shadow_fp_after: _Fingerprint = ()
        stdout = ""
        stderr = ""
        returncode = -2
        timed_out = False
        duration = 0.0
        rewritten = command

        try:
            shutil.copytree(str(workspace_path), str(shadow_path), dirs_exist_ok=True)
            rewritten = _rewrite_paths(command, workspace_path, shadow_path)
            shadow_fp_before = tuple(_fingerprint_workspace(shadow_path))

            start = time.monotonic()

            try:
                proc = subprocess.run(
                    rewritten,
                    shell=True,
                    cwd=str(shadow_path),
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                stdout = proc.stdout
                stderr = proc.stderr
                returncode = proc.returncode

            except subprocess.TimeoutExpired as exc:
                timed_out = True
                returncode = -1
                stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")

            duration = time.monotonic() - start
            shadow_fp_after = tuple(_fingerprint_workspace(shadow_path))

        finally:
            shutil.rmtree(shadow_path, ignore_errors=True)

        after_fp = _fingerprint_workspace(workspace_path)
        real_workspace_untouched = before_fp == after_fp

        return ExecutionResult(
            command=command,
            rewritten_command=rewritten,
            shadow_path=shadow_path,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            duration_seconds=duration,
            real_workspace_untouched=real_workspace_untouched,
            timed_out=timed_out,
            shadow_before=shadow_fp_before,
            shadow_after=shadow_fp_after,
        )
