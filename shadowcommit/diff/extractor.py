"""Diff extractor — measures actual effects of a shadow-executed command.

Compares shadow copy fingerprints taken before and after execution to
determine which files were created, modified, or deleted. Applies
heuristics to detect network activity and sensitive path access.

Known limitations (MVP):
- files_read is best-effort: extracted from path-like tokens in the
  rewritten command rather than from true syscall tracing.
- Network detection is heuristic: scans stdout/stderr for known patterns
  and may produce false positives (e.g. a file containing a URL that gets
  printed to stdout).
- Files written outside /tmp (e.g. /tmp/format_report.txt) are captured
  only if they appear in the shadow fingerprint, which requires the shadow
  copy to include that path. Commands writing to absolute paths outside the
  workspace are not fingerprinted and will not appear in files_created.
"""
import dataclasses
import shlex
from pathlib import PurePosixPath

from shadowcommit.constants import (
    DEFAULT_SRC_DIR,
    NETWORK_HEURISTIC_RE,
    is_sensitive_path,
)
from shadowcommit.shadow.executor import ExecutionResult


@dataclasses.dataclass(frozen=True)
class ObservedDiff:
    """Immutable record of what a shadow-executed command actually did.

    All path fields contain relative paths (relative to the shadow/workspace root)
    unless the command wrote to an absolute path outside the workspace.
    """

    command: str
    files_read: tuple[str, ...]
    files_modified: tuple[str, ...]
    files_created: tuple[str, ...]
    files_deleted: tuple[str, ...]
    sensitive_paths_touched: bool
    network_activity_detected: bool
    writes_outside_src: tuple[str, ...]


def _compare_fingerprints(
    before: tuple[tuple[str, int, int], ...],
    after: tuple[tuple[str, int, int], ...],
) -> tuple[list[str], list[str], list[str]]:
    """Compare before/after fingerprints and return (modified, created, deleted).

    Args:
        before: Fingerprint snapshot before execution.
        after: Fingerprint snapshot after execution.

    Returns:
        Tuple of (files_modified, files_created, files_deleted) as path lists.
    """
    before_map = {rel: (size, mtime) for rel, size, mtime in before}
    after_map = {rel: (size, mtime) for rel, size, mtime in after}

    modified = [
        path for path in before_map
        if path in after_map and before_map[path] != after_map[path]
    ]
    created = [path for path in after_map if path not in before_map]
    deleted = [path for path in before_map if path not in after_map]

    return sorted(modified), sorted(created), sorted(deleted)


def _extract_files_read(result: ExecutionResult) -> list[str]:
    """Best-effort extraction of files read during command execution.

    Parses path-like tokens from the rewritten command. Converts absolute
    shadow paths to relative paths. Only returns paths that existed in the
    shadow before execution (i.e. were available to read).

    Args:
        result: The ExecutionResult to analyse.

    Returns:
        Deduplicated list of relative paths plausibly read by the command.
    """
    shadow_str = str(result.shadow_path)
    known_paths = {entry[0] for entry in result.shadow_before}

    try:
        tokens = shlex.split(result.rewritten_command)
    except ValueError:
        tokens = result.rewritten_command.split()

    candidates: list[str] = []
    for token in tokens:
        if token.startswith("-"):
            continue
        # Strip shadow prefix to get relative path
        if token.startswith(shadow_str):
            rel = token[len(shadow_str):].lstrip("/")
        else:
            rel = token

        if not rel or rel.startswith("-"):
            continue
        if "/" not in rel and "." not in rel:
            continue
        if rel in known_paths:
            candidates.append(rel)

    # Deduplicate preserving order
    seen: set[str] = set()
    result_list: list[str] = []
    for p in candidates:
        if p not in seen:
            seen.add(p)
            result_list.append(p)
    return result_list


def _detect_writes_outside_src(
    files_modified: list[str],
    files_created: list[str],
) -> list[str]:
    """Return paths in files_modified or files_created that are outside src/.

    Args:
        files_modified: Relative paths of modified files.
        files_created: Relative paths of created files.

    Returns:
        Sorted list of paths not under DEFAULT_SRC_DIR/.
    """
    prefix = DEFAULT_SRC_DIR + "/"
    outside = [
        p for p in (files_modified + files_created)
        if not p.startswith(prefix)
    ]
    return sorted(set(outside))


def _check_sensitive(
    files_read: list[str],
    files_modified: list[str],
    files_created: list[str],
    files_deleted: list[str],
    rewritten_command: str,
) -> bool:
    """Return True if any changed path or command token is sensitive.

    Args:
        files_read: Best-effort read paths.
        files_modified: Modified paths.
        files_created: Created paths.
        files_deleted: Deleted paths.
        rewritten_command: The command as it was executed.

    Returns:
        True if a sensitive pattern was matched anywhere.
    """
    all_paths = files_read + files_modified + files_created + files_deleted
    if any(is_sensitive_path(p) for p in all_paths):
        return True

    # Also scan command tokens for sensitive paths (catches cat .env-style reads
    # that don't appear in the fingerprint diff because files aren't modified)
    try:
        tokens = shlex.split(rewritten_command)
    except ValueError:
        tokens = rewritten_command.split()

    for token in tokens:
        name = PurePosixPath(token).name
        if is_sensitive_path(token) or is_sensitive_path(name):
            return True

    return False


class DiffExtractor:
    """Extracts an ObservedDiff from an ExecutionResult."""

    @staticmethod
    def extract(result: ExecutionResult) -> ObservedDiff:
        """Analyse an ExecutionResult and return the observed effects.

        Args:
            result: The result of a ShadowExecutor.execute() call.

        Returns:
            ObservedDiff describing what the command actually did.
        """
        modified, created, deleted = _compare_fingerprints(
            result.shadow_before, result.shadow_after
        )

        files_read = _extract_files_read(result)

        network = bool(
            NETWORK_HEURISTIC_RE.search(result.stdout)
            or NETWORK_HEURISTIC_RE.search(result.stderr)
        )

        writes_outside = _detect_writes_outside_src(modified, created)

        sensitive = _check_sensitive(
            files_read, modified, created, deleted, result.rewritten_command
        )

        return ObservedDiff(
            command=result.command,
            files_read=tuple(files_read),
            files_modified=tuple(modified),
            files_created=tuple(created),
            files_deleted=tuple(deleted),
            sensitive_paths_touched=sensitive,
            network_activity_detected=network,
            writes_outside_src=tuple(writes_outside),
        )
