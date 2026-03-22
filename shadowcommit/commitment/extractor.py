"""Static bash command analyzer that produces best-effort Commitment predictions.

Limitations (known and accepted for MVP):
- Chained command splitting on &&, ||, ;, | is naive and breaks on quoted
  occurrences of those operators.
- Path extraction is heuristic — may produce false positives from flag arguments
  that happen to look like paths.
- Does not handle shell obfuscation (base64, eval, variable expansion, etc.).
  Obfuscated commands that slip past this analyzer will still be caught in
  Phase 5 when the shadow executor's observed diff is compared to the commitment.
"""
import fnmatch
import re
import shlex
from pathlib import PurePosixPath

from shadowcommit.commitment.schema import Commitment
from shadowcommit.constants import SENSITIVE_PATTERNS

# Commands whose first token indicates the following arguments are files being read.
_READ_VERBS: frozenset[str] = frozenset({
    "cat", "head", "tail", "less", "more", "grep", "diff", "view",
})

# Flags that indicate in-place modification of file arguments.
_MODIFY_FLAGS: frozenset[str] = frozenset({"--in-place", "-i"})

# Commands whose first token indicates file creation.
_CREATE_VERBS: frozenset[str] = frozenset({"touch", "mkdir", "mktemp"})

# Commands that imply network activity.
_NETWORK_VERBS: frozenset[str] = frozenset({
    "curl", "wget", "nc", "ncat", "ssh", "scp", "rsync",
    "ping", "nslookup", "dig", "ftp", "sftp",
})

# Commands that imply privileged operations.
_PRIVILEGED_VERBS: frozenset[str] = frozenset({"sudo", "chmod", "chown", "chgrp", "mount"})

# Regex for `>>` (append to existing file) and `>` (overwrite/create file).
# Matches the redirect operator and the following filename token.
_APPEND_RE = re.compile(r">>\s*(\S+)")
_OVERWRITE_RE = re.compile(r"(?<!>)>\s*(\S+)")


def _looks_like_path(token: str) -> bool:
    """Return True if token plausibly refers to a file system path."""
    return "/" in token or "." in token


def _split_subcommands(command: str) -> list[str]:
    """Split a shell command string into sub-commands on &&, ||, ;, and |.

    This is a naive split that does not account for quoting.
    """
    return re.split(r"\s*(?:&&|\|\||\||;)\s*", command)


def _is_sensitive(path: str) -> bool:
    """Return True if path matches any pattern in SENSITIVE_PATTERNS."""
    name = PurePosixPath(path).name
    for pattern in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
            return True
    return False


def _analyze_subcommand(
    sub: str,
) -> tuple[list[str], list[str], list[str], bool, bool, bool]:
    """Analyze a single (non-chained) sub-command.

    Returns:
        (files_read, files_modified, files_created, network, sensitive, privileged)
    """
    files_read: list[str] = []
    files_modified: list[str] = []
    files_created: list[str] = []
    network = False
    sensitive = False
    privileged = False

    try:
        tokens = shlex.split(sub)
    except ValueError:
        tokens = sub.split()

    if not tokens:
        return files_read, files_modified, files_created, network, sensitive, privileged

    verb = tokens[0].lstrip("./")

    # Network detection
    if verb in _NETWORK_VERBS:
        network = True

    # Privileged detection
    if verb in _PRIVILEGED_VERBS:
        privileged = True

    # autopep8 --diff → read; autopep8 --in-place → modify
    if verb == "autopep8":
        is_diff = "--diff" in tokens
        is_inplace = "--in-place" in tokens or "-i" in tokens
        for tok in tokens[1:]:
            if tok.startswith("-"):
                continue
            if _looks_like_path(tok):
                if is_diff:
                    files_read.append(tok)
                elif is_inplace:
                    files_modified.append(tok)

    # sed -i → modify
    elif verb == "sed":
        if "-i" in tokens:
            for tok in tokens[1:]:
                if tok.startswith("-") or tok.startswith("s/") or tok.startswith("'s/"):
                    continue
                if _looks_like_path(tok):
                    files_modified.append(tok)

    # find → read the target directory
    elif verb == "find":
        if len(tokens) > 1 and not tokens[1].startswith("-"):
            files_read.append(tokens[1])

    # touch/mkdir/mktemp → create
    elif verb in _CREATE_VERBS:
        for tok in tokens[1:]:
            if not tok.startswith("-"):
                files_created.append(tok)

    # Generic read verbs: cat, grep, diff, etc.
    elif verb in _READ_VERBS:
        for tok in tokens[1:]:
            if tok.startswith("-"):
                continue
            if _looks_like_path(tok):
                files_read.append(tok)

    # Redirect detection (applies on top of verb analysis)
    for match in _APPEND_RE.finditer(sub):
        path = match.group(1)
        if path not in files_modified:
            files_modified.append(path)

    for match in _OVERWRITE_RE.finditer(sub):
        path = match.group(1)
        if path not in files_created:
            files_created.append(path)

    # Sensitive path check across all collected paths
    all_paths = files_read + files_modified + files_created
    # Also scan raw tokens for path-like arguments we may have missed
    for tok in tokens:
        if _looks_like_path(tok) and not tok.startswith("-"):
            all_paths.append(tok)

    if any(_is_sensitive(p) for p in all_paths):
        sensitive = True

    return files_read, files_modified, files_created, network, sensitive, privileged


class CommitmentExtractor:
    """Produces honest, best-effort Commitment predictions from bash command strings."""

    @staticmethod
    def extract(command: str, purpose: str) -> Commitment:
        """Analyze a bash command string and return a predicted Commitment.

        Handles &&, ||, ;, and | chained commands by unioning their effects.

        Args:
            command: The bash command string to analyze.
            purpose: Human-readable description of the command's intent.

        Returns:
            A Commitment representing the predicted effects.
        """
        subcommands = _split_subcommands(command)

        all_read: list[str] = []
        all_modified: list[str] = []
        all_created: list[str] = []
        network = False
        sensitive = False
        privileged = False

        for sub in subcommands:
            r, m, c, n, s, p = _analyze_subcommand(sub.strip())
            all_read.extend(r)
            all_modified.extend(m)
            all_created.extend(c)
            network = network or n
            sensitive = sensitive or s
            privileged = privileged or p

        # Deduplicate while preserving order
        def _dedup(lst: list[str]) -> list[str]:
            seen: set[str] = set()
            result = []
            for item in lst:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        return Commitment(
            command=command,
            purpose=purpose,
            files_read=_dedup(all_read),
            files_modified=_dedup(all_modified),
            files_created=_dedup(all_created),
            network_expected=network,
            sensitive_paths_expected=sensitive,
            privileged_changes_expected=privileged,
        )
