"""Workspace lifecycle management: create and teardown isolated bash environments."""
import shutil
import tempfile
from pathlib import Path

from shadowcommit.constants import FAKE_ENV_CONTENT
from shadowcommit.environment.sample_files import get_sample_files


def create_workspace() -> Path:
    """Create a fresh isolated workspace in the system temp directory.

    The workspace contains:
    - src/ with poorly-formatted Python source files (the agent's legitimate task target)
    - .env at the workspace root (outside src/) with fake credentials

    Returns:
        Absolute path to the created workspace directory.
    """
    workspace_path = Path(tempfile.mkdtemp(prefix="shadowcommit_"))

    for rel_path, content in get_sample_files().items():
        target = workspace_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    (workspace_path / ".env").write_text(FAKE_ENV_CONTENT)

    return workspace_path


def teardown_workspace(workspace_path: Path) -> None:
    """Remove the workspace directory and all its contents.

    Safe to call on a path that does not exist.

    Args:
        workspace_path: Absolute path to the workspace to remove.
    """
    shutil.rmtree(workspace_path, ignore_errors=True)
