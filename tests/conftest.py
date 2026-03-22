"""Shared pytest fixtures for the ShadowCommit test suite."""
from pathlib import Path

import pytest

from shadowcommit.environment.workspace import create_workspace, teardown_workspace


@pytest.fixture
def workspace() -> "Path":
    """Provide a fresh isolated workspace, cleaned up after the test."""
    ws = create_workspace()
    yield ws
    teardown_workspace(ws)
