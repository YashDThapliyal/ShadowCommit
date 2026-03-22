"""Tests for shadowcommit.environment.workspace."""
import tempfile
from pathlib import Path

import pytest

from shadowcommit.constants import DEFAULT_SRC_DIR, FAKE_ENV_CONTENT
from shadowcommit.environment.sample_files import get_sample_files
from shadowcommit.environment.workspace import create_workspace, teardown_workspace


class TestCreateWorkspace:
    def test_returns_path(self) -> None:
        ws = create_workspace()
        try:
            assert isinstance(ws, Path)
        finally:
            teardown_workspace(ws)

    def test_is_absolute(self) -> None:
        ws = create_workspace()
        try:
            assert ws.is_absolute()
        finally:
            teardown_workspace(ws)

    def test_directory_exists(self) -> None:
        ws = create_workspace()
        try:
            assert ws.is_dir()
        finally:
            teardown_workspace(ws)

    def test_created_in_system_temp(self) -> None:
        ws = create_workspace()
        try:
            assert str(ws).startswith(tempfile.gettempdir())
        finally:
            teardown_workspace(ws)

    def test_src_directory_exists(self) -> None:
        ws = create_workspace()
        try:
            assert (ws / DEFAULT_SRC_DIR).is_dir()
        finally:
            teardown_workspace(ws)

    def test_sample_files_created(self) -> None:
        ws = create_workspace()
        try:
            for rel_path in get_sample_files():
                assert (ws / rel_path).is_file(), f"Missing: {rel_path}"
        finally:
            teardown_workspace(ws)

    def test_sample_file_content_matches(self) -> None:
        ws = create_workspace()
        try:
            for rel_path, expected_content in get_sample_files().items():
                actual = (ws / rel_path).read_text()
                assert actual == expected_content, f"Content mismatch in {rel_path}"
        finally:
            teardown_workspace(ws)

    def test_env_file_at_workspace_root(self) -> None:
        ws = create_workspace()
        try:
            env_path = ws / ".env"
            assert env_path.is_file(), ".env must exist at workspace root"
        finally:
            teardown_workspace(ws)

    def test_env_file_not_inside_src(self) -> None:
        ws = create_workspace()
        try:
            assert not (ws / DEFAULT_SRC_DIR / ".env").exists()
        finally:
            teardown_workspace(ws)

    def test_env_file_content(self) -> None:
        ws = create_workspace()
        try:
            content = (ws / ".env").read_text()
            assert content == FAKE_ENV_CONTENT
        finally:
            teardown_workspace(ws)

    def test_each_call_produces_unique_directory(self) -> None:
        ws1 = create_workspace()
        ws2 = create_workspace()
        try:
            assert ws1 != ws2
        finally:
            teardown_workspace(ws1)
            teardown_workspace(ws2)


class TestTeardownWorkspace:
    def test_removes_directory(self) -> None:
        ws = create_workspace()
        teardown_workspace(ws)
        assert not ws.exists()

    def test_nonexistent_path_does_not_raise(self) -> None:
        phantom = Path(tempfile.gettempdir()) / "shadowcommit_does_not_exist_xyz"
        teardown_workspace(phantom)  # should not raise

    def test_removes_nested_contents(self) -> None:
        ws = create_workspace()
        teardown_workspace(ws)
        assert not ws.exists()
