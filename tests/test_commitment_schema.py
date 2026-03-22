"""Tests for shadowcommit.commitment.schema — Commitment dataclass."""
import json
import pytest
from shadowcommit.commitment.schema import Commitment


MINIMAL = dict(
    command="ls src/",
    purpose="list files",
    files_read=[],
    files_modified=[],
    files_created=[],
    network_expected=False,
    sensitive_paths_expected=False,
    privileged_changes_expected=False,
)


class TestCommitmentCreation:
    def test_all_fields_stored(self) -> None:
        c = Commitment(**MINIMAL)
        assert c.command == "ls src/"
        assert c.purpose == "list files"
        assert c.files_read == []
        assert c.files_modified == []
        assert c.files_created == []
        assert c.network_expected is False
        assert c.sensitive_paths_expected is False
        assert c.privileged_changes_expected is False

    def test_with_populated_lists(self) -> None:
        c = Commitment(
            command="cat foo.txt",
            purpose="read file",
            files_read=["foo.txt"],
            files_modified=[],
            files_created=[],
            network_expected=False,
            sensitive_paths_expected=False,
            privileged_changes_expected=False,
        )
        assert c.files_read == ["foo.txt"]

    def test_boolean_fields_are_bool(self) -> None:
        c = Commitment(**MINIMAL)
        assert isinstance(c.network_expected, bool)
        assert isinstance(c.sensitive_paths_expected, bool)
        assert isinstance(c.privileged_changes_expected, bool)


class TestCommitmentImmutability:
    def test_cannot_assign_field(self) -> None:
        c = Commitment(**MINIMAL)
        with pytest.raises((AttributeError, TypeError)):
            c.command = "other"  # type: ignore[misc]

    def test_cannot_assign_list_field(self) -> None:
        c = Commitment(**MINIMAL)
        with pytest.raises((AttributeError, TypeError)):
            c.files_read = ["x"]  # type: ignore[misc]


class TestCommitmentValidation:
    def test_empty_command_raises(self) -> None:
        data = {**MINIMAL, "command": ""}
        with pytest.raises(ValueError, match="command"):
            Commitment.from_dict(data)

    def test_empty_purpose_raises(self) -> None:
        data = {**MINIMAL, "purpose": ""}
        with pytest.raises(ValueError, match="purpose"):
            Commitment.from_dict(data)

    def test_missing_required_key_raises(self) -> None:
        data = {k: v for k, v in MINIMAL.items() if k != "command"}
        with pytest.raises((ValueError, KeyError)):
            Commitment.from_dict(data)

    def test_files_read_wrong_type_raises(self) -> None:
        data = {**MINIMAL, "files_read": "not-a-list"}
        with pytest.raises(ValueError):
            Commitment.from_dict(data)

    def test_network_expected_wrong_type_raises(self) -> None:
        data = {**MINIMAL, "network_expected": "yes"}
        with pytest.raises(ValueError):
            Commitment.from_dict(data)


class TestCommitmentSerialization:
    def test_to_dict_returns_dict(self) -> None:
        c = Commitment(**MINIMAL)
        assert isinstance(c.to_dict(), dict)

    def test_to_dict_round_trips(self) -> None:
        c = Commitment(**MINIMAL)
        assert c.to_dict() == MINIMAL

    def test_to_json_returns_string(self) -> None:
        c = Commitment(**MINIMAL)
        assert isinstance(c.to_json(), str)

    def test_to_json_is_valid_json(self) -> None:
        c = Commitment(**MINIMAL)
        parsed = json.loads(c.to_json())
        assert parsed["command"] == "ls src/"

    def test_from_dict_round_trips(self) -> None:
        c = Commitment(**MINIMAL)
        assert Commitment.from_dict(c.to_dict()) == c

    def test_from_json_round_trips(self) -> None:
        c = Commitment(**MINIMAL)
        assert Commitment.from_json(c.to_json()) == c

    def test_from_json_invalid_json_raises(self) -> None:
        with pytest.raises((ValueError, json.JSONDecodeError)):
            Commitment.from_json("not json {{{")
