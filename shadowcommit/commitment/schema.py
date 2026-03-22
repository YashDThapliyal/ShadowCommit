"""Commitment dataclass — the structured pre-execution prediction every command must emit."""
import dataclasses
import json
from typing import Any


@dataclasses.dataclass(frozen=True)
class Commitment:
    """Immutable record of what an agent predicts a command will do.

    All fields are set at construction time and cannot be mutated.
    Use from_dict() / from_json() to deserialize with validation.
    """

    command: str
    purpose: str
    files_read: list[str]
    files_modified: list[str]
    files_created: list[str]
    network_expected: bool
    sensitive_paths_expected: bool
    privileged_changes_expected: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Commitment":
        """Deserialize from a dictionary, raising ValueError on invalid input.

        Args:
            data: Dictionary with all required Commitment fields.

        Raises:
            ValueError: If required fields are missing, have wrong types, or are empty.
            KeyError: If a required key is absent.
        """
        command = data["command"]
        purpose = data["purpose"]

        if not isinstance(command, str) or not command.strip():
            raise ValueError("'command' must be a non-empty string")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("'purpose' must be a non-empty string")

        for list_field in ("files_read", "files_modified", "files_created"):
            if not isinstance(data[list_field], list):
                raise ValueError(f"'{list_field}' must be a list")

        for bool_field in ("network_expected", "sensitive_paths_expected", "privileged_changes_expected"):
            if not isinstance(data[bool_field], bool):
                raise ValueError(f"'{bool_field}' must be a bool")

        return cls(
            command=command,
            purpose=purpose,
            files_read=list(data["files_read"]),
            files_modified=list(data["files_modified"]),
            files_created=list(data["files_created"]),
            network_expected=data["network_expected"],
            sensitive_paths_expected=data["sensitive_paths_expected"],
            privileged_changes_expected=data["privileged_changes_expected"],
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Commitment":
        """Deserialize from a JSON string.

        Args:
            json_str: JSON-encoded commitment.

        Raises:
            ValueError: If the JSON is invalid or fields fail validation.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc
        return cls.from_dict(data)
