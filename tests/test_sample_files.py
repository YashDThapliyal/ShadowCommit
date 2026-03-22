"""Tests for shadowcommit.environment.sample_files."""
import ast
from shadowcommit.environment.sample_files import get_sample_files


class TestGetSampleFiles:
    def test_returns_dict(self) -> None:
        result = get_sample_files()
        assert isinstance(result, dict)

    def test_non_empty(self) -> None:
        assert len(get_sample_files()) >= 2

    def test_all_keys_are_strings(self) -> None:
        for key in get_sample_files():
            assert isinstance(key, str)

    def test_all_values_are_strings(self) -> None:
        for value in get_sample_files().values():
            assert isinstance(value, str)

    def test_all_paths_are_relative(self) -> None:
        for path in get_sample_files():
            assert not path.startswith("/"), f"Path must be relative: {path}"

    def test_all_paths_under_src(self) -> None:
        for path in get_sample_files():
            assert path.startswith("src/"), f"Path must be under src/: {path}"

    def test_all_paths_are_python_files(self) -> None:
        for path in get_sample_files():
            assert path.endswith(".py"), f"Expected .py file: {path}"

    def test_all_content_is_valid_python(self) -> None:
        for path, content in get_sample_files().items():
            try:
                ast.parse(content)
            except SyntaxError as exc:
                raise AssertionError(f"Invalid Python in {path}: {exc}") from exc

    def test_content_is_poorly_formatted(self) -> None:
        """At least one file must contain formatting issues autopep8 would fix."""
        all_content = "\n".join(get_sample_files().values())
        # autopep8 fixes: missing spaces around operators, extra whitespace,
        # lines without blank lines between functions, etc.
        has_formatting_issue = (
            "  " in all_content  # extra indentation or spacing
            or ",\n" in all_content  # trailing comma patterns
            or any(
                "=" in line and "==" not in line and " = " not in line
                for line in all_content.splitlines()
                if "def " not in line and "class " not in line
            )
        )
        assert has_formatting_issue, "Sample files should contain formatting issues"

    def test_no_duplicate_paths(self) -> None:
        files = get_sample_files()
        assert len(files) == len(set(files.keys()))
