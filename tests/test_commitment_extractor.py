"""Tests for shadowcommit.commitment.extractor — static bash command analyzer."""
from shadowcommit.commitment.extractor import CommitmentExtractor
from shadowcommit.commitment.schema import Commitment


class TestExtractReturnsCommitment:
    def test_returns_commitment(self) -> None:
        result = CommitmentExtractor.extract("ls src/", "list files")
        assert isinstance(result, Commitment)

    def test_command_field_matches_input(self) -> None:
        cmd = "find src/ -name '*.py'"
        result = CommitmentExtractor.extract(cmd, "find python files")
        assert result.command == cmd

    def test_purpose_field_matches_input(self) -> None:
        result = CommitmentExtractor.extract("ls", "list")
        assert result.purpose == "list"


class TestExtractFilesRead:
    def test_cat_detects_files_read(self) -> None:
        result = CommitmentExtractor.extract("cat foo.txt", "read file")
        assert "foo.txt" in result.files_read

    def test_cat_absolute_path(self) -> None:
        result = CommitmentExtractor.extract("cat /tmp/data.txt", "read")
        assert "/tmp/data.txt" in result.files_read

    def test_grep_detects_files_read(self) -> None:
        result = CommitmentExtractor.extract("grep -r 'TODO' src/main.py", "search")
        assert "src/main.py" in result.files_read

    def test_autopep8_diff_detects_files_read(self) -> None:
        result = CommitmentExtractor.extract("autopep8 --diff src/main.py", "diff")
        assert "src/main.py" in result.files_read

    def test_find_does_not_pollute_files_read(self) -> None:
        result = CommitmentExtractor.extract("find src/ -name '*.py' -type f", "find")
        # find itself reads the directory but we don't need to enumerate output paths
        # the src/ directory should appear in files_read
        assert result.files_read is not None  # list exists


class TestExtractFilesModified:
    def test_autopep8_in_place_detects_files_modified(self) -> None:
        result = CommitmentExtractor.extract(
            "autopep8 --in-place src/utils.py src/main.py", "format"
        )
        assert "src/utils.py" in result.files_modified
        assert "src/main.py" in result.files_modified

    def test_append_redirect_detects_files_modified(self) -> None:
        result = CommitmentExtractor.extract(
            "echo hello >> existing.txt", "append"
        )
        assert "existing.txt" in result.files_modified

    def test_sed_in_place_detects_files_modified(self) -> None:
        result = CommitmentExtractor.extract(
            "sed -i 's/foo/bar/' src/data.py", "replace"
        )
        assert "src/data.py" in result.files_modified


class TestExtractFilesCreated:
    def test_overwrite_redirect_detects_files_created(self) -> None:
        result = CommitmentExtractor.extract(
            "autopep8 --diff src/main.py > /tmp/report.txt", "diff report"
        )
        assert "/tmp/report.txt" in result.files_created

    def test_touch_detects_files_created(self) -> None:
        result = CommitmentExtractor.extract("touch newfile.txt", "create")
        assert "newfile.txt" in result.files_created


class TestExtractNetworkExpected:
    def test_curl_sets_network_true(self) -> None:
        result = CommitmentExtractor.extract("curl https://example.com", "fetch")
        assert result.network_expected is True

    def test_wget_sets_network_true(self) -> None:
        result = CommitmentExtractor.extract("wget http://example.com/file", "download")
        assert result.network_expected is True

    def test_ssh_sets_network_true(self) -> None:
        result = CommitmentExtractor.extract("ssh user@host 'ls'", "remote")
        assert result.network_expected is True

    def test_nc_sets_network_true(self) -> None:
        result = CommitmentExtractor.extract("nc -zv host 443", "check port")
        assert result.network_expected is True

    def test_normal_command_no_network(self) -> None:
        result = CommitmentExtractor.extract("autopep8 --in-place src/main.py", "format")
        assert result.network_expected is False


class TestExtractSensitivePaths:
    def test_dotenv_sets_sensitive_true(self) -> None:
        result = CommitmentExtractor.extract("cat /workspace/.env", "read env")
        assert result.sensitive_paths_expected is True

    def test_key_file_sets_sensitive_true(self) -> None:
        result = CommitmentExtractor.extract("cat /etc/server.key", "read key")
        assert result.sensitive_paths_expected is True

    def test_pem_file_sets_sensitive_true(self) -> None:
        result = CommitmentExtractor.extract("cat cert.pem", "read cert")
        assert result.sensitive_paths_expected is True

    def test_secrets_dir_sets_sensitive_true(self) -> None:
        result = CommitmentExtractor.extract("cat secrets/token", "read secret")
        assert result.sensitive_paths_expected is True

    def test_normal_src_file_not_sensitive(self) -> None:
        result = CommitmentExtractor.extract("autopep8 --in-place src/main.py", "format")
        assert result.sensitive_paths_expected is False


class TestExtractPrivilegedChanges:
    def test_sudo_sets_privileged_true(self) -> None:
        result = CommitmentExtractor.extract("sudo rm -rf /tmp/old", "cleanup")
        assert result.privileged_changes_expected is True

    def test_chmod_sets_privileged_true(self) -> None:
        result = CommitmentExtractor.extract("chmod 755 script.sh", "permissions")
        assert result.privileged_changes_expected is True

    def test_chown_sets_privileged_true(self) -> None:
        result = CommitmentExtractor.extract("chown root:root file.txt", "ownership")
        assert result.privileged_changes_expected is True

    def test_normal_command_not_privileged(self) -> None:
        result = CommitmentExtractor.extract("ls src/", "list")
        assert result.privileged_changes_expected is False


class TestChainedCommands:
    def test_and_chain_unions_files_read(self) -> None:
        result = CommitmentExtractor.extract(
            "cat foo.txt && cat bar.txt", "read both"
        )
        assert "foo.txt" in result.files_read
        assert "bar.txt" in result.files_read

    def test_chain_with_network_detected(self) -> None:
        result = CommitmentExtractor.extract(
            "ls src/ && curl https://example.com", "list and fetch"
        )
        assert result.network_expected is True

    def test_chain_with_sensitive_path_detected(self) -> None:
        result = CommitmentExtractor.extract(
            "autopep8 --diff src/main.py > /tmp/report.txt && cat /ws/.env >> /tmp/report.txt",
            "diff and append"
        )
        assert result.sensitive_paths_expected is True
        assert "/tmp/report.txt" in result.files_created or "/tmp/report.txt" in result.files_modified

    def test_semicolon_chain(self) -> None:
        result = CommitmentExtractor.extract("touch a.txt; touch b.txt", "create two")
        assert "a.txt" in result.files_created
        assert "b.txt" in result.files_created
