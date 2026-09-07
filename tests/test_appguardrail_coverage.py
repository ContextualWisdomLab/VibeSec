import os
import runpy
import sys
from unittest.mock import patch

import pytest

from scanner.cli.appguardrail import (_collect_files, _parse_inline_list,
                                      _path_matches_glob, _scan_file, cmd_hook,
                                      cmd_init, cmd_monitor, cmd_review,
                                      cmd_scan, main)
from tests.test_appguardrail import MOCK_RULES


class Args:
    def __init__(self, tool="cursor", stack=None):
        self.tool = tool
        self.stack = stack


class ScanArgs:
    def __init__(self, path):
        self.path = str(path)


def _create_symlink(target, link, target_is_directory=False):
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:  # pragma: no cover
        pytest.skip(
            f"symlinks are not available in this environment: {exc}"
        )  # pragma: no cover


def test_cmd_init_symlink_removal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target_dir = tmp_path / ".cursor" / "rules"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "appguardrail.md"

    # Create a dummy file to symlink to
    dummy = tmp_path / "dummy.md"
    dummy.write_text("dummy")
    _create_symlink(dummy, target_file)

    checklist = tmp_path / "APPGUARDRAIL_CHECKLIST.md"
    _create_symlink(dummy, checklist)

    cmd_init(Args(tool="cursor"))

    # Both should be regular files now, not symlinks
    assert target_file.exists()
    assert not target_file.is_symlink()
    assert checklist.exists()
    assert not checklist.is_symlink()


def test_cmd_init_append_marker_no_marker(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("No marker here.\n")

    cmd_init(Args(tool="claude-code"))

    content = claude_file.read_text()
    assert "No marker here." in content
    assert "AppGuardrail" in content


def test_cmd_init_auto_installs_agent_instructions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    cmd_init(Args(tool="auto"))

    assert (tmp_path / "AGENTS.md").exists()
    assert (tmp_path / ".github" / "copilot-instructions.md").exists()
    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / ".cursor" / "rules" / "appguardrail.md").exists()
    assert (tmp_path / ".windsurf" / "rules" / "appguardrail.md").exists()
    assert "AppGuardrail" in (tmp_path / "AGENTS.md").read_text()
    assert "appguardrail scan --codegraph ." in (tmp_path / "AGENTS.md").read_text()


def test_cmd_scan_path_not_exists(tmp_path, capsys):
    missing_path = tmp_path / "does_not_exist"
    with pytest.raises(SystemExit) as excinfo:
        cmd_scan(ScanArgs(missing_path))

    assert excinfo.value.code == 1
    assert "❌ Error: Path does not exist:" in capsys.readouterr().err


def test_cmd_scan_skips_symlink_path(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text("print('target')\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    assert cmd_scan(ScanArgs(link)) == 0
    assert "Skipping symlink path:" in capsys.readouterr().out


def test_cmd_init_path_traversal_checklist(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    # checklist가 symlink되어 외부를 가리키면?
    checklist_link = tmp_path / "APPGUARDRAIL_CHECKLIST.md"
    outside_dir = tmp_path.parent / "outside"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "outside.md"
    outside_file.touch()

    _create_symlink(outside_file, checklist_link)

    with pytest.raises(SystemExit) as exc:
        cmd_init(Args(tool="cursor"))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "escapes the project root" in err
    assert "💡 Hint: Ensure" in err


def test_cmd_init_path_traversal_target_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # .cursor/rules/appguardrail.md symlinked to outside
    rules_dir = tmp_path / ".cursor" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = tmp_path.parent / "outside2"
    outside_dir.mkdir(exist_ok=True)
    outside_file = outside_dir / "appguardrail.md"
    outside_file.touch()

    target_link = rules_dir / "appguardrail.md"
    _create_symlink(outside_file, target_link)

    with pytest.raises(SystemExit) as exc:
        cmd_init(Args(tool="cursor"))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "escapes the project root" in err
    assert "💡 Hint: Ensure" in err


class HookArgs:
    pass


def test_cmd_hook_no_git_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cmd_hook(HookArgs()) == 1
    assert "Not a git repository" in capsys.readouterr().err


def test_cmd_hook_success(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    assert cmd_hook(HookArgs()) == 0

    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.exists()
    hook_text = hook_file.read_text()
    assert "appguardrail scan ." in hook_text
    assert "command -v appguardrail" in hook_text
    assert 'python3 "$APPGUARDRAIL_CLI" scan .' in hook_text
    if os.name != "nt":
        import stat

        assert hook_file.stat().st_mode & stat.S_IEXEC

    assert "pre-commit hook installed successfully" in capsys.readouterr().out


def test_cmd_hook_codegraph_mode(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    class CodeGraphHookArgs:
        codegraph = True

    assert cmd_hook(CodeGraphHookArgs()) == 0

    hook_file = git_dir / "hooks" / "pre-commit"
    hook_text = hook_file.read_text()
    assert "appguardrail scan --codegraph ." in hook_text
    assert 'python3 "$APPGUARDRAIL_CLI" scan --codegraph .' in hook_text
    assert "CodeGraph mode is enabled" in capsys.readouterr().out


def test_cmd_hook_path_traversal(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    # hooks symlinked to outside
    outside_dir = tmp_path.parent / "outside_hooks"
    outside_dir.mkdir(exist_ok=True)

    hooks_link = git_dir / "hooks"
    _create_symlink(outside_dir, hooks_link, target_is_directory=True)

    assert cmd_hook(HookArgs()) == 1
    err = capsys.readouterr().err
    assert "escapes the project root" in err
    assert "💡 Hint: Ensure" in err


def test_cmd_hook_remove_symlink(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir()

    dummy = tmp_path / "dummy_hook"
    dummy.touch()

    hook_link = hooks_dir / "pre-commit"
    _create_symlink(dummy, hook_link)

    assert cmd_hook(HookArgs()) == 0
    assert not hook_link.is_symlink()


def test_collect_files_oserror_on_scandir(tmp_path):
    def mock_scandir(path):
        raise PermissionError("Mock permission error")

    with patch("os.scandir", mock_scandir):
        files = list(_collect_files(tmp_path))
        assert files == []


def test_collect_files_oserror_on_entry(tmp_path):
    class MockEntry:
        def __init__(self, is_dir_val, is_file_val, is_symlink_val):
            self._is_dir = is_dir_val
            self._is_file = is_file_val
            self._is_symlink = is_symlink_val
            self.name = "mock"
            self.path = str(tmp_path / "mock")

        def is_dir(self, follow_symlinks=False):
            if self._is_dir:
                raise OSError("Mock OS Error")
            return False  # pragma: no cover

        def is_file(self, follow_symlinks=False):  # pragma: no cover
            return self._is_file

        def is_symlink(self):
            return self._is_symlink

    def mock_scandir(path):
        class MockIt:
            def __enter__(self):
                return [MockEntry(True, False, False)]

            def __exit__(self, *args):
                pass

        return MockIt()

    with patch("os.scandir", mock_scandir):
        files = list(_collect_files(tmp_path))
        assert files == []


def test_scan_file_lstat_oserror(tmp_path):
    test_file = tmp_path / "test.ts"

    with patch("os.lstat", side_effect=OSError("Mock OS Error")):
        assert _scan_file(test_file, tmp_path) == []


def test_scan_file_large_file(tmp_path):
    test_file = tmp_path / "large.ts"

    class MockStat:
        st_mode = 0o100644  # Regular file
        st_size = 20 * 1024 * 1024  # 20MB

    with patch("os.lstat", return_value=MockStat()):
        assert _scan_file(test_file, tmp_path) == []


def test_scan_file_not_regular(tmp_path):
    import stat

    test_file = tmp_path / "fifo"

    class MockStat:
        st_mode = stat.S_IFIFO  # FIFO pipe
        st_size = 100

    with patch("os.lstat", return_value=MockStat()):
        assert _scan_file(test_file, tmp_path) == []


class ReviewArgs:
    def __init__(self, stack=None, db=None, payments=None):
        self.stack = stack
        self.db = db
        self.payments = payments


def test_cmd_review_all_flags(capsys):
    cmd_review(ReviewArgs(stack="nextjs-supabase", db="supabase", payments="stripe"))
    out = capsys.readouterr().out
    assert "Next.js application" in out
    assert "Supabase RLS" in out
    assert "Stripe" in out


def test_cmd_review_firebase(capsys):
    cmd_review(ReviewArgs(stack="nextjs-firebase", db="firebase"))
    out = capsys.readouterr().out
    assert "Firebase Rules" in out
    assert "Next.js application" in out


def test_main_init(monkeypatch, capsys):
    test_args = ["appguardrail", "init", "--tool", "cursor"]
    monkeypatch.setattr(sys, "argv", test_args)
    # mock cmd_init to just print and return
    with patch("scanner.cli.appguardrail.cmd_init") as mock_init:
        main()
        mock_init.assert_called_once()


def test_main_scan(monkeypatch):
    test_args = ["appguardrail", "scan", "."]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.appguardrail.cmd_scan", return_value=0) as mock_scan:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_scan.assert_called_once()


def test_main_scan_plugin(monkeypatch):
    test_args = ["appguardrail", "scan-plugin", "--plugin-root", "."]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch(
        "appguardrail_core.claude_plugin_scan_cli.cmd_scan_plugin",
        return_value=0,
    ) as mock_scan:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_scan.assert_called_once()


def test_main_review(monkeypatch):
    test_args = ["appguardrail", "review", "--stack", "nextjs"]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.appguardrail.cmd_review") as mock_review:
        main()
        mock_review.assert_called_once()


def test_main_report(monkeypatch, tmp_path):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text("[]")
    test_args = [
        "appguardrail",
        "report",
        "buyer-diligence",
        "--findings",
        str(findings_file),
    ]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.appguardrail.cmd_report", return_value=0) as mock_report:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_report.assert_called_once()


def test_main_hook(monkeypatch):
    test_args = ["appguardrail", "hook"]
    monkeypatch.setattr(sys, "argv", test_args)
    with patch("scanner.cli.appguardrail.cmd_hook", return_value=0) as mock_hook:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_hook.assert_called_once()


def test_main_no_args(monkeypatch, capsys):
    test_args = ["appguardrail"]
    monkeypatch.setattr(sys, "argv", test_args)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "usage: appguardrail" in capsys.readouterr().out


def test_cmd_scan_actual_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = MOCK_SECRET_KEY;\n")

    with patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES):
        assert cmd_scan(ScanArgs(tmp_path)) == 1


def test_cmd_scan_actual_run_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    test_file = tmp_path / "safe.ts"
    test_file.write_text("console.log('safe');\n")

    with patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES):
        assert cmd_scan(ScanArgs(test_file)) == 0


def test_scan_file_empty_rules(tmp_path):
    test_file = tmp_path / "safe.txt"
    test_file.write_text("hello\n")
    with patch("scanner.cli.appguardrail.SCAN_RULES", []):
        assert _scan_file(test_file, tmp_path) == []


def test_if_name_main():
    import sys
    from unittest.mock import patch

    original_argv = sys.argv
    sys.argv = ["appguardrail", "--help"]

    try:
        with patch("sys.exit") as mock_exit:
            runpy.run_path("scanner/cli/appguardrail.py", run_name="__main__")
            mock_exit.assert_called_with(0)
    finally:
        sys.argv = original_argv


def test_scan_file_open_permission_error():
    import stat
    from pathlib import Path
    from unittest.mock import mock_open, patch

    from scanner.cli.appguardrail import _scan_file

    base_path = Path("/mock/base")
    file_path = Path("/mock/base/test.js")

    with (
        patch("os.lstat") as mock_lstat,
        patch("scanner.cli.appguardrail._get_applicable_rules") as mock_get_rules,
        patch("builtins.open", mock_open()) as m_open,
    ):

        mock_st = mock_lstat.return_value
        mock_st.st_mode = stat.S_IFREG
        mock_st.st_size = 100

        mock_get_rules.return_value = [("rule1", "HIGH", "msg", lambda c: iter([]))]
        m_open.side_effect = PermissionError("Mock permission error")

        findings = _scan_file(file_path, base_path)
        assert findings == []


def test_cmd_monitor(capsys, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    class MonitorArgs:
        pass

    assert cmd_monitor(MonitorArgs()) == 0


def test_path_matches_glob():
    assert _path_matches_glob("./a/b/c.py", "a/b/c.py")
    assert _path_matches_glob("a/b/c.py", "./a/b/c.py")


def test_parse_inline_list():
    assert _parse_inline_list("[]") == []


def test_is_safe_url_cli_coverage():
    from scanner.cli.appguardrail import _is_safe_url

    assert not _is_safe_url("http://0.0.0.0/")
    assert not _is_safe_url("http://224.0.0.1/")
    assert not _is_safe_url("http://[::]/")
    assert not _is_safe_url("http://[ff00::1]/")
