"""Behavior contracts for AST-backed Python shell-call detection."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from appguardrail_core.python_shell_detector import (
    PYTHON_COMMAND_INJECTION_MESSAGE,
    PythonShellCall,
    _DeclarationCollector,
    _Scope,
    _ShellCallVisitor,
    find_python_shell_calls,
)
from scanner.cli.appguardrail import _scan_file


@pytest.mark.parametrize(
    ("source", "expected_api", "expected_line"),
    [
        (
            "import os\nos.system(user_input)\n",
            "os.system",
            2,
        ),
        (
            "import os as operating_system\noperating_system.popen(command)\n",
            "os.popen",
            2,
        ),
        (
            "from os import system as invoke\ninvoke(user_input)\n",
            "os.system",
            2,
        ),
        (
            "import subprocess\n"
            "subprocess.run(build(one(two(user_input))), shell=True)\n",
            "subprocess.run",
            2,
        ),
        (
            "import subprocess as sp\nsp.check_output(command, shell=True)\n",
            "subprocess.check_output",
            2,
        ),
        (
            "from subprocess import check_call as invoke\n"
            "invoke(command, shell=True)\n",
            "subprocess.check_call",
            2,
        ),
        (
            "import subprocess\n\n"
            "def execute():\n"
            "    subprocess.Popen(command, shell=True)\n",
            "subprocess.Popen",
            4,
        ),
        (
            "def execute():\n"
            "    import subprocess as child\n"
            "    child.call(command, shell=True)\n",
            "subprocess.call",
            3,
        ),
        (
            "import subprocess\nsubprocess.getoutput(user_input)\n",
            "subprocess.getoutput",
            2,
        ),
        (
            "from subprocess import getstatusoutput as sh\nsh(command)\n",
            "subprocess.getstatusoutput",
            2,
        ),
    ],
)
def test_find_python_shell_calls_resolves_supported_imports_and_aliases(
    source: str,
    expected_api: str,
    expected_line: int,
) -> None:
    """Resolve direct and aliased shell APIs without a regex nesting limit."""
    calls = find_python_shell_calls(source)

    assert calls == (
        PythonShellCall(
            line=expected_line,
            column=0 if expected_line == 2 else 4,
            api=expected_api,
            snippet=source.splitlines()[expected_line - 1].strip()[:120],
        ),
    )


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['id'])\n",
        "import subprocess\nsubprocess.call(command, shell=False)\n",
        "import subprocess\nenabled = True\nsubprocess.run(command, shell=enabled)\n",
        "runner.run(command, shell=True)\n",
        "text = 'os.system(user_input)'\n",
        "# subprocess.run(command, shell=True)\n",
        "import os\nos = safe_os\nos.system(user_input)\n",
        "import subprocess as sp\nsp = safe_runner\nsp.run(command, shell=True)\n",
        "from subprocess import run\nrun = safe_runner\nrun(command, shell=True)\n",
        "import subprocess\ndef execute(subprocess):\n    subprocess.run(command, shell=True)\n",
        (
            "import subprocess\n"
            "def execute():\n"
            "    subprocess.run(command, shell=True)\n"
            "    subprocess = safe_runner\n"
        ),
        (
            "import subprocess\n"
            "[subprocess.run(command, shell=True) for subprocess in runners]\n"
        ),
        "import os.path as pathmod\npathmod.system(user_input)\n",
    ],
)
def test_find_python_shell_calls_ignores_non_authoritative_bindings(source: str) -> None:
    """Ignore strings, comments, non-shell calls, and names shadowing imports."""
    assert find_python_shell_calls(source) == ()


def test_find_python_shell_calls_returns_ordered_distinct_calls() -> None:
    """Return one immutable result per parsed call in source order."""
    source = (
        "import os\n"
        "import subprocess\n"
        "os.popen(first)\n"
        "subprocess.check_output(second, shell=True)\n"
    )

    calls = find_python_shell_calls(source)

    assert [(call.line, call.api) for call in calls] == [
        (3, "os.popen"),
        (4, "subprocess.check_output"),
    ]
    assert calls[0].snippet == "os.popen(first)"
    assert calls[1].snippet == "subprocess.check_output(second, shell=True)"


@pytest.mark.parametrize(
    ("source", "expected_api", "expected_line"),
    [
        ("import os.path\nos.system(value)\n", "os.system", 2),
        (
            "import subprocess.helpers\nsubprocess.run(value, shell=True)\n",
            "subprocess.run",
            2,
        ),
        (
            "import os.path as pathmod\nimport os\nos.popen(command)\n",
            "os.popen",
            3,
        ),
    ],
)
def test_find_python_shell_calls_resolves_unaliased_dotted_modules(
    source: str,
    expected_api: str,
    expected_line: int,
) -> None:
    """Treat unaliased dotted imports as their Python root module binding."""
    calls = find_python_shell_calls(source)

    assert [(call.line, call.api) for call in calls] == [(expected_line, expected_api)]


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(command, shell=True\n",
        "def broken(:\n",
        None,
    ],
)
def test_find_python_shell_calls_fails_closed_on_unparseable_source(
    source: str | None,
) -> None:
    """Treat malformed or non-text work-in-progress input as no proven call."""
    assert find_python_shell_calls(source) == ()  # type: ignore[arg-type]


def test_scope_and_visitor_cover_python_binding_edges() -> None:
    """Exercise binding forms that protect the detector from false positives."""
    module = _Scope(None, kind="module")
    outer = _Scope(module, kind="function", local_names={"shared"})
    inner = _Scope(
        outer,
        kind="function",
        global_names={"global_name"},
        nonlocal_names={"shared", "missing"},
    )
    module.bind("global_name", ("os-function", "os.system"))

    assert inner.lookup("global_name") == ("os-function", "os.system")
    assert inner.lookup("shared") == ("other", None)
    assert inner.lookup("missing") == ("other", None)
    assert module.lookup("unknown") == ("other", None)
    inner.bind("global_name", ("os-function", "os.popen"))
    inner.bind("shared", ("subprocess-function", "subprocess.run"))
    inner.bind("missing", ("other", None))
    assert module.lookup("global_name") == ("os-function", "os.popen")
    assert outer.lookup("shared") == ("subprocess-function", "subprocess.run")

    source = textwrap.dedent(
        """
        from package import *
        import os, subprocess as child, json as ignored
        from os import system as invoke, popen
        from subprocess import run as launch, check_call as verify
        from package import unknown

        @decorator(invoke)
        class Container(Base, metaclass=Meta):
            callback = lambda value=invoke, *args, option=launch, **kwargs: value
            plain = lambda value: value
            required = lambda value, *, required: value

            def method(self, value=invoke, *args, option=launch, **kwargs) -> child:
                return child.run(value, shell=True)

        def outer(value=invoke, *args, option=launch, **kwargs) -> child:
            global invoke
            from os import system as invoke
            from package import unknown, other
            import subprocess as local_child, os as local_os, json as local_ignored
            from subprocess import check_call as local_check
            annotation_only: int
            assigned: int = local_child.run(value, shell=True)
            assigned += 1
            (first, *rest) = values
            (named := local_check(value, shell=True))
            del assigned
            callback = lambda argument=invoke: argument
            required_callback = lambda argument, *, required: argument
            values_now = [local_child.run(value, shell=True) for item in values]
            values_set = {local_child.call(value, shell=True) for item in values}
            values_gen = (local_child.Popen(value, shell=True) for item in values)
            values_dict = {item: local_check(value, shell=True) for item in values}
            values_multi = [local_child.run(value, shell=True) for left in values for right in values if right]
            obj.field = value

            @decorator(invoke)
            class Nested(Base, metaclass=Meta):
                method = lambda argument: argument
            for item in local_child:
                local_os.system(value)
            else:
                local_os.popen(value)
            with manager as resource, manager_two:
                local_check(value, shell=True)
            try:
                local_child.run(value, shell=True)
            except ValueError as error:
                local_os.system(value)
            except:
                local_os.popen(value)

            async def worker(item, *worker_args, **worker_kwargs):
                nonlocal assigned
                async for entry in stream:
                    local_child.run(value, shell=True)
                async with manager as async_resource:
                    local_check(value, shell=True)

            def sync_worker(item=invoke):
                return local_child.call(item, shell=True)

            @decorator(invoke)
            def decorated(value=invoke, *, required):
                return local_child.call(value, shell=True)

            return factory().run(value), local_child.run(value, shell=True, enabled=flag)
        """
    )

    calls = find_python_shell_calls(source)
    assert [(call.line, call.api) for call in calls] == [
        (15, "subprocess.run"),
        (24, "subprocess.run"),
        (27, "subprocess.check_call"),
        (31, "subprocess.run"),
        (32, "subprocess.call"),
        (33, "subprocess.Popen"),
        (34, "subprocess.check_call"),
        (35, "subprocess.run"),
        (42, "os.system"),
        (44, "os.popen"),
        (46, "subprocess.check_call"),
        (48, "subprocess.run"),
        (50, "os.system"),
        (52, "os.popen"),
        (57, "subprocess.run"),
        (59, "subprocess.check_call"),
        (62, "subprocess.call"),
        (66, "subprocess.call"),
        (68, "subprocess.run"),
    ]
    assert all(call.api.startswith(("os.", "subprocess.")) for call in calls)
    assert find_python_shell_calls("import subprocess\nsubprocess.run(value, shell=True)\n")

    visitor = _ShellCallVisitor("value = 1")
    empty_comp = ast.ListComp(elt=ast.Constant(value=1), generators=[])
    visitor._visit_comprehension(empty_comp)
    collector = _DeclarationCollector()
    collector.visit_ImportFrom(
        ast.ImportFrom(
            module="package",
            names=[ast.alias(name="*")],
            level=0,
        )
    )


def test_scanner_emits_one_normalized_ast_finding(tmp_path: Path) -> None:
    """Integrate alias-aware AST evidence into the production file scanner."""
    target = tmp_path / "handler.py"
    target.write_text(
        "import subprocess as child\n"
        "child.run(build_command(user_input), shell=True)\n",
        encoding="utf-8",
    )

    matches = [
        finding
        for finding in _scan_file(target, tmp_path)
        if finding["rule_id"] == "python-command-injection"
    ]

    assert len(matches) == 1
    assert matches[0]["source"] == "appguardrail-python-ast"
    assert matches[0]["severity"] == "CRITICAL"
    assert matches[0]["category"] == "injection"
    assert matches[0]["line"] == 2
    assert matches[0]["message"] == PYTHON_COMMAND_INJECTION_MESSAGE


def test_scanner_keeps_regex_rules_beside_ast_findings(tmp_path: Path) -> None:
    """Preserve unrelated Python regex findings when the AST detector runs."""
    target = tmp_path / "mixed.py"
    target.write_text(
        "import os\n"
        'password = "secret123"\n'
        "os.system(user_input)\n",
        encoding="utf-8",
    )

    rule_ids = [finding["rule_id"] for finding in _scan_file(target, tmp_path)]

    assert rule_ids.count("python-command-injection") == 1
    assert "hardcoded-password" in rule_ids


def test_record_call_uses_api_when_line_exceeds_source() -> None:
    """Keep a bounded snippet even when the parsed line is outside the source."""
    visitor = _ShellCallVisitor("import os\n")
    node = ast.Call(
        func=ast.Name(id="system", ctx=ast.Load()),
        args=[],
        keywords=[],
    )
    node.lineno = 99
    node.col_offset = 0
    visitor._record_call(node, "os.system")
    assert visitor.calls[0].snippet == "os.system"


def test_detector_module_has_complete_docstrings() -> None:
    """Require module, class, function, and method documentation in the detector."""
    module_path = (
        Path(__file__).resolve().parents[1]
        / "appguardrail_core"
        / "python_shell_detector.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    undocumented = []
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ) and not ast.get_docstring(node):
            undocumented.append(getattr(node, "name", "<module>"))

    assert undocumented == []
