"""Regression tests for string-based language-profile path handling."""

import inspect
from pathlib import Path

import pytest

from appguardrail_core.language import (
    _detect_signals,
    _iter_lower_path_components,
    detect_language_axes,
    detect_stack_profile,
)
from scanner.cli.appguardrail import _display_path


class StringPath(str):
    """String path subtype used to preserve the public ``str`` input contract."""


@pytest.mark.parametrize(
    "path_text",
    [
        "src/app.py",
        "src/component.tsx",
        "src/page.html",
        "src/archive.tar.py",
        "src/.hidden.py",
        "src/trailing.py.",
        "package.json",
        "nested/tsconfig.json",
        r"windows\service\App.java",
        r"windows\web\api\route.ts",
    ],
)
def test_string_path_language_detection_matches_path_objects(path_text: str) -> None:
    """The optimized string path must preserve the declared Path input contract."""
    assert detect_language_axes([path_text]) == detect_language_axes([Path(path_text)])


def test_all_dot_stem_keeps_a_stable_security_scan_extension() -> None:
    """Python-looking files cannot evade scanning through version-specific Path rules."""
    assert detect_language_axes(["src/....py"]) == {"python"}


def test_string_subclass_uses_string_language_detection_branch() -> None:
    """A ``str`` subtype must not be mistaken for a ``Path``-like object."""
    assert detect_language_axes([StringPath(r"src\main.py")]) == {"python"}


def test_string_subclass_uses_string_display_path_branch() -> None:
    """CLI display formatting must accept ``str`` subtypes without Path methods."""
    assert _display_path(StringPath(r"src\main.py")) == "src/main.py"


def test_display_path_avoids_allocating_when_normalization_is_unnecessary() -> None:
    """An already normalized plain string must retain its exact object identity."""
    path = "src/packages/appguardrail/module.py"

    assert _display_path(path) is path


def test_display_path_normalizes_every_windows_separator() -> None:
    """Formatting still allocates the required slash-normalized Windows result."""
    assert _display_path(r"src\packages\appguardrail\module.py") == (
        "src/packages/appguardrail/module.py"
    )


@pytest.mark.parametrize(
    ("path_text", "expects_template_marker"),
    [
        ("mytemplates/page.tsx", False),
        ("views/page.tsx", True),
        (r"src\views\page.tsx", True),
        (r"src/views\page.tsx", True),
    ],
)
def test_template_and_view_markers_use_exact_path_components(
    path_text: str, expects_template_marker: bool
) -> None:
    """Template detection must handle both separators without substring matches."""
    profile = detect_stack_profile([path_text])

    assert ("templates" in profile.frameworks) is expects_template_marker


def test_signal_detection_avoids_replace_split_hot_loop_allocations() -> None:
    """Signal extraction and its helper must avoid replace/split path rebuilding."""
    for function in (_detect_signals, _iter_lower_path_components):
        source = inspect.getsource(function)

        assert ".replace(" not in source
        assert ".split(" not in source


def test_generator_input_is_materialized_once_for_profile_detection(tmp_path: Path) -> None:
    """One-shot iterables must feed language, framework, and signal detection once."""
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"next":"15"}}\n', encoding="utf-8")
    route = tmp_path / "app" / "api" / "route.ts"
    route.parent.mkdir(parents=True)
    route.write_text("export const GET = true;\n", encoding="utf-8")

    profile = detect_stack_profile(path for path in (manifest, route))

    assert profile.id == "node-typescript-web"
    assert profile.languages == ("javascript", "typescript")
    assert {"app", "api", "next", "package.json"} <= set(profile.signals)
    assert profile.zap_recommended is True


def test_windows_style_string_paths_preserve_web_directory_signals() -> None:
    """String inputs from another operating system must retain directory signals."""
    profile = detect_stack_profile([r"workspace\app\api\route.ts"])

    assert profile.id == "node-typescript-web"
    assert profile.languages == ("typescript",)
    assert {"app", "api"} <= set(profile.signals)
    assert profile.zap_recommended is True
