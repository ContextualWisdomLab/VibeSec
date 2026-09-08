"""Language and framework profile detection for zero-config scans."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

LANGUAGE_EXTENSIONS = {
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx", ".mts", ".cts"],
    "java": [".java"],
    "python": [".py"],
    "web": [".html", ".htm"],
}

LANGUAGE_BY_EXTENSION = {
    extension: language
    for language, extensions in LANGUAGE_EXTENSIONS.items()
    for extension in extensions
}

PYTHON_MANIFESTS = {"pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"}
JAVA_MANIFESTS = {
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "gradle.lockfile",
}
NODE_MANIFESTS = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "tsconfig.json",
}

PYTHON_WEB_MARKERS = {
    "django",
    "fastapi",
    "flask",
    "jinja2",
    "pydantic",
    "pyyaml",
    "requests",
    "sqlalchemy",
    "starlette",
}
JAVA_WEB_MARKERS = {
    "spring-boot",
    "spring-security",
    "springframework",
    "servlet",
    "jackson",
    "jjwt",
    "auth0",
}
NODE_WEB_MARKERS = {
    "express",
    "next",
    "next.js",
    "nestjs",
    "react",
    "vite",
    "cors",
    "helmet",
    "jsonwebtoken",
    "stripe",
    "firebase",
    "supabase",
}

WEB_SIGNAL_DIRS = {"app", "api", "pages", "routes", "templates", "views", "public"}
MANIFEST_NAMES = PYTHON_MANIFESTS | JAVA_MANIFESTS | NODE_MANIFESTS


@dataclass(frozen=True)
class StackProfile:
    """Beginner-facing scan profile inferred from repository files."""

    id: str
    display_name: str
    languages: tuple[str, ...]
    frameworks: tuple[str, ...]
    signals: tuple[str, ...]
    external_tools: tuple[str, ...]
    zap_recommended: bool
    beginner_summary: str
    next_steps: tuple[str, ...]


def detect_language_axes(files: Iterable[str | Path]) -> set[str]:
    """Return language axes found in a scan target without requiring user flags."""
    languages: set[str] = set()
    for file_path in files:
        if not isinstance(file_path, str):
            name = file_path.name
            suffix = file_path.suffix.lower()
        else:
            idx = max(file_path.rfind("/"), file_path.rfind("\\"))
            name = file_path[idx + 1 :] if idx != -1 else file_path

            dot_idx = name.rfind(".")
            suffix = name[dot_idx:].lower() if dot_idx > 0 else ""

        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language:
            languages.add(language)
        if name in PYTHON_MANIFESTS:
            languages.add("python")
        if name in JAVA_MANIFESTS:
            languages.add("java")
        if name in NODE_MANIFESTS:
            languages.add("javascript")
            if name == "tsconfig.json":
                languages.add("typescript")
    return languages


def detect_stack_profile(files: Iterable[str | Path]) -> StackProfile:
    """Infer the most helpful zero-config scan profile for beginner users."""
    files_list = list(files) if not isinstance(files, (list, set, tuple)) else files
    paths = [
        str(file_path) if isinstance(file_path, Path) else file_path
        for file_path in files_list
    ]
    languages = detect_language_axes(paths)
    frameworks = _detect_framework_markers(paths)
    signals = _detect_signals(paths, frameworks)

    if "java" in languages and languages & {"javascript", "typescript"}:
        profile_id = "java-node-typescript"
        display_name = "Java + Node.js/TypeScript web stack"
        summary = (
            "Java service and Node.js/TypeScript web code detected; AppGuardrail "
            "will combine backend, frontend, and cross-service checks."
        )
        next_steps = (
            "Review cross-service auth, CORS, JWT, cookie, and webhook findings first.",
            "Run Semgrep and Trivy when available for deeper Java and JavaScript coverage.",
        )
    elif "python" in languages and (
        "web" in languages or frameworks & PYTHON_WEB_MARKERS
    ):
        profile_id = "python-web"
        display_name = "Python web application"
        summary = (
            "Python web markers detected; AppGuardrail will prioritize web auth, "
            "deserialization, TLS, CORS, rendering, and dependency review."
        )
        next_steps = (
            "Review critical/high findings before deployment.",
            "Install Bandit, Ruff, and Semgrep for deeper optional checks.",
        )
    elif "java" in languages:
        profile_id = "java"
        display_name = "Java application"
        summary = (
            "Java code or build files detected; AppGuardrail will prioritize Spring, "
            "JWT, TLS, cookie, and deserialization checks."
        )
        next_steps = (
            "Review Spring Security, JWT, and TLS findings first.",
            "Run Semgrep and import CodeQL evidence when available.",
        )
    elif languages & {"javascript", "typescript"}:
        profile_id = "node-typescript-web"
        display_name = "Node.js/TypeScript web application"
        summary = (
            "Node.js or TypeScript web markers detected; AppGuardrail will prioritize "
            "auth, CORS, client-secret, webhook, and browser sink checks."
        )
        next_steps = (
            "Review client-exposed secrets, CORS, auth, and webhook findings first.",
            "Run Semgrep and Trivy when available for deeper coverage.",
        )
    elif languages:
        profile_id = "generic-code"
        display_name = "Generic code scan"
        summary = (
            "Code files detected; AppGuardrail will run applicable built-in rules."
        )
        next_steps = ("Review critical/high findings before deployment.",)
    else:
        profile_id = "unknown"
        display_name = "Unknown stack"
        summary = "No known language axis was detected from scanned files."
        next_steps = ("Confirm the scan path contains source code or manifests.",)

    return StackProfile(
        id=profile_id,
        display_name=display_name,
        languages=tuple(sorted(languages)),
        frameworks=tuple(sorted(frameworks)),
        signals=tuple(sorted(signals)),
        external_tools=_external_tools_for(languages, profile_id),
        zap_recommended=_is_web_reachable(languages, frameworks, paths),
        beginner_summary=summary,
        next_steps=next_steps,
    )


def _iter_lower_path_components(path: str) -> Iterable[str]:
    """Yield lowercase non-empty path components for either slash convention."""
    start = 0
    for index, character in enumerate(path):
        if character not in "/\\":
            continue
        if index > start:
            yield path[start:index].lower()
        start = index + 1
    if start < len(path):
        yield path[start:].lower()


def _detect_framework_markers(paths: list[str]) -> set[str]:
    markers: set[str] = set()
    for path in paths:
        idx = max(path.rfind("/"), path.rfind("\\"))
        name = path[idx + 1 :] if idx != -1 else path
        if any(
            component in {"templates", "views"}
            for component in _iter_lower_path_components(path)
        ):
            markers.add("templates")
        if name not in MANIFEST_NAMES:
            continue
        text = _read_manifest_text(path).lower()
        for marker in PYTHON_WEB_MARKERS | JAVA_WEB_MARKERS | NODE_WEB_MARKERS:
            if marker in text:
                markers.add(marker)
    return markers


def _detect_signals(paths: list[str], frameworks: set[str]) -> set[str]:
    signals = set(frameworks)
    for path in paths:
        idx = max(path.rfind("/"), path.rfind("\\"))
        name = path[idx + 1 :] if idx != -1 else path
        if name in MANIFEST_NAMES:
            signals.add(name)
        for component in _iter_lower_path_components(path):
            if component in WEB_SIGNAL_DIRS:
                signals.add(component)
    return signals


def _read_manifest_text(path: str, max_bytes: int = 128_000) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(max_bytes).decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _external_tools_for(languages: set[str], profile_id: str) -> tuple[str, ...]:
    tools: set[str] = set()
    if "python" in languages:
        tools.update({"bandit", "ruff", "semgrep"})
    if languages & {"java", "javascript", "typescript", "web"}:
        tools.add("semgrep")
    if profile_id in {
        "java",
        "java-node-typescript",
        "node-typescript-web",
        "python-web",
    }:
        tools.add("trivy")
    return tuple(sorted(tools))


def _is_web_reachable(
    languages: set[str], frameworks: set[str], paths: list[str]
) -> bool:
    if "web" in languages:
        return True
    if frameworks & (
        PYTHON_WEB_MARKERS | JAVA_WEB_MARKERS | NODE_WEB_MARKERS | {"templates"}
    ):
        return True
    for path in paths:
        for component in _iter_lower_path_components(path):
            if component in WEB_SIGNAL_DIRS:
                return True
    return False
