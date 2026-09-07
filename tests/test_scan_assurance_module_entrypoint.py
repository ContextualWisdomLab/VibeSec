"""Black-box packaging entrypoint coverage for scan assurance."""

from __future__ import annotations

import hashlib
import json
import runpy
import sys
from pathlib import Path

import pytest

from appguardrail_core import scan_assurance


def test_module_entrypoint_executes_real_clean_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Executing the shipped module as ``__main__`` must evaluate real artifacts."""
    findings_path = tmp_path / "findings.json"
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "assurance.json"
    findings_bytes = (
        json.dumps(
            {"schema": scan_assurance.FINDINGS_SCHEMA, "findings": []},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    findings_path.write_bytes(findings_bytes)
    evidence_path.write_text(
        json.dumps(
            {
                "schema": scan_assurance.EVIDENCE_SCHEMA,
                "repository": "ContextualWisdomLab/appguardrail",
                "commit": "a" * 40,
                "generated_at": "2026-08-16T00:00:00Z",
                "scanner_version": "0.1.1",
                "execution": "completed",
                "configured_detectors": ["builtin"],
                "completed_detectors": ["builtin"],
                "requested_external_engines": [],
                "external_engines": {},
                "scope": {
                    "files_scanned": 1,
                    "paths": ["."],
                    "languages": ["python"],
                    "exclusions": [],
                },
                "gate": {
                    "threshold": ["CRITICAL", "HIGH"],
                    "blocking_count": 0,
                    "non_blocking_count": 0,
                },
                "findings_sha256": hashlib.sha256(findings_bytes).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(scan_assurance.__file__),
            "--findings",
            str(findings_path),
            "--evidence",
            str(evidence_path),
            "--out",
            str(output_path),
            "--repository",
            "ContextualWisdomLab/appguardrail",
            "--commit",
            "a" * 40,
            "--now",
            "2026-08-16T00:00:00Z",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(scan_assurance.__file__), run_name="__main__")

    assert exit_info.value.code == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["scan_outcome_code"] == "clean"
