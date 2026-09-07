"""Bounded structural analyzer for GitHub Actions polling loops.

The packaged regex family for issue #1087 remains the migration oracle.
This module classifies literal-shell ``while`` polls by causal control flow:
initialization must precede the candidate loop, total bounds must converge
on that loop, and helper or sibling jobs cannot donate safety.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


TRANSPORT_ONLY_POLL_BOUND = "github-actions-transport-only-poll-bound"
TRANSPORT_FAILURE_BUDGET_POLL_BOUND = (
    "github-actions-transport-failure-budget-poll-bound"
)

_JOB_KEY = re.compile(r"^  ([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*:\s*(?:#.*)?$")
_TIMEOUT_KEY = re.compile(r"^    timeout-minutes\s*:\s*(.*?)\s*$")
_RUN_KEY = re.compile(r"^(\s*)(?:-\s+)?run\s*:\s*\|([+-])?\s*(?:#.*)?$")
_POSITIVE_INT = re.compile(r"^[1-9][0-9]*$")
_POSITIVE_EXPR = re.compile(r"^\$\{\{\s*([1-9][0-9]*)\s*\}\}$")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_INCREMENT = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)=\s*\$\(\(\s*\$?\1\s*\+\s*1\s*\)\)$"
)
_TEST = re.compile(
    r"\[\s*(.+?)\s+-(gt|ge|lt|le)\s+(.+?)\s*\]"
)
_GH_API = re.compile(r"(?<![A-Za-z0-9_])gh[ \t]+api(?![A-Za-z0-9_])")
_VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_WHILE = re.compile(r"^while\b(.*)$")
_HEREDOC = re.compile(r"""<<[-]?\s*(?:'([^']+)'|"([^"]+)"|\\?(\S+))""")
_TRANSFER = re.compile(
    r"^(break(?:\s+[1-9][0-9]*)?|continue(?:\s+[1-9][0-9]*)?|exit(?:\s+0)?|return(?:\s+0)?)$"
)
_FAIL_EXIT = re.compile(r"^exit\s+([1-9][0-9]*)$")
_DEADLINE_OFFSET = re.compile(r"\+\s*([1-9][0-9]*)")


@dataclass(frozen=True)
class PollLoopAssessment:
    """Causal assessment of one GitHub Actions polling loop.

    Attributes:
        job_name: Owning Actions job identifier.
        transport_failure_budget: Whether a failure-path retry counter exists.
        loop_local_total_bound: Whether this loop has a reachable total bound.
        owning_job_timeout: Whether the owning job has a static positive timeout.
        comparison_converges: Whether a total-bound comparison expires forward.
        exit_reachable: Whether a fail-closed exit of that bound is reachable.
        is_transport_only_unbounded: Finding condition for this loop.
        historical_transport_names: Whether the historical budget identifier is used.
    """

    job_name: str
    transport_failure_budget: bool
    loop_local_total_bound: bool
    owning_job_timeout: bool
    comparison_converges: bool
    exit_reachable: bool
    is_transport_only_unbounded: bool
    historical_transport_names: bool = False


@dataclass(frozen=True)
class _Statement:
    """One executable shell statement after quote and comment masking."""

    index: int
    command: str


@dataclass(frozen=True)
class _Job:
    """One conventional Actions job with timeout and literal shell steps."""

    name: str
    timeout_minutes: str
    shells: tuple[str, ...]


@dataclass(frozen=True)
class _LoopSpan:
    """Inclusive statement range of one ``while``/``done`` pair."""

    start: int
    end: int
    condition: str


@dataclass(frozen=True)
class _IfFrame:
    """In-progress ``if`` block collected while walking a loop body."""

    condition: str
    phase: str
    commands: tuple[str, ...]
    reachable: bool


def classify_poll_loops(workflow_text: str) -> tuple[PollLoopAssessment, ...]:
    """Classify polling loops in conventional GitHub Actions workflow YAML.

    Args:
        workflow_text: Complete workflow document text.

    Returns:
        One assessment per infinite ``while`` loop that executes ``gh api``.
    """
    assessments: list[PollLoopAssessment] = []
    for job in _parse_jobs(workflow_text.replace("\r\n", "\n").replace("\r", "\n")):
        owning_timeout = _is_positive_timeout(job.timeout_minutes)
        for shell in job.shells:
            assessments.extend(_classify_shell(job.name, shell, owning_timeout))
    return tuple(assessments)


def poll_bound_rule_ids(assessments: tuple[PollLoopAssessment, ...]) -> tuple[str, ...]:
    """Map unbounded assessments onto the existing packaged detector identities.

    Args:
        assessments: Classifier output from :func:`classify_poll_loops`.

    Returns:
        Existing rule IDs in assessment order. Historical transport names keep
        ``github-actions-transport-only-poll-bound``; renamed budgets keep
        ``github-actions-transport-failure-budget-poll-bound``.
    """
    rule_ids: list[str] = []
    for item in assessments:
        if not item.is_transport_only_unbounded:
            continue
        if item.historical_transport_names:
            rule_ids.append(TRANSPORT_ONLY_POLL_BOUND)
            continue
        rule_ids.append(TRANSPORT_FAILURE_BUDGET_POLL_BOUND)
    return tuple(rule_ids)


def additional_poll_bound_rule_ids(
    workflow_text: str,
    existing_rule_ids: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return poll-bound rule IDs not already reported for the same file.

    Merge is keyed by rule identity. Regex hits for an existing detector ID
    are preserved; the classifier contributes an ID only when that identity
    is absent so a file cannot double-count the packaged #1088 corpus.

    Args:
        workflow_text: Complete workflow document text.
        existing_rule_ids: Detector identities already emitted for this file.

    Returns:
        Existing packaged rule IDs in first-seen analyzer order.
    """
    already = set(existing_rule_ids)
    extra: list[str] = []
    seen: set[str] = set()
    for rule_id in poll_bound_rule_ids(classify_poll_loops(workflow_text)):
        if rule_id in already or rule_id in seen:
            continue
        seen.add(rule_id)
        extra.append(rule_id)
    return tuple(extra)


def _is_positive_timeout(value: str) -> bool:
    """Return whether a timeout-minutes value is a static positive bound."""
    stripped = value.split("#", 1)[0].strip()
    if _POSITIVE_INT.fullmatch(stripped):
        return True
    matched = _POSITIVE_EXPR.fullmatch(stripped)
    return matched is not None


def _parse_jobs(workflow_text: str) -> tuple[_Job, ...]:
    """Extract conventional two-space jobs, timeouts, and literal ``run`` blocks."""
    lines = workflow_text.splitlines()
    start = _jobs_section_index(lines)
    if start is None:
        return ()
    jobs: list[_Job] = []
    current_name = ""
    timeout = ""
    shells: list[str] = []
    run_indent = -1
    run_lines: list[str] = []
    content_indent: int | None = None
    for line in lines[start + 1 :]:
        if run_indent >= 0:
            if not line.strip():
                run_lines.append("")
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent > run_indent:
                if content_indent is None:
                    content_indent = indent
                run_lines.append(line[min(content_indent, len(line)):])
                continue
            shells.append("\n".join(run_lines))
            run_indent = -1
            run_lines = []
            content_indent = None
        job_match = _JOB_KEY.match(line)
        if job_match:
            if current_name:
                jobs.append(_Job(current_name, timeout, tuple(shells)))
            current_name = job_match.group(1)
            timeout = ""
            shells = []
            continue
        if not current_name:
            continue
        timeout_match = _TIMEOUT_KEY.match(line)
        if timeout_match:
            timeout = timeout_match.group(1)
            continue
        run_match = _RUN_KEY.match(line)
        if run_match:
            run_indent = len(run_match.group(1))
            run_lines = []
            content_indent = None
    if run_indent >= 0:
        shells.append("\n".join(run_lines))
    if current_name:
        jobs.append(_Job(current_name, timeout, tuple(shells)))
    return tuple(jobs)


def _jobs_section_index(lines: list[str]) -> int | None:
    """Return the index of a column-zero ``jobs:`` mapping key."""
    for index, line in enumerate(lines):
        stripped = line.split("#", 1)[0].rstrip()
        if stripped == "jobs:":
            return index
    return None


def _classify_shell(job_name: str, shell: str, owning_timeout: bool) -> tuple[PollLoopAssessment, ...]:
    """Classify infinite ``gh api`` polls inside one literal shell block."""
    statements = _shell_statements(shell)
    loops = _loop_spans(statements)
    assessments: list[PollLoopAssessment] = []
    occupied = _loop_body_indexes(loops)
    for loop in loops:
        body = statements[loop.start + 1 : loop.end]
        commands = tuple(item.command for item in body)
        if loop.condition not in {":", "true"}:
            continue
        if not any(_GH_API.search(command) for command in commands):
            continue
        assignments = _prelude_assignments(statements, loop.start, occupied)
        frames, top_commands = _walk_if_frames(commands)
        transport = _has_transport_failure_budget(frames, top_commands)
        converges, exit_reachable = _total_bound_flags(assignments, frames, top_commands)
        loop_local = converges and exit_reachable
        historical = _uses_historical_names(assignments, commands)
        terminates = _success_path_terminates(top_commands)
        assessments.append(
            PollLoopAssessment(
                job_name=job_name,
                transport_failure_budget=transport,
                loop_local_total_bound=loop_local,
                owning_job_timeout=owning_timeout,
                comparison_converges=converges,
                exit_reachable=exit_reachable,
                is_transport_only_unbounded=(
                    transport
                    and not loop_local
                    and not owning_timeout
                    and not terminates
                ),
                historical_transport_names=historical,
            )
        )
    return tuple(assessments)


def _uses_historical_names(assignments: dict[str, str], commands: tuple[str, ...]) -> bool:
    """Return whether the historical transport-budget identifier is present."""
    if "max_poll_transport_failures" in assignments:
        return True
    return any("max_poll_transport_failures" in command for command in commands)


def _prelude_assignments(statements: tuple[_Statement, ...], loop_start: int, occupied: frozenset[int]) -> dict[str, str]:
    """Collect depth-zero assignments that precede the candidate loop."""
    values: dict[str, str] = {}
    for statement in statements[:loop_start]:
        if statement.index in occupied:
            continue
        parsed = _assignment(statement.command)
        if parsed is None:
            continue
        values[parsed[0]] = parsed[1]
    return values


def _loop_body_indexes(loops: tuple[_LoopSpan, ...]) -> frozenset[int]:
    """Return statement indexes that belong to any loop body, excluding headers."""
    indexes: set[int] = set()
    for loop in loops:
        indexes.update(range(loop.start + 1, loop.end))
    return frozenset(indexes)


def _loop_spans(statements: tuple[_Statement, ...]) -> tuple[_LoopSpan, ...]:
    """Match ``while`` headers to their corresponding ``done`` terminators."""
    stack: list[tuple[int, str]] = []
    spans: list[_LoopSpan] = []
    for statement in statements:
        command = statement.command
        while_match = _WHILE.match(command)
        if while_match:
            token = while_match.group(1).strip().split(None, 1)
            condition = token[0] if token else ""
            stack.append((statement.index, condition.rstrip(";")))
            continue
        if command == "done" or command.startswith("done "):
            if not stack:
                continue
            start, condition = stack.pop()
            spans.append(_LoopSpan(start, statement.index, condition))
    return tuple(spans)


def _shell_statements(shell: str) -> tuple[_Statement, ...]:
    """Split a shell block into executable statements, skipping heredoc bodies."""
    statements: list[_Statement] = []
    heredoc_end: str | None = None
    index = 0
    for raw_line in shell.splitlines():
        if heredoc_end is not None:
            if raw_line.strip() == heredoc_end:
                heredoc_end = None
            continue
        marker = _heredoc_marker(raw_line)
        executable = _mask_inert(raw_line)
        for part in executable.split(";"):
            command = part.strip()
            if command.startswith("do "):
                command = command[3:].strip()
            if command == "do":
                continue
            if command.startswith("then "):
                statements.append(_Statement(index, "then"))
                index += 1
                command = command[5:].strip()
            if command:
                statements.append(_Statement(index, command))
                index += 1
        if marker is not None:
            heredoc_end = marker
    return tuple(statements)


def _heredoc_marker(line: str) -> str | None:
    """Return a heredoc terminator token when the line starts a heredoc."""
    matched = _HEREDOC.search(line)
    if matched is None:
        return None
    return matched.group(1) or matched.group(2) or matched.group(3)


def _mask_inert(line: str) -> str:
    """Replace comments and quoted data with spaces, keeping substitutions."""
    chars: list[str] = []
    index = 0
    length = len(line)
    while index < length:
        current = line[index]
        if current == "\\" and index + 1 < length:
            chars.extend("  ")
            index += 2
            continue
        if current == "'":
            index += 1
            while index < length and line[index] != "'":
                chars.append(" ")
                index += 1
            if index < length:
                chars.append(" ")
                index += 1
            continue
        if current == '"':
            index += 1
            while index < length and line[index] != '"':
                if line[index] == "\\" and index + 1 < length:
                    chars.extend("  ")
                    index += 2
                    continue
                kept, consumed = _keep_expansion(line, index)
                if consumed:
                    chars.append(kept)
                    index += consumed
                    continue
                chars.append(" ")
                index += 1
            if index < length:
                chars.append(" ")
                index += 1
            continue
        if current == "#" and (not chars or chars[-1] in " \t"):
            break
        kept, consumed = _keep_expansion(line, index)
        if consumed:
            chars.append(kept)
            index += consumed
            continue
        chars.append(current)
        index += 1
    return "".join(chars)


def _keep_expansion(text: str, index: int) -> tuple[str, int]:
    """Keep ``$var``, ``${var}``, or ``$(...)`` starting at ``index``."""
    if index >= len(text) or text[index] != "$":
        return "", 0
    if index + 1 < len(text) and text[index + 1] == "(":
        if index + 2 < len(text) and text[index + 2] == "(":
            return _balanced_dollar(text, index)
        inner, consumed = _dollar_paren(text, index)
        return " $(" + _mask_inert(inner) + ") ", consumed
    if index + 1 < len(text) and text[index + 1] == "{":
        end = text.find("}", index + 2)
        if end < 0:
            return text[index:], len(text) - index
        return text[index : end + 1], end + 1 - index
    end = index + 1
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    if end == index + 1:
        return "$", 1
    return text[index:end], end - index


def _dollar_paren(text: str, start: int) -> tuple[str, int]:
    """Return the inner text of ``$(...)`` and the consumed character count."""
    depth = 1
    index = start + 2
    inner_start = index
    while index < len(text) and depth:
        if text[index] == "(":
            depth += 1
        if text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[inner_start:index], index + 1 - start
        index += 1
    return text[inner_start:], len(text) - start


def _balanced_dollar(text: str, start: int) -> tuple[str, int]:
    """Keep a ``$((...))`` arithmetic expansion intact."""
    depth = 0
    index = start + 1
    while index < len(text):
        if text[index] == "(":
            depth += 1
        if text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[start : index + 1], index + 1 - start
        index += 1
    return text[start:], len(text) - start


def _walk_if_frames(commands: tuple[str, ...]) -> tuple[tuple[_IfFrame, ...], tuple[str, ...]]:
    """Collect ``if`` frames and top-level commands from a loop body."""
    stack: list[list[object]] = []
    completed: list[_IfFrame] = []
    top: list[str] = []
    pending: str | None = None
    for command in commands:
        if command.startswith("if "):
            pending = command[3:].strip()
            continue
        if command == "then":
            condition = pending or ""
            pending = None
            stack.append([condition, True, []])
            continue
        if command == "fi":
            if not stack:
                continue
            condition, reachable, body = stack.pop()
            completed.append(
                _IfFrame(str(condition), "then", tuple(str(item) for item in body), bool(reachable))
            )
            continue
        if stack:
            condition, reachable, body = stack[-1]
            if reachable:
                body.append(command)
            if _TRANSFER.fullmatch(command) and reachable:
                stack[-1][1] = False
            continue
        top.append(command)
    return tuple(completed), tuple(top)


def _success_path_terminates(top_commands: tuple[str, ...]) -> bool:
    """Return whether a reachable top-level transfer ends the poll.

    An unconditional ``break``, ``exit``, or ``return`` removes the back edge.
    A top-level ``continue`` skips the rest of the body and repeats the loop.
    """
    for command in top_commands:
        if _TRANSFER.fullmatch(command):
            return not command.startswith("continue")
        if _FAIL_EXIT.fullmatch(command):
            return True
    return False


def _has_transport_failure_budget(frames: tuple[_IfFrame, ...], top_commands: tuple[str, ...]) -> bool:
    """Return whether a negated ``gh api`` branch increments a retry counter."""
    del top_commands
    for frame in frames:
        if "!" not in frame.condition or _GH_API.search(frame.condition) is None:
            continue
        if any(_INCREMENT.match(command) for command in frame.commands):
            return True
    return False


def _total_bound_flags(assignments: dict[str, str], frames: tuple[_IfFrame, ...], top_commands: tuple[str, ...]) -> tuple[bool, bool]:
    """Return ``(comparison_converges, exit_reachable)`` for loop-local totals."""
    deadlines = {
        name
        for name, value in assignments.items()
        if _is_deadline_init(value)
    }
    counters = {name for name, value in assignments.items() if value.strip() == "0"}
    limits = {
        name
        for name, value in assignments.items()
        if _POSITIVE_INT.fullmatch(value.strip())
    }
    top_increments = {
        matched.group(1)
        for command in top_commands
        if (matched := _INCREMENT.match(command))
    }
    converges = False
    exit_reachable = False
    for frame in frames:
        test = _TEST.search(frame.condition)
        if test is None:
            continue
        left, operator, right = test.group(1), test.group(2), test.group(3)
        direction = _comparison_direction(left, operator, right)
        if direction != "forward":
            continue
        if not _is_total_comparison(left, right, deadlines, counters, limits, top_increments):
            continue
        converges = True
        if frame.reachable and any(_FAIL_EXIT.match(command) for command in frame.commands):
            exit_reachable = True
    return converges, exit_reachable


def _is_deadline_init(value: str) -> bool:
    """Return whether an assignment initializes a wall-clock deadline."""
    return "date" in value and "%s" in value and _DEADLINE_OFFSET.search(value) is not None


def _comparison_direction(left: str, operator: str, right: str) -> str:
    """Classify a test operator as forward, reversed, or unrelated."""
    left_kind = _operand_kind(left)
    right_kind = _operand_kind(right)
    forward_ops = operator in {"gt", "ge"}
    if left_kind == "now" and right_kind.startswith("var:"):
        return "forward" if forward_ops else "reversed"
    if left_kind.startswith("var:") and right_kind == "now":
        return "forward" if not forward_ops else "reversed"
    if left_kind.startswith("var:") and right_kind.startswith("var:"):
        return "forward" if forward_ops else "reversed"
    return "none"


def _operand_kind(text: str) -> str:
    """Classify a test operand as current time, variable, or other text."""
    if "date" in text and "%s" in text:
        return "now"
    matched = _VAR_REF.search(text)
    if matched:
        return "var:" + matched.group(1)
    return "other"


def _is_total_comparison(left: str, right: str, deadlines: set[str], counters: set[str], limits: set[str], top_increments: set[str]) -> bool:
    """Return whether a forward comparison is a loop-local total bound."""
    names = set(_VAR_REF.findall(left + " " + right))
    if names & deadlines:
        return True
    counter_hit = names & counters & top_increments
    limit_hit = names & limits
    return bool(counter_hit) and bool(limit_hit)


def _assignment(command: str) -> tuple[str, str] | None:
    """Parse a simple shell assignment command."""
    matched = _ASSIGN.match(command)
    if matched is None:
        return None
    return matched.group(1), matched.group(2)
