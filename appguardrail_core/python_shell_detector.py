"""High-confidence AST detection for Python APIs that execute through a shell."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Final


PYTHON_COMMAND_INJECTION_MESSAGE: Final = (
    "Potential command injection sink detected: os.system/os.popen and "
    "subprocess.getoutput/getstatusoutput execute through a shell, and "
    "subprocess shell=True invokes a shell. Avoid shell execution, validate "
    "untrusted input, and use argument arrays where possible. "
    "[OWASP A03:2021 - Injection]"
)

_OS_SHELL_APIS: Final = frozenset({"popen", "system"})
_SUBPROCESS_SHELL_APIS: Final = frozenset(
    {"Popen", "call", "check_call", "check_output", "run"}
)
_SUBPROCESS_IMPLICIT_SHELL_APIS: Final = frozenset({"getoutput", "getstatusoutput"})
_OTHER_BINDING: Final = ("other", None)
_OS_MODULE_BINDING: Final = ("os-module", None)
_SUBPROCESS_MODULE_BINDING: Final = ("subprocess-module", None)
Binding = tuple[str, str | None]


@dataclass(frozen=True, slots=True)
class PythonShellCall:
    """One source-bound shell-spawning Python call."""

    line: int
    column: int
    api: str
    snippet: str


class _Scope:
    """Track high-confidence import bindings inside one lexical scope."""

    def __init__(
        self,
        parent: _Scope | None,
        *,
        kind: str,
        local_names: set[str] | None = None,
        global_names: set[str] | None = None,
        nonlocal_names: set[str] | None = None,
    ) -> None:
        """Initialize one scope with Python's function-local shadowing rules."""
        self.parent = parent
        self.kind = kind
        self.bindings = {
            name: _OTHER_BINDING for name in (local_names or set())
        }
        self.global_names = global_names or set()
        self.nonlocal_names = nonlocal_names or set()

    def _module_scope(self) -> _Scope:
        """Return the root module scope."""
        scope = self
        while scope.parent is not None:
            scope = scope.parent
        return scope

    def _nonlocal_scope(self, name: str) -> _Scope | None:
        """Return the nearest enclosing non-module binding for ``name``."""
        scope = self.parent
        while scope is not None and scope.parent is not None:
            if name in scope.bindings:
                return scope
            scope = scope.parent
        return None

    def lookup(self, name: str) -> Binding:
        """Resolve a name without guessing through a shadowing binding."""
        if name in self.global_names:
            return self._module_scope().bindings.get(name, _OTHER_BINDING)
        if name in self.nonlocal_names:
            target = self._nonlocal_scope(name)
            return (
                target.bindings.get(name, _OTHER_BINDING)
                if target is not None
                else _OTHER_BINDING
            )
        if name in self.bindings:
            return self.bindings[name]
        if self.parent is not None:
            return self.parent.lookup(name)
        return _OTHER_BINDING

    def bind(self, name: str, binding: Binding) -> None:
        """Bind a name at the scope selected by global/nonlocal declarations."""
        if name in self.global_names:
            self._module_scope().bindings[name] = binding
            return
        if name in self.nonlocal_names:
            target = self._nonlocal_scope(name)
            if target is not None:
                target.bindings[name] = binding
            return
        self.bindings[name] = binding


class _DeclarationCollector(ast.NodeVisitor):
    """Collect names that make a function binding local for its whole body."""

    def __init__(self) -> None:
        """Initialize empty local/global/nonlocal declaration sets."""
        self.local_names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def _bind_target(self, target: ast.AST) -> None:
        """Collect names bound by one assignment-style target."""
        if isinstance(target, ast.Name):
            self.local_names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value)

    def visit_Global(self, node: ast.Global) -> None:
        """Record names explicitly routed to module scope."""
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        """Record names explicitly routed to an enclosing function scope."""
        self.nonlocal_names.update(node.names)

    def visit_Import(self, node: ast.Import) -> None:
        """Collect the names bound by an import statement."""
        for alias in node.names:
            self.local_names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Collect explicit names bound by a from-import statement."""
        for alias in node.names:
            if alias.name != "*":
                self.local_names.add(alias.asname or alias.name)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Collect assignment targets and nested declarations in the value."""
        for target in node.targets:
            self._bind_target(target)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Collect one annotated target and inspect its expressions."""
        self._bind_target(node.target)
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Collect one augmented-assignment target and inspect its value."""
        self._bind_target(node.target)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Collect a walrus target and inspect its value."""
        self._bind_target(node.target)
        self.visit(node.value)

    def visit_For(self, node: ast.For) -> None:
        """Collect a for-loop target and recurse into its current scope."""
        self._bind_target(node.target)
        self.visit(node.iter)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        """Collect an async-for target and recurse into its current scope."""
        self.visit_For(node)

    def visit_With(self, node: ast.With) -> None:
        """Collect with-item aliases and recurse into the body."""
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Collect async-with aliases and recurse into the body."""
        self.visit_With(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Collect an exception alias and recurse into the handler body."""
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self.local_names.add(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Bind a nested function name without entering its nested body."""
        self.local_names.add(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Bind a nested async-function name without entering its nested body."""
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Bind a nested class name without entering its nested body."""
        self.local_names.add(node.name)
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Inspect lambda defaults without entering its nested body."""
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def visit_ListComp(self, _node: ast.ListComp) -> None:
        """Keep comprehension-local targets out of the containing scope."""

    def visit_SetComp(self, _node: ast.SetComp) -> None:
        """Keep comprehension-local targets out of the containing scope."""

    def visit_GeneratorExp(self, _node: ast.GeneratorExp) -> None:
        """Keep generator-expression targets out of the containing scope."""

    def visit_DictComp(self, _node: ast.DictComp) -> None:
        """Keep dictionary-comprehension targets out of the containing scope."""


class _ShellCallVisitor(ast.NodeVisitor):
    """Resolve imports and record only high-confidence shell-spawning calls."""

    def __init__(self, source: str) -> None:
        """Initialize the module scope and source-line cache."""
        self.source_lines = source.splitlines()
        self.scope = _Scope(None, kind="module")
        self.scope.bindings.update(
            {
                "os": _OS_MODULE_BINDING,
                "subprocess": _SUBPROCESS_MODULE_BINDING,
            }
        )
        self.calls: list[PythonShellCall] = []

    def _bind_target(self, target: ast.AST) -> None:
        """Shadow names assigned by one runtime target."""
        if isinstance(target, ast.Name):
            self.scope.bind(target.id, _OTHER_BINDING)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value)

    def _function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _Scope:
        """Build a function scope with Python's statically local names."""
        collector = _DeclarationCollector()
        for statement in node.body:
            collector.visit(statement)
        local_names = collector.local_names - collector.global_names - collector.nonlocal_names
        arguments = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        local_names.update(argument.arg for argument in arguments)
        if node.args.vararg is not None:
            local_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            local_names.add(node.args.kwarg.arg)
        parent = self.scope.parent if self.scope.kind == "class" else self.scope
        return _Scope(
            parent,
            kind="function",
            local_names=local_names,
            global_names=collector.global_names,
            nonlocal_names=collector.nonlocal_names,
        )

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Evaluate definition expressions, then traverse one function scope."""
        for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        if node.returns is not None:
            self.visit(node.returns)
        self.scope.bind(node.name, _OTHER_BINDING)
        previous = self.scope
        self.scope = self._function_scope(node)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope = previous

    def _binding_for_call(self, function: ast.expr) -> tuple[str, str] | None:
        """Resolve a call target to its supported family and canonical API."""
        if isinstance(function, ast.Name):
            kind, api = self.scope.lookup(function.id)
            if (
                kind in {"os-function", "subprocess-function", "subprocess-implicit-shell"}
                and api is not None
            ):
                return kind, api
            return None
        if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            kind, _api = self.scope.lookup(function.value.id)
            if kind == "os-module" and function.attr in _OS_SHELL_APIS:
                return "os-function", f"os.{function.attr}"
            if kind == "subprocess-module" and function.attr in _SUBPROCESS_IMPLICIT_SHELL_APIS:
                return "subprocess-implicit-shell", f"subprocess.{function.attr}"
            if kind == "subprocess-module" and function.attr in _SUBPROCESS_SHELL_APIS:
                return "subprocess-function", f"subprocess.{function.attr}"
        return None

    def _record_call(self, node: ast.Call, api: str) -> None:
        """Append one source-bound finding candidate."""
        line = max(node.lineno, 1)
        snippet = (
            self.source_lines[line - 1].strip()[:120]
            if line <= len(self.source_lines)
            else api
        )
        self.calls.append(
            PythonShellCall(
                line=line,
                column=max(node.col_offset, 0),
                api=api,
                snippet=snippet,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        """Bind supported modules and shadow every other imported name."""
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            name = alias.asname or root
            resolved = alias.name if alias.asname else root
            if resolved == "os":
                binding = _OS_MODULE_BINDING
            elif resolved == "subprocess":
                binding = _SUBPROCESS_MODULE_BINDING
            else:
                binding = _OTHER_BINDING
            self.scope.bind(name, binding)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Bind supported direct imports while ignoring wildcard inference."""
        for alias in node.names:
            if alias.name == "*":
                continue
            name = alias.asname or alias.name
            binding = _OTHER_BINDING
            if node.level == 0 and node.module == "os" and alias.name in _OS_SHELL_APIS:
                binding = ("os-function", f"os.{alias.name}")
            elif (
                node.level == 0
                and node.module == "subprocess"
                and alias.name in _SUBPROCESS_IMPLICIT_SHELL_APIS
            ):
                binding = ("subprocess-implicit-shell", f"subprocess.{alias.name}")
            elif (
                node.level == 0
                and node.module == "subprocess"
                and alias.name in _SUBPROCESS_SHELL_APIS
            ):
                binding = ("subprocess-function", f"subprocess.{alias.name}")
            self.scope.bind(name, binding)

    def visit_Global(self, _node: ast.Global) -> None:
        """Use declarations precomputed when the function scope was created."""

    def visit_Nonlocal(self, _node: ast.Nonlocal) -> None:
        """Use declarations precomputed when the function scope was created."""

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit the value before applying assignment shadowing."""
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotations and values before applying target shadowing."""
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
        self._bind_target(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Visit an augmented operation before shadowing its target."""
        self.visit(node.target)
        self.visit(node.value)
        self._bind_target(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Visit a walrus value before binding its target."""
        self.visit(node.value)
        self._bind_target(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        """Keep deleted local names shadowed rather than falling through."""
        for target in node.targets:
            self._bind_target(target)

    def visit_For(self, node: ast.For) -> None:
        """Visit loop input, bind its target, then traverse both branches."""
        self.visit(node.iter)
        self._bind_target(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        """Apply the same binding order to an async-for loop."""
        self.visit_For(node)

    def visit_With(self, node: ast.With) -> None:
        """Visit context expressions before binding their aliases."""
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Apply the same binding order to an async-with statement."""
        self.visit_With(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Visit exception type, bind its alias, and traverse the handler."""
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self.scope.bind(node.name, _OTHER_BINDING)
        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Traverse one synchronous function with lexical shadowing."""
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Traverse one asynchronous function with lexical shadowing."""
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Traverse a class body without leaking class bindings into methods."""
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.scope.bind(node.name, _OTHER_BINDING)
        previous = self.scope
        self.scope = _Scope(previous, kind="class")
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope = previous

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Traverse a lambda body with parameter shadowing."""
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        local_names = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        }
        if node.args.vararg is not None:
            local_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            local_names.add(node.args.kwarg.arg)
        parent = self.scope.parent if self.scope.kind == "class" else self.scope
        previous = self.scope
        self.scope = _Scope(parent, kind="function", local_names=local_names)
        try:
            self.visit(node.body)
        finally:
            self.scope = previous

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
    ) -> None:
        """Traverse a Python 3 comprehension in its own target scope."""
        if not node.generators:
            return
        self.visit(node.generators[0].iter)
        previous = self.scope
        self.scope = _Scope(previous, kind="comprehension")
        try:
            for index, generator in enumerate(node.generators):
                if index:
                    self.visit(generator.iter)
                self._bind_target(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)
        finally:
            self.scope = previous

    def visit_ListComp(self, node: ast.ListComp) -> None:
        """Traverse one list comprehension with isolated targets."""
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        """Traverse one set comprehension with isolated targets."""
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        """Traverse one generator expression with isolated targets."""
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        """Traverse one dictionary comprehension with isolated targets."""
        self._visit_comprehension(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Record supported calls and continue into nested call expressions."""
        resolved = self._binding_for_call(node.func)
        if resolved is not None:
            kind, api = resolved
            if kind in {"os-function", "subprocess-implicit-shell"} or any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                self._record_call(node, api)
        self.generic_visit(node)


def find_python_shell_calls(source: str) -> tuple[PythonShellCall, ...]:
    """Return high-confidence Python shell calls in deterministic source order."""
    if not isinstance(source, str):
        return ()
    try:
        tree = ast.parse(source)
    except (SyntaxError, TypeError, ValueError, RecursionError):
        return ()
    visitor = _ShellCallVisitor(source)
    visitor.visit(tree)
    return tuple(
        sorted(
            visitor.calls,
            key=lambda call: (call.line, call.column, call.api),
        )
    )
