import re

with open("tests/test_rules_core.py", "r") as f:
    content = f.read()

content = content.replace(
    'class RejectRegex:\n        def finditer(self, _message):\n            raise AssertionError("regex engine must not run on the no-bracket fast path")',
    'class RejectRegex:\n        def finditer(self, _message):  # pragma: no cover\n            raise AssertionError("regex engine must not run on the no-bracket fast path")'
)

with open("tests/test_rules_core.py", "w") as f:
    f.write(content)
