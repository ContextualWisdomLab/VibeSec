from pathlib import Path

path = Path("tests/test_console_dashboard_security.py")
content = path.read_text(encoding="utf-8")

# Because we implemented `count()`, the template changed:
# From: `aria-label="${esc(s.created_at)}: ${esc(String(s.deploy_blocking||0))} blocking"`
# To:   `aria-label="${esc(s.created_at)}: ${db} blocking"`
# where db = count(s.deploy_blocking)
# The contract tests assert the literal string representations which are now obsolete.

content = content.replace(
    'assert trend_template.count("${esc(String(s.deploy_blocking||0))}") >= 2',
    'assert trend_template.count("${db} blocking") >= 2'
)

content = content.replace(
    'assert \'aria-label="${esc(s.created_at)}: ${esc(String(s.deploy_blocking||0))} blocking"\' in html',
    'assert \'aria-label="${esc(s.created_at)}: ${db} blocking"\' in html'
)

path.write_text(content, encoding="utf-8")
