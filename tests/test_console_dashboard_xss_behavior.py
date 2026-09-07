"""Executable DOM-sink regression for the standalone AppGuardrail console."""

import re
import subprocess

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def _load_script_prefix() -> str:
    """Return the shipped console script through `load` without detail boot code."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    match = re.search(r"<script>(?P<script>[\s\S]*?)</script>", html, re.IGNORECASE)
    assert match is not None
    prefix, separator, _ = match.group("script").partition(
        "async function detail(id,tr){"
    )
    assert separator
    return prefix


def test_untrusted_scan_summary_values_are_escaped_before_innerhtml() -> None:
    """Run the real `load` renderer and keep hostile scan metadata inert at HTML sinks."""
    script = _load_script_prefix()
    harness = r"""
const elements = new Map();
function element(name) {
  return {
    name,
    innerHTML: '',
    textContent: '',
    classList: {
      add() {},
      remove() {},
      contains() { return false; }
    }
  };
}
for (const selector of ['#msg','#app','#logout','#conn','#stats','#trend','#history tbody','#detail']) {
  elements.set(selector, element(selector));
}
const document = {
  querySelector(selector) { return elements.get(selector) || element(selector); },
  querySelectorAll() { return []; },
  addEventListener() {},
  activeElement: null
};
const sessionStorage = { getItem() { return null; } };
const window = { matchMedia() { return {matches: true}; } };
const payload = {
  id: '7" autofocus onfocus="globalThis.pwned=1',
  created_at: '<svg onload="globalThis.pwned=2"></svg>',
  repo: '<img src=x onerror="globalThis.pwned=3">',
  commit: 'deadbeef',
  total: '<img src=x onerror="globalThis.pwned=4">',
  deploy_blocking: 2,
  new_blocking: 1,
  severity_counts: {CRITICAL: '<svg onload="globalThis.pwned=5"></svg>'}
};
async function fetch() {
  return {
    status: 200,
    ok: true,
    async json() { return {scans: [payload]}; }
  };
}
"""
    assertions = r"""
(async () => {
  await load();
  const stats = elements.get('#stats').innerHTML;
  const trend = elements.get('#trend').innerHTML;
  const history = elements.get('#history tbody').innerHTML;
  const combined = stats + trend + history;

  for (const raw of [
    payload.created_at,
    payload.repo,
    payload.total,
    payload.severity_counts.CRITICAL,
    `data-id="${payload.id}"`
  ]) {
    if (combined.includes(raw)) throw new Error(`raw hostile value reached innerHTML: ${raw}`);
  }
  if (!stats.includes('&lt;svg onload=&quot;globalThis.pwned=5&quot;&gt;&lt;/svg&gt;')) {
    throw new Error('critical summary payload was not HTML-escaped');
  }
  if (!trend.includes('&lt;svg onload=&quot;globalThis.pwned=2&quot;&gt;&lt;/svg&gt;')) {
    throw new Error('trend timestamp payload was not HTML-escaped');
  }
  if (!history.includes('&lt;img src=x onerror=&quot;globalThis.pwned=4&quot;&gt;')) {
    throw new Error('scan total payload was not HTML-escaped');
  }
  if (!history.includes('data-id="7&quot; autofocus onfocus=&quot;globalThis.pwned=1"')) {
    throw new Error('scan id did not remain inside the quoted data-id attribute');
  }
  if (globalThis.pwned !== undefined) throw new Error('hostile payload executed');
})().catch(error => { console.error(error); process.exit(1); });
"""

    completed = subprocess.run(
        ["node", "-e", harness + script + assertions],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
