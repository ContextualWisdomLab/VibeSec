"""Tests for the multi-tenant control-plane store + API."""

import json
import threading
import urllib.error
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import (
    _is_slack_webhook,
    _send_alert,
    _slack_blocks,
    add_scan,
    connect,
    create_key,
    create_org,
    get_scan,
    has_role,
    list_scans,
    make_control_plane_server,
    org_for_key,
    role_for_key,
    scan_trend,
    set_webhook,
)

FINDINGS = [
    {"severity": "CRITICAL", "rule_id": "x", "context": "app-code"},
    {"severity": "INFO", "rule_id": "y", "context": "doc"},
]


# ---- store ----


def test_org_key_auth():
    conn = connect(":memory:")
    oid, key = create_org(conn, "Acme")
    assert org_for_key(conn, key) == oid
    assert org_for_key(conn, "agk_wrong") is None
    assert org_for_key(conn, "") is None


def test_add_and_list_scan_counts():
    conn = connect(":memory:")
    oid, _ = create_org(conn, "Acme")
    s = add_scan(conn, oid, FINDINGS, repo="acme/app", commit_sha="abc")
    assert s["total"] == 2 and s["deploy_blocking"] == 1
    listed = list_scans(conn, oid)
    assert len(listed) == 1 and listed[0]["repo"] == "acme/app"
    full = get_scan(conn, oid, s["id"])
    assert len(full["findings"]) == 2


def test_tenant_isolation():
    conn = connect(":memory:")
    a, _ = create_org(conn, "Acme")
    b, _ = create_org(conn, "Beta")
    s = add_scan(conn, a, FINDINGS)
    assert get_scan(conn, b, s["id"]) is None  # cross-tenant read blocked
    assert list_scans(conn, b) == []


# ---- API ----


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _req(method, url, key=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if key:
        r.add_header("Authorization", f"Bearer {key}")
    if data:
        r.add_header("Content-Type", "application/json")
    with closing(urllib.request.urlopen(r, timeout=5)) as resp:
        return resp.status, json.loads(resp.read())


@pytest.fixture()
def server(tmp_path):
    db = str(tmp_path / "cp.db")
    conn = connect(db)
    _oid, key = create_org(conn, "Acme")
    conn.close()
    srv = make_control_plane_server("127.0.0.1", 0, db)
    _serve(srv)
    port = srv.server_address[1]
    yield f"http://127.0.0.1:{port}", key
    srv.shutdown()
    srv.server_close()


def test_health_no_auth(server):
    base, _ = server
    status, body = _req("GET", f"{base}/api/v1/health")
    assert status == 200 and body["status"] == "ok"


def test_ingest_and_history(server):
    base, key = server
    status, summary = _req(
        "POST",
        f"{base}/api/v1/scans",
        key,
        {"repo": "acme/app", "commit": "abc", "findings": FINDINGS},
    )
    assert status == 201 and summary["deploy_blocking"] == 1
    status, listing = _req("GET", f"{base}/api/v1/scans", key)
    assert status == 200 and len(listing["scans"]) == 1
    scan_id = listing["scans"][0]["id"]
    status, full = _req("GET", f"{base}/api/v1/scans/{scan_id}", key)
    assert status == 200 and len(full["findings"]) == 2


def test_auth_required(server):
    base, _ = server
    for key in (None, "agk_wrong"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            _req("GET", f"{base}/api/v1/scans", key)
        assert exc.value.code == 401


def test_bad_body_400(server):
    base, key = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req("POST", f"{base}/api/v1/scans", key, {"findings": "not-a-list"})
    assert exc.value.code == 400


def test_console_served_at_root(server):
    base, _ = server
    with closing(urllib.request.urlopen(base + "/", timeout=5)) as resp:
        body = resp.read()
    assert resp.status == 200
    assert b"AppGuardrail Console" in body  # served the org console HTML


def test_drift_new_blocking():
    conn = connect(":memory:")
    oid, _ = create_org(conn, "Acme")
    crit = {
        "severity": "CRITICAL",
        "rule_id": "secret",
        "file": "a.ts",
        "line": 3,
        "message": "hardcoded key",
        "context": "app-code",
    }
    other = {
        "severity": "HIGH",
        "rule_id": "rls",
        "file": "b.sql",
        "line": 1,
        "message": "RLS off",
        "context": "app-code",
    }
    s1 = add_scan(conn, oid, [crit], repo="acme/app")
    assert s1["new_blocking"] == 1  # first scan: all blocking are new
    s2 = add_scan(conn, oid, [{**crit, "line": 9}], repo="acme/app")
    assert s2["new_blocking"] == 0  # same finding, line moved -> not new
    s3 = add_scan(conn, oid, [crit, other], repo="acme/app")
    assert (
        s3["deploy_blocking"] == 2 and s3["new_blocking"] == 1
    )  # one newly introduced
    s4 = add_scan(conn, oid, [crit], repo="acme/other")
    assert s4["new_blocking"] == 1  # different repo -> independent baseline


def test_webhook_alerts_on_drift(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "appguardrail_core.controlplane._send_alert",
        lambda url, payload, **kw: sent.append((url, payload, kw)) or True,
    )
    conn = connect(":memory:")
    oid, _ = create_org(conn, "Acme")
    set_webhook(conn, oid, "http://hook.example/x")
    crit = {
        "severity": "CRITICAL",
        "rule_id": "s",
        "file": "a.ts",
        "line": 1,
        "message": "k",
        "context": "app-code",
    }
    add_scan(conn, oid, [crit], repo="acme/app")  # 1 new -> alert
    add_scan(conn, oid, [{**crit, "line": 9}], repo="acme/app")  # 0 new -> no alert
    assert len(sent) == 1
    url, payload, kw = sent[0]
    assert url == "http://hook.example/x"
    assert payload["event"] == "drift.new_blocking" and payload["new_blocking"] == 1
    # add_scan hands the Slack renderer the org name + the new findings.
    assert kw["org_name"] == "Acme"
    assert [f["rule_id"] for f in kw["new_findings"]] == ["s"]


def test_no_webhook_no_alert(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "appguardrail_core.controlplane._send_alert",
        lambda url, payload, **kw: sent.append(1),
    )
    conn = connect(":memory:")
    oid, _ = create_org(conn, "Acme")  # no webhook set
    add_scan(
        conn,
        oid,
        [
            {
                "severity": "CRITICAL",
                "rule_id": "s",
                "file": "a",
                "line": 1,
                "context": "app-code",
            }
        ],
    )
    assert sent == []  # no webhook -> no delivery attempt


def test_api_set_webhook(server):
    base, key = server
    status, body = _req(
        "POST", f"{base}/api/v1/webhook", key, {"url": "http://hook.example/y"}
    )
    assert status == 200 and body["webhook_url"] == "http://hook.example/y"


def test_api_empty_webhook_body_rejected(server):
    import http.client
    from urllib.parse import urlparse as _u

    base, key = server
    _req("POST", f"{base}/api/v1/webhook", key, {"url": "http://hook.example/y"})

    parsed = _u(base)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    conn.putrequest("POST", "/api/v1/webhook")
    conn.putheader("Authorization", f"Bearer {key}")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", "0")
    conn.endheaders()
    response = conn.getresponse()

    assert response.status == 400
    assert json.loads(response.read()) == {"error": "invalid JSON body"}
    conn.close()


def test_api_explicit_webhook_deletion(server):
    base, key = server
    status, body = _req("POST", f"{base}/api/v1/webhook", key, {"url": None})

    assert status == 200
    assert body["webhook_url"] is None


def test_api_set_webhook_ssrf_protection(server):
    base, key = server
    # Invalid type
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req("POST", f"{base}/api/v1/webhook", key, {"url": 1234})
    assert exc.value.code == 400
    assert json.loads(exc.value.read())["error"] == "invalid webhook url"
    # Localhost SSRF attempt
    with pytest.raises(urllib.error.HTTPError) as exc:
        _req("POST", f"{base}/api/v1/webhook", key, {"url": "http://127.0.0.1/hook"})
    assert exc.value.code == 400
    assert json.loads(exc.value.read())["error"] == "invalid webhook url"


def test_roles_and_key_scoping():
    conn = connect(":memory:")
    oid, owner_key = create_org(conn, "Acme")
    # bootstrap key is an owner
    assert role_for_key(conn, owner_key) == (oid, "owner")
    _, mk = create_key(conn, oid, "member", "ci")
    _, vk = create_key(conn, oid, "viewer")
    assert role_for_key(conn, mk) == (oid, "member")
    assert role_for_key(conn, vk) == (oid, "viewer")
    assert role_for_key(conn, "agk_bad") is None
    assert has_role("owner", "member") and has_role("member", "member")
    assert not has_role("viewer", "member") and not has_role("member", "owner")


def test_api_role_enforcement(server):
    base, owner_key = server
    # forge member + viewer keys directly in the fixture DB via a fresh connect
    # (the server shares the same file); simplest: create via the owner API.
    status, mk = _req("POST", f"{base}/api/v1/keys", owner_key, {"role": "member"})
    assert status == 201 and mk["role"] == "member"
    status, vk = _req("POST", f"{base}/api/v1/keys", owner_key, {"role": "viewer"})
    assert status == 201 and vk["role"] == "viewer"
    member, viewer = mk["api_key"], vk["api_key"]

    F = {"findings": [{"severity": "CRITICAL", "rule_id": "x", "context": "app-code"}]}
    # viewer: read yes, ingest no, keys no
    assert _req("GET", f"{base}/api/v1/scans", viewer)[0] == 200
    for method, path, body in [
        ("POST", "/api/v1/scans", F),
        ("POST", "/api/v1/keys", {"role": "member"}),
        ("POST", "/api/v1/webhook", {"url": "http://x"}),
    ]:
        with pytest.raises(urllib.error.HTTPError) as e:
            _req(method, f"{base}{path}", viewer, body)
        assert e.value.code == 403
    # member: ingest yes, keys/webhook no
    assert _req("POST", f"{base}/api/v1/scans", member, F)[0] == 201
    with pytest.raises(urllib.error.HTTPError) as e:
        _req("POST", f"{base}/api/v1/webhook", member, {"url": "http://x"})
    assert e.value.code == 403
    # owner: all yes
    assert (
        _req("POST", f"{base}/api/v1/webhook", owner_key, {"url": "http://x"})[0] == 200
    )


def test_pagination_and_trend():
    conn = connect(":memory:")
    oid, _ = create_org(conn, "Acme")
    for i in range(5):
        add_scan(
            conn,
            oid,
            [
                {
                    "severity": "CRITICAL",
                    "rule_id": f"r{i}",
                    "file": "a",
                    "line": i,
                    "message": "m",
                    "context": "app-code",
                }
            ],
            repo="acme/app",
        )
    # list is newest-first; offset skips
    p1 = list_scans(conn, oid, limit=2, offset=0)
    p2 = list_scans(conn, oid, limit=2, offset=2)
    assert [s["id"] for s in p1] == [5, 4]
    assert [s["id"] for s in p2] == [3, 2]
    # trend is oldest-first with the right length
    t = scan_trend(conn, oid, limit=10)
    assert len(t) == 5
    assert t[0]["created_at"] <= t[-1]["created_at"]
    assert all("deploy_blocking" in x and "new_blocking" in x for x in t)


def test_api_pagination_and_trend(server):
    base, key = server
    for i in range(4):
        _req("POST", f"{base}/api/v1/scans", key, {"repo": "r", "findings": []})
    _, page = _req("GET", f"{base}/api/v1/scans?limit=2&offset=1", key)
    assert len(page["scans"]) == 2
    _, tr = _req("GET", f"{base}/api/v1/scans/trend?limit=3", key)
    assert len(tr["trend"]) == 3


# ---- Slack-formatted drift alert ----


def test_is_slack_webhook():
    assert _is_slack_webhook("https://hooks.slack.com/services/T/B/xyz")
    assert not _is_slack_webhook(
        "https://hooks.slack.com.evil.example/x"
    )  # host must match
    assert not _is_slack_webhook("https://hook.example/x")
    assert not _is_slack_webhook("not a url")


def test_slack_blocks_shape_and_content():
    payload = {"org_id": 7, "scan_id": 42, "repo": "acme/app", "new_blocking": 2}
    findings = [
        {"rule_id": "hardcoded-secret", "file": "src/a.ts"},
        {"rule_id": "sql-injection", "file": "src/b.py"},
    ]
    body = _slack_blocks("Acme", payload, findings)
    assert "blocks" in body and body["blocks"][0]["type"] == "header"
    text = json.dumps(body)
    assert "Acme" in text  # org name rendered
    assert (
        "2 new deploy-blocking findings" in body["blocks"][0]["text"]["text"]
    )  # count in header
    assert (
        "hardcoded-secret" in text and "src/a.ts" in text
    )  # top rule_id + file listed
    assert "#42" in text  # scan id


def test_slack_blocks_caps_and_escapes():
    findings = [{"rule_id": f"r{i}", "file": f"f{i}"} for i in range(8)]
    payload = {"org_id": 1, "scan_id": 1, "repo": "r", "new_blocking": 8}
    body = _slack_blocks("Ben & <Co>", payload, findings, top=5)
    detail = body["blocks"][-1]["text"]["text"]
    assert detail.count("• `r") == 5  # only top 5 rules listed
    assert "+3 more" in detail  # overflow line
    assert "Ben &amp; &lt;Co&gt;" in json.dumps(body)  # org name escaped for Slack


def test_send_alert_slack_vs_generic(monkeypatch):
    posted = {}

    def _fake_build_opener(*handlers):
        assert any(type(h).__name__ == "SafeRedirectHandler" for h in handlers)

        class FakeOpener:
            def open(self, req, timeout=None):
                posted["url"] = req.full_url
                posted["body"] = json.loads(req.data.decode())

                class _R:
                    pass

                return _R()

        return FakeOpener()

    monkeypatch.setattr(urllib.request, "build_opener", _fake_build_opener)
    generic = {
        "event": "drift.new_blocking",
        "org_id": 3,
        "scan_id": 9,
        "repo": "acme/app",
        "new_blocking": 1,
        "deploy_blocking": 1,
    }
    findings = [{"rule_id": "secret", "file": "a.ts"}]

    # Slack URL -> Block Kit payload
    assert (
        _send_alert(
            "https://hooks.slack.com/services/x",
            generic,
            org_name="Acme",
            new_findings=findings,
        )
        is True
    )
    assert "blocks" in posted["body"]
    assert "Acme" in json.dumps(posted["body"])
    assert (
        "1 new deploy-blocking finding" in posted["body"]["blocks"][0]["text"]["text"]
    )

    # Generic URL -> untouched original payload (backward compatible)
    assert (
        _send_alert(
            "https://hook.example/x", generic, org_name="Acme", new_findings=findings
        )
        is True
    )
    assert posted["body"] == generic
    assert "blocks" not in posted["body"]


# ---- API hardening: body cap + query clamps ----


def test_negative_and_huge_limit_clamped(server):
    base, key = server
    for _ in range(3):
        _req("POST", f"{base}/api/v1/scans", key, {"repo": "r", "findings": []})
    # limit=-1 means UNBOUNDED in sqlite — must be clamped, not passed through
    _, page = _req("GET", f"{base}/api/v1/scans?limit=-1", key)
    assert 1 <= len(page["scans"]) <= 1000
    _, page2 = _req("GET", f"{base}/api/v1/scans?limit=999999&offset=-5", key)
    assert len(page2["scans"]) <= 1000  # hi clamp; negative offset -> 0


def test_oversized_body_rejected(server):
    import http.client
    from urllib.parse import urlparse as _u

    base, key = server
    u = _u(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    # Claim an over-cap body; server must 400 without reading it all.
    conn.putrequest("POST", "/api/v1/scans")
    conn.putheader("Authorization", f"Bearer {key}")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(50 * 1024 * 1024))
    conn.endheaders()
    conn.send(b"{")  # send a byte so the server can respond
    resp = conn.getresponse()
    assert resp.status == 400
    conn.close()


def test_negative_content_length_rejected(server):
    import http.client
    from urllib.parse import urlparse as _u

    base, key = server
    u = _u(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    conn.putrequest("POST", "/api/v1/scans")
    conn.putheader("Authorization", f"Bearer {key}")
    conn.putheader("Content-Length", "-1")
    conn.endheaders()
    resp = conn.getresponse()
    assert resp.status == 400
    conn.close()
