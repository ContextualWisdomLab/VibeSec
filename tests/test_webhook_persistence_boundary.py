"""Regression tests for the webhook persistence security boundary."""

import json
import threading
import urllib.request
from contextlib import closing

import pytest

from appguardrail_core.controlplane import (
    connect,
    create_org,
    make_control_plane_server,
    set_webhook,
)


def _stored_webhook(conn, org_id: int):
    return conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()[0]


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _req(method, url, key=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if key:
        request.add_header("Authorization", f"Bearer {key}")
    if data:
        request.add_header("Content-Type", "application/json")
    with closing(urllib.request.urlopen(request, timeout=5)) as response:
        return response.status, json.loads(response.read())


@pytest.fixture()
def webhook_server(tmp_path):
    db_path = str(tmp_path / "controlplane.db")
    conn = connect(db_path)
    _, key = create_org(conn, "Acme")
    conn.close()
    server = make_control_plane_server("127.0.0.1", 0, db_path)
    _serve(server)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", key
    finally:
        server.shutdown()
        server.server_close()


def test_set_webhook_rejects_unsafe_destination_before_persistence():
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")

    with pytest.raises(ValueError, match="invalid webhook url"):
        set_webhook(conn, org_id, "http://127.0.0.1/internal")

    assert _stored_webhook(conn, org_id) is None


def test_set_webhook_rejects_non_string_before_sqlite_binding():
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")

    with pytest.raises(ValueError, match="invalid webhook url"):
        set_webhook(conn, org_id, 1234)  # type: ignore[arg-type]

    assert _stored_webhook(conn, org_id) is None


def test_set_webhook_empty_string_clears_existing_destination():
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "Acme")
    set_webhook(conn, org_id, "http://hook.example/x")
    assert _stored_webhook(conn, org_id) == "http://hook.example/x"

    set_webhook(conn, org_id, "")

    assert _stored_webhook(conn, org_id) is None


def test_api_empty_string_clears_existing_destination(webhook_server):
    base_url, key = webhook_server
    status, body = _req(
        "POST", f"{base_url}/api/v1/webhook", key, {"url": "http://hook.example/x"}
    )
    assert status == 200
    assert body["webhook_url"] == "http://hook.example/x"

    status, body = _req("POST", f"{base_url}/api/v1/webhook", key, {"url": ""})

    assert status == 200
    assert body["webhook_url"] is None
