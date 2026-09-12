"""Regression tests for the webhook persistence security boundary."""

import pytest

from appguardrail_core.controlplane import connect, create_org, set_webhook


def _stored_webhook(conn, org_id: int):
    return conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()[0]


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
