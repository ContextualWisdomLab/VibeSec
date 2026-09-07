import pytest

from appguardrail_core.controlplane import connect, create_org, set_webhook


def test_set_webhook_rejects_loopback_before_persistence() -> None:
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "ssrf-contract")

    with pytest.raises(ValueError, match="Invalid webhook URL"):
        set_webhook(conn, org_id, "http://127.0.0.1:8080/internal")

    row = conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()
    assert row["webhook_url"] is None


def test_set_webhook_allows_explicit_clear_without_url_validation() -> None:
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "clear-contract")

    set_webhook(conn, org_id, None)

    row = conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()
    assert row["webhook_url"] is None


def test_set_webhook_treats_empty_string_as_explicit_clear() -> None:
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "empty-clear-contract")
    conn.execute(
        "UPDATE orgs SET webhook_url = ? WHERE id = ?",
        ("https://example.com/hook", org_id),
    )
    conn.commit()

    set_webhook(conn, org_id, "")

    row = conn.execute(
        "SELECT webhook_url FROM orgs WHERE id = ?", (org_id,)
    ).fetchone()
    assert row["webhook_url"] is None


def test_set_webhook_rejects_non_string_values() -> None:
    conn = connect(":memory:")
    org_id, _ = create_org(conn, "type-contract")

    with pytest.raises(ValueError, match="Invalid webhook URL"):
        set_webhook(conn, org_id, 1234)  # type: ignore[arg-type]
