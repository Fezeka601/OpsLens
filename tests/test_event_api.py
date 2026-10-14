from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from opslens.api.app import app
from opslens.database.connection import get_connection
from opslens.database.test_connection import get_test_connection
from opslens.database import (
    schema,
    event_repository,
    alert_repository,
    incident_repository,
    investigation_repository,
    response_repository,
)
from opslens.database.schema import create_tables


client = TestClient(app)


def redirect_to_test_database(monkeypatch):
    """Redirect schema and repository database connections to the test database."""
    monkeypatch.setattr(
        schema,
        get_connection.__name__,
        get_test_connection,
    )

    monkeypatch.setattr(
        event_repository,
        get_connection.__name__,
        get_test_connection,
    )

    monkeypatch.setattr(
        alert_repository,
        get_connection.__name__,
        get_test_connection,
    )

    monkeypatch.setattr(
        incident_repository,
        get_connection.__name__,
        get_test_connection,
    )

    monkeypatch.setattr(
        investigation_repository,
        get_connection.__name__,
        get_test_connection,
    )

    monkeypatch.setattr(
        response_repository,
        get_connection.__name__,
        get_test_connection,
    )

    create_tables()


def test_duplicate_event_submission_is_ignored(monkeypatch):
    redirect_to_test_database(monkeypatch)

    event_id = str(uuid4())

    payload = {
        "event_id": event_id,
        "service": "idempotency-api-test",
        "event_type": "FRAUD_CHECK",
        "user_id": f"U-{uuid4()}",
        "transaction_id": f"TX-{uuid4()}",
        "ip_address": "192.168.1.200",
        "metadata": {
            "test_case": "automated_idempotency_test"
        },
    }

    # First submission should create the event.
    first_response = client.post("/events", json=payload)

    assert first_response.status_code == 201, first_response.text

    first_body = first_response.json()

    assert first_body["event_id"] == event_id
    assert first_body.get("duplicate") is not True

    # Repeating the exact same request should be ignored.
    second_response = client.post("/events", json=payload)

    assert second_response.status_code == 200, second_response.text

    second_body = second_response.json()

    assert second_body["event_id"] == event_id
    assert second_body["duplicate"] is True
    assert second_body["detection"]["new_alerts_saved"] == 0
    assert second_body["incidents_created"] == 0

    # Verify that the test database contains exactly one copy.
    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM security_events
                WHERE event_id = %s
                """,
                (event_id,),
            )

            row = cursor.fetchone()

        assert row[0] == 1

    finally:
        connection.close()


def test_high_value_payment_creates_alert(monkeypatch):
    redirect_to_test_database(monkeypatch)

    event_id = str(uuid4())

    payload = {
        "event_id": event_id,
        "service": "payment-api-test",
        "event_type": "PAYMENT_SUCCESS",
        "user_id": f"U-{uuid4()}",
        "transaction_id": f"TX-{uuid4()}",
        "ip_address": "192.168.1.210",
        "metadata": {
            "amount": 75000,
            "currency": "ZAR",
        },
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 201, response.text

    body = response.json()

    assert body["event_id"] == event_id
    assert body["detection"]["matches_found"] >= 1
    assert body["detection"]["new_alerts_saved"] >= 1

    alert_rules = {
        alert["rule"]
        for alert in body["detection"]["alerts"]
    }

    assert "UNUSUAL_PAYMENT_AMOUNT" in alert_rules

    # Verify the alert is also available through the 'alerts' endpoint.
    alerts_response = client.get("/alerts?limit=500")

    assert alerts_response.status_code == 200, alerts_response.text

    saved_alerts = alerts_response.json()

    assert any(
        alert["rule"] == "UNUSUAL_PAYMENT_AMOUNT"
        and event_id in [
            str(item)
            for item in alert["event_ids"]
        ]
        for alert in saved_alerts
    )

def test_privilege_violation_creates_incident_and_response_actions(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)

    event_id = str(uuid4())

    payload = {
        "event_id": event_id,
        "service": "authorization-api-test",
        "event_type": "PRIVILEGE_VIOLATION",
        "user_id": f"U-{uuid4()}",
        "transaction_id": f"TX-{uuid4()}",
        "ip_address": "192.168.1.220",
        "metadata": {
            "user_role": "USER",
            "required_role": "ADMIN",
            "action": "DELETE_USER",
        },
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 201, response.text

    body = response.json()

    # Confirm that privilege abuse was detected.
    assert body["detection"]["new_alerts_saved"] >= 1

    alert_rules = {
        alert["rule"]
        for alert in body["detection"]["alerts"]
    }

    assert "PRIVILEGE_ABUSE_DETECTION" in alert_rules

    # Confirm that the event produced an incident.
    assert body["incidents_created"] >= 1
    assert len(body["incidents"]) >= 1

    incident_ids = {
        str(incident["incident_id"])
        for incident in body["incidents"]
    }

    assert incident_ids

    # Confirm that response actions were saved for these incidents.
    actions_response = client.get("/response-actions")

    # Retrieve response actions for each newly created incident.
    incident_actions = []

    for incident_id in incident_ids:
        actions_response = client.get(
            f"/incidents/{incident_id}/response-actions"
        )

        assert actions_response.status_code == 200, actions_response.text

        actions_body = actions_response.json()

        if isinstance(actions_body, dict):
            saved_actions = actions_body.get(
                "response_actions",
                actions_body.get("actions", []),
            )
        else:
            saved_actions = actions_body

        assert isinstance(saved_actions, list), (
            f"Expected a list of response actions, got: {actions_body}"
        )

        incident_actions.extend(saved_actions)

    assert incident_actions, (
        "Expected saved response actions for the newly created incident."
    )

@pytest.mark.parametrize(
    "service",
    [
        "",
        "   ",
    ],
)
def test_event_rejects_empty_or_whitespace_service(service):
    response = client.post(
        "/events",
        json={
            "service": service,
            "event_type": "FRAUD_CHECK",
        },
    )

    assert response.status_code == 422, response.text


def test_event_rejects_empty_event_id():
    response = client.post(
        "/events",
        json={
            "event_id": "",
            "service": "validation-test",
            "event_type": "FRAUD_CHECK",
        },
    )

    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "metadata",
    [
        {},                              # Missing amount
        {"amount": True},                # Boolean is not a valid amount
        {"amount": "not-a-number"},      # Non-numeric
        {"amount": -1},                  # Negative
        {"amount": "NaN"},               # Not finite
        {"amount": "Infinity"},          # Not finite
    ],
)
def test_payment_success_rejects_invalid_amounts(metadata):
    response = client.post(
        "/events",
        json={
            "service": "payment-validation-test",
            "event_type": "PAYMENT_SUCCESS",
            "user_id": "U-VALIDATION-TEST",
            "transaction_id": "TX-VALIDATION-TEST",
            "metadata": metadata,
        },
    )

    assert response.status_code == 422, response.text