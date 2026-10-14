
from uuid import uuid4
from opslens.database.connection import get_connection
from fastapi.testclient import TestClient

from opslens.api.app import app
from opslens.database import (
    schema,
    alert_repository,
    incident_repository,
    response_repository,
)
from opslens.database.test_connection import get_test_connection
from opslens.database.schema import create_tables
from opslens.models.security_alert import SecurityAlert
from opslens.models.security_incident import SecurityIncident
from opslens.database.alert_repository import AlertRepository
from opslens.database.incident_repository import IncidentRepository


client = TestClient(app)


def redirect_to_test_database(monkeypatch):
    """Redirect database operations to the test database."""
    monkeypatch.setattr(
        schema,
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
        response_repository,
        get_connection.__name__,
        get_test_connection,
    )

    create_tables()



def create_test_incident_and_alert():
    """Create an incident and alert for response-action tests."""
    event_id = str(uuid4())

    alert = SecurityAlert(
        rule="PAYMENT_FRAUD_DETECTION",
        severity="HIGH",
        message="Test payment fraud alert",
        user_id="U-RESPONSE-TEST",
        event_ids=[event_id],
    )
    AlertRepository().save(alert)

    incident = SecurityIncident(
        title="Test response-action incident",
        description="Incident created for response-action API testing",
        severity="HIGH",
        status="OPEN",
        user_id="U-RESPONSE-TEST",
        alert_ids=[alert.alert_id],
        event_ids=[event_id],
    )
    IncidentRepository().save(incident)

    return incident, alert


def create_test_response_action(incident, alert):
    """Insert a response action associated with the incident and alert."""
    response_action_id = str(uuid4())

    connection = get_test_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incident_response_actions (
                    response_action_id,
                    incident_id,
                    alert_id,
                    action,
                    priority,
                    reason,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    response_action_id,
                    incident.incident_id,
                    alert.alert_id,
                    "FLAG_TRANSACTIONS",
                    "HIGH",
                    "Test response action",
                    "RECOMMENDED",
                ),
            )
        connection.commit()
    finally:
        connection.close()

    return response_action_id


def test_get_response_actions_returns_empty_list_for_new_incident(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)
    incident, _ = create_test_incident_and_alert()

    response = client.get(
        f"/incidents/{incident.incident_id}/response-actions"
    )

    assert response.status_code == 200
    assert response.json()["incident_id"] == incident.incident_id
    assert response.json()["action_count"] == 0
    assert response.json()["actions"] == []


def test_get_response_actions_returns_404_for_missing_incident(monkeypatch):
    redirect_to_test_database(monkeypatch)

    response = client.get(
        f"/incidents/{uuid4()}/response-actions"
    )

    assert response.status_code == 404


def test_get_response_actions_returns_saved_action(monkeypatch):
    redirect_to_test_database(monkeypatch)
    incident, alert = create_test_incident_and_alert()
    action_id = create_test_response_action(incident, alert)

    response = client.get(
        f"/incidents/{incident.incident_id}/response-actions"
    )

    assert response.status_code == 200

    body = response.json()
    assert body["action_count"] == 1
    assert body["actions"][0]["response_action_id"] == action_id
    assert body["actions"][0]["action"] == "FLAG_TRANSACTIONS"
    assert body["actions"][0]["status"] == "RECOMMENDED"


def test_update_response_action_status_succeeds(monkeypatch):
    redirect_to_test_database(monkeypatch)
    incident, alert = create_test_incident_and_alert()
    action_id = create_test_response_action(incident, alert)

    response = client.patch(
        f"/incidents/{incident.incident_id}/response-actions/"
        f"{action_id}/status",
        json={"status": "UNDER_REVIEW"},
    )

    assert response.status_code == 200

    response_actions = client.get(
        f"/incidents/{incident.incident_id}/response-actions"
    )

    assert response_actions.status_code == 200

    actions = response_actions.json()["actions"]
    updated_action = next(
        action
        for action in actions
        if action["response_action_id"] == action_id
    )
    assert updated_action["status"] == "UNDER_REVIEW"


def test_update_response_action_returns_404_for_missing_incident(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)

    response = client.patch(
        f"/incidents/{uuid4()}/response-actions/{uuid4()}/status",
        json={"status": "UNDER_REVIEW"},
    )

    assert response.status_code == 404


def test_update_response_action_returns_404_for_missing_action(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)
    incident, _ = create_test_incident_and_alert()

    response = client.patch(
        f"/incidents/{incident.incident_id}/response-actions/"
        f"{uuid4()}/status",
        json={"status": "UNDER_REVIEW"},
    )

    assert response.status_code == 404


def test_update_response_action_rejects_invalid_status(monkeypatch):
    redirect_to_test_database(monkeypatch)
    incident, alert = create_test_incident_and_alert()
    action_id = create_test_response_action(incident, alert)

    response = client.patch(
        f"/incidents/{incident.incident_id}/response-actions/"
        f"{action_id}/status",
        json={"status": "INVALID_STATUS"},
    )

    assert response.status_code == 422

def test_update_response_action_rejects_missing_status(monkeypatch):
    redirect_to_test_database(monkeypatch)
    incident, alert = create_test_incident_and_alert()
    action_id = create_test_response_action(incident, alert)

    response = client.patch(
        f"/incidents/{incident.incident_id}/response-actions/"
        f"{action_id}/status",
        json={},
    )

    assert response.status_code == 422, response.text


def test_update_response_action_rejects_non_object_body(monkeypatch):
    redirect_to_test_database(monkeypatch)
    incident, alert = create_test_incident_and_alert()
    action_id = create_test_response_action(incident, alert)

    response = client.patch(
        f"/incidents/{incident.incident_id}/response-actions/"
        f"{action_id}/status",
        json=["UNDER_REVIEW"],
    )

    assert response.status_code == 422, response.text
