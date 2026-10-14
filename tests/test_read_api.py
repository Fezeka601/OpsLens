from fastapi.testclient import TestClient
from opslens.database.connection import get_connection
from opslens.api.app import app
from opslens.database.test_connection import get_test_connection
from opslens.database import (
    schema,
    event_repository,
    alert_repository,
    incident_repository,
)
from opslens.database.schema import create_tables
from opslens.models.security_incident import SecurityIncident
import uuid

client = TestClient(app)


def redirect_to_test_database(monkeypatch):
    # Redirect database operations to the test database.
    monkeypatch.setattr(
        schema, get_connection.__name__, get_test_connection
    )
    monkeypatch.setattr(
        event_repository, get_connection.__name__, get_test_connection
    )
    monkeypatch.setattr(
        alert_repository, get_connection.__name__, get_test_connection
    )
    monkeypatch.setattr(
        incident_repository, get_connection.__name__, get_test_connection
    )

    create_tables()


def test_get_events_returns_a_list(monkeypatch):
    redirect_to_test_database(monkeypatch)

    response = client.get("/events")

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


def test_get_alerts_returns_a_list(monkeypatch):
    redirect_to_test_database(monkeypatch)

    response = client.get("/alerts")

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


def test_get_incidents_returns_a_list(monkeypatch):
    redirect_to_test_database(monkeypatch)

    response = client.get("/incidents")

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


def test_get_endpoints_reject_invalid_limits(monkeypatch):
    redirect_to_test_database(monkeypatch)

    for endpoint in ("/events", "/alerts", "/incidents"):
        response_zero = client.get(endpoint, params={"limit": 0})
        assert response_zero.status_code == 422, (
            f"{endpoint} accepted limit=0"
        )

        response_excessive = client.get(
            endpoint,
            params={"limit": 501},
        )
        assert response_excessive.status_code == 422, (
            f"{endpoint} accepted limit=501"
        )


def test_get_events_accepts_valid_limit(monkeypatch):
    redirect_to_test_database(monkeypatch)

    response = client.get("/events", params={"limit": 1})

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)
    assert len(response.json()) <= 1

def test_get_incident_returns_404_for_missing_incident(monkeypatch):
    redirect_to_test_database(monkeypatch)

    missing_incident_id = str(uuid.uuid4())
    response = client.get(f"/incidents/{missing_incident_id}")

    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "Incident not found"


def test_get_incident_returns_saved_incident(monkeypatch):
    redirect_to_test_database(monkeypatch)

    incident = SecurityIncident(
        severity="HIGH",
        status="OPEN",
        title="Suspicious payment activity",
        description=(
            "Repeated payment failures followed by suspicious activity."
        ),
        user_id="U102",
        alert_ids=[str(uuid.uuid4())],
        event_ids=[str(uuid.uuid4()), str(uuid.uuid4())],
        metadata={"source": "PAYMENT_FRAUD_DETECTION"},
    )

    incident_repository.IncidentRepository().save(incident)

    response = client.get(f"/incidents/{incident.incident_id}")

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["incident_id"] == incident.incident_id
    assert data["severity"] == "HIGH"
    assert data["status"] == "OPEN"
    assert data["title"] == "Suspicious payment activity"
    assert data["user_id"] == "U102"
    assert data["alert_ids"] == incident.alert_ids
    assert data["event_ids"] == incident.event_ids
    assert data["metadata"]["source"] == "PAYMENT_FRAUD_DETECTION"