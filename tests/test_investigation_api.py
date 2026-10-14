import uuid

from fastapi.testclient import TestClient
import uuid
from opslens.database.connection import get_connection
from fastapi.testclient import TestClient

from opslens.api.app import app
from opslens.models.security_event import SecurityEvent
from opslens.models.security_incident import SecurityIncident

from opslens.database.test_connection import get_test_connection
from opslens.database import (
    schema,
    event_repository,
    incident_repository,
    investigation_repository,
)
from opslens.database.schema import create_tables
from opslens.database.event_repository import EventRepository
from opslens.database.incident_repository import IncidentRepository


client = TestClient(app)


def redirect_to_test_database(monkeypatch):
    """Redirect database operations to opslens_test."""
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
        incident_repository,
        get_connection.__name__,
        get_test_connection,
    )
    monkeypatch.setattr(
        investigation_repository,
        get_connection.__name__,
        get_test_connection,
    )

    create_tables()



def create_test_incident(event_ids=None):
    """Create and save a uniquely identified test incident."""
    incident = SecurityIncident(
        severity="HIGH",
        status="INVESTIGATING",
        title="Test suspicious payment activity",
        description="Test incident for investigation API coverage.",
        user_id=f"U-{uuid.uuid4().hex[:8]}",
        event_ids=event_ids or [],
    )

    IncidentRepository().save(incident)
    return incident


def test_get_investigations_returns_empty_list_for_new_incident(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)
    incident = create_test_incident()

    response = client.get(
        f"/incidents/{incident.incident_id}/investigation"
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["incident_id"] == incident.incident_id
    assert data["investigation_count"] == 0
    assert data["investigations"] == []


def test_get_investigations_returns_404_for_missing_incident(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)
    missing_id = str(uuid.uuid4())

    response = client.get(
        f"/incidents/{missing_id}/investigation"
    )

    assert response.status_code == 404


def test_post_investigation_returns_404_for_missing_incident(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)
    missing_id = str(uuid.uuid4())

    response = client.post(
        f"/incidents/{missing_id}/investigation"
    )

    assert response.status_code == 404


def test_post_investigation_returns_422_when_no_events_are_stored(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)

    # The incident references an event that does not exist.
    incident = create_test_incident(
        event_ids=[str(uuid.uuid4())]
    )

    response = client.post(
        f"/incidents/{incident.incident_id}/investigation"
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "No stored events were found for this incident"
    )


def test_post_investigation_saves_result_and_allows_retrieval(
    monkeypatch,
):
    redirect_to_test_database(monkeypatch)

    event = SecurityEvent(
        service="payment-service",
        event_type="PAYMENT_FAILED",
        user_id=f"U-{uuid.uuid4().hex[:8]}",
        metadata={"reason": "test failure"},
    )

    EventRepository().save(event)

    incident = create_test_incident(
        event_ids=[event.event_id]
    )

    # Replace the investigator dependency for this test only.
    # The API route and database repositories remain real.
    class FakeInvestigator:
        def investigate(self, incident_model, events):
            assert (
                incident_model.incident_id
                == incident.incident_id
            )
            assert len(events) == 1

            return {
                "incident_id": incident.incident_id,
                "severity": "HIGH",
                "status": "INVESTIGATED",
                "user_id": incident.user_id,
                "related_event_count": len(events),
                "timeline": [
                    {
                        "event_id": event.event_id,
                        "event_type": "PAYMENT_FAILED",
                    }
                ],
                "findings": [
                    "Test investigation finding"
                ],
            }

    monkeypatch.setattr(
        "opslens.api.app.incident_investigator",
        FakeInvestigator(),
    )

    post_response = client.post(
        f"/incidents/{incident.incident_id}/investigation"
    )

    assert post_response.status_code == 200, post_response.text

    post_data = post_response.json()

    assert post_data["investigation_id"]
    assert post_data["incident_id"] == incident.incident_id
    assert post_data["related_event_count"] == 1
    assert post_data["findings"] == [
        "Test investigation finding"
    ]

    # Retrieve the persisted investigation through the API.
    get_response = client.get(
        f"/incidents/{incident.incident_id}/investigation"
    )

    assert get_response.status_code == 200, get_response.text

    get_data = get_response.json()

    assert get_data["incident_id"] == incident.incident_id
    assert get_data["investigation_count"] == 1
    assert len(get_data["investigations"]) == 1

    saved_investigation = get_data["investigations"][0]

    assert (
        saved_investigation["investigation_id"]
        == post_data["investigation_id"]
    )
    assert saved_investigation["related_event_count"] == 1
    assert saved_investigation["findings"] == [
        "Test investigation finding"
    ]
