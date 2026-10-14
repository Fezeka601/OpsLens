from fastapi.testclient import TestClient

from opslens.api.app import app


client = TestClient(app)


def test_health_endpoint_returns_200():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() is not None


def test_event_with_invalid_type_returns_422():
    payload = {
        "service": "payment-service",
        "event_type": "INVALID_EVENT_TYPE",
        "user_id": "U-API-TEST",
        "metadata": {},
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 422

def test_nonexistent_incident_returns_404():
    response = client.get(
        "/incidents/66b3ce20-0c0c-40f2-91fb-1da91e3b1f99"
    )

    assert response.status_code == 404