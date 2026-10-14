from opslens.database.connection import get_connection
from opslens.database.test_connection import get_test_connection
from opslens.database import schema, incident_repository, investigation_repository
from opslens.database.schema import create_tables
from opslens.database.incident_repository import IncidentRepository
from opslens.database.investigation_repository import InvestigationRepository
from opslens.models.security_incident import SecurityIncident


def test_save_investigation(monkeypatch):
    # Redirect all database operations to the test database.
    monkeypatch.setattr(
        schema,
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

    incident = SecurityIncident(
        severity="HIGH",
        status="INVESTIGATING",
        title="Suspicious payment activity",
        description=(
            "Repeated payment failures followed by "
            "successful payment activity."
        ),
        user_id="U102",
    )

    IncidentRepository().save(incident)

    investigation = {
        "incident_id": incident.incident_id,
        "severity": incident.severity,
        "status": incident.status,
        "user_id": incident.user_id,
        "related_event_count": 2,
        "timeline": [
            {
                "event_type": "PAYMENT_FAILED",
                "user_id": "U102",
            },
            {
                "event_type": "PAYMENT_SUCCESS",
                "user_id": "U102",
            },
        ],
        "findings": [
            "Failed payment activity was detected.",
            "Successful payment activity followed the failure.",
        ],
    }

    repository = InvestigationRepository()
    investigation_id = repository.save(investigation)

    # Verify the saved investigation in the test database.
    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    investigation_id,
                    incident_id,
                    severity,
                    status,
                    user_id,
                    related_event_count,
                    timeline,
                    findings
                FROM investigation_findings
                WHERE investigation_id = %s
                """,
                (investigation_id,),
            )

            row = cursor.fetchone()

        assert row is not None
        assert str(row[0]) == investigation_id
        assert str(row[1]) == incident.incident_id
        assert row[2] == "HIGH"
        assert row[3] == "INVESTIGATING"
        assert row[4] == "U102"
        assert row[5] == 2
        assert len(row[6]) == 2
        assert len(row[7]) == 2

    finally:
        connection.close()