from opslens.database.connection import get_connection
from opslens.database.test_connection import get_test_connection
from opslens.database import schema, incident_repository
from opslens.database.schema import create_tables
from opslens.database.incident_repository import IncidentRepository
from opslens.models.security_incident import SecurityIncident


def test_save_security_incident(monkeypatch):
    # Redirect database operations to the test database.
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

    create_tables()

    alert_id = "e3697cb2-c9bf-4eb9-a37f-b8821458db34"
    event_id = "19355f65-54ed-4f40-af0c-638ee7462f7b"

    incident = SecurityIncident(
        severity="HIGH",
        status="OPEN",
        title="Suspicious payment activity",
        description=(
            "Repeated payment failures followed by "
            "successful payment activity."
        ),
        user_id="U102",
        alert_ids=[alert_id],
        event_ids=[event_id],
        metadata={
            "source": "PAYMENT_FRAUD_DETECTION"
        },
    )

    repository = IncidentRepository()
    repository.save(incident)

    # Verify the incident in the test database.
    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    incident_id,
                    severity,
                    status,
                    title,
                    user_id,
                    alert_ids,
                    event_ids,
                    description,
                    metadata
                FROM security_incidents
                WHERE incident_id = %s
                """,
                (incident.incident_id,),
            )

            row = cursor.fetchone()

        assert row is not None
        assert str(row[0]) == incident.incident_id
        assert row[1] == "HIGH"
        assert row[2] == "OPEN"
        assert row[3] == "Suspicious payment activity"
        assert row[4] == "U102"
        assert str(row[5][0]) == alert_id
        assert str(row[6][0]) == event_id
        assert row[7] == (
            "Repeated payment failures followed by "
            "successful payment activity."
        )
        assert row[8]["source"] == "PAYMENT_FRAUD_DETECTION"

    finally:
        connection.close()
