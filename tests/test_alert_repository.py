from opslens.database.connection import get_connection
from opslens.database.test_connection import get_test_connection
from opslens.database import schema, alert_repository
from opslens.database.schema import create_tables
from opslens.database.alert_repository import AlertRepository
from opslens.models.security_alert import SecurityAlert


def test_save_security_alert(monkeypatch):
    # Redirect schema and repository operations to the test database.
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

    create_tables()

    alert = SecurityAlert(
        rule="PAYMENT_FRAUD_DETECTION",
        severity="HIGH",
        message="Suspicious payment activity detected.",
        user_id="U102",
        event_ids=[
            "19355f65-54ed-4f40-af0c-638ee7462f7b"
        ],
        metadata={
            "failed_payments": 2,
            "successful_payments": 5,
            "currency": "ZAR",
        },
    )

    repository = AlertRepository()
    repository.save(alert)

    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    alert_id,
                    rule,
                    severity,
                    user_id,
                    event_ids,
                    message,
                    metadata
                FROM security_alerts
                WHERE alert_id = %s
                """,
                (alert.alert_id,),
            )

            row = cursor.fetchone()

        assert row is not None
        assert str(row[0]) == str(alert.alert_id)
        assert row[1] == "PAYMENT_FRAUD_DETECTION"
        assert row[2] == "HIGH"
        assert row[3] == "U102"
        assert str(row[4][0]) == (
            "19355f65-54ed-4f40-af0c-638ee7462f7b"
        )
        assert row[5] == "Suspicious payment activity detected."
        assert row[6] == {
            "failed_payments": 2,
            "successful_payments": 5,
            "currency": "ZAR",
        }

    finally:
        connection.close()
