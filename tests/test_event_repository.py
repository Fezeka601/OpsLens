from opslens.database.test_connection import get_test_connection
from opslens.database import schema, event_repository
from opslens.database.schema import create_tables
from opslens.database.event_repository import EventRepository
from opslens.models.security_event import SecurityEvent
from opslens.database.connection import get_connection

def test_save_security_event(monkeypatch):
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

    create_tables()

    event = SecurityEvent(
        service="payment-service",
        event_type="PAYMENT_SUCCESS",
        user_id="U102",
        transaction_id="TX9003",
        ip_address="192.168.1.21",
        metadata={
            "amount": 75000,
            "currency": "ZAR",
        },
    )

    repository = EventRepository()

    # First submission should insert the event.
    first_save = repository.save(event)
    assert first_save is True

    # Repeating the same event ID should not insert it again.
    second_save = repository.save(event)
    assert second_save is False

    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    event_id,
                    service,
                    event_type,
                    user_id,
                    transaction_id,
                    COUNT(*) OVER (PARTITION BY event_id) AS occurrences
                FROM security_events
                WHERE event_id = %s
                """,
                (event.event_id,),
            )

            row = cursor.fetchone()

        assert row is not None
        assert str(row[0]) == event.event_id
        assert row[1] == "payment-service"
        assert row[2] == "PAYMENT_SUCCESS"
        assert row[3] == "U102"
        assert row[4] == "TX9003"
        assert row[5] == 1

    finally:
        connection.close()
