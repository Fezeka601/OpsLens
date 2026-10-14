from psycopg.types.json import Jsonb

from opslens.database.connection import get_connection
from opslens.models.security_event import SecurityEvent


class EventRepository:

    def save(self, event: SecurityEvent) -> bool:
        """
        Save a security event.

        Returns:
            True if the event was inserted.
            False if an event with the same ID already exists.
        """
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO security_events (
                        event_id,
                        timestamp,
                        service,
                        event_type,
                        user_id,
                        transaction_id,
                        ip_address,
                        metadata
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING event_id
                    """,
                    (
                        event.event_id,
                        event.timestamp,
                        event.service,
                        event.event_type,
                        event.user_id,
                        event.transaction_id,
                        event.ip_address,
                        Jsonb(event.metadata),
                    ),
                )

                saved = cursor.fetchone() is not None

            connection.commit()
            return saved

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def get_all(self, limit: int = 100) -> list[dict]:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        event_id,
                        timestamp,
                        service,
                        event_type,
                        user_id,
                        transaction_id,
                        ip_address,
                        metadata
                    FROM security_events
                    ORDER BY timestamp DESC
                    LIMIT %s
                    """,
                    (limit,),
                )

                rows = cursor.fetchall()

                return [
                    {
                        "event_id": str(row[0]),
                        "timestamp": row[1].isoformat(),
                        "service": row[2],
                        "event_type": row[3],
                        "user_id": row[4],
                        "transaction_id": row[5],
                        "ip_address": row[6],
                        "metadata": row[7] or {},
                    }
                    for row in rows
                ]

        finally:
            connection.close()

    def get_by_ids(
        self,
        event_ids: list[str],
    ) -> list[SecurityEvent]:
        if not event_ids:
            return []

        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        event_id,
                        timestamp,
                        service,
                        event_type,
                        user_id,
                        transaction_id,
                        ip_address,
                        metadata
                    FROM security_events
                    WHERE event_id = ANY(%s)
                    """,
                    (event_ids,),
                )

                rows = cursor.fetchall()

                events = [
                    SecurityEvent(
                        event_id=str(row[0]),
                        timestamp=row[1],
                        service=row[2],
                        event_type=row[3],
                        user_id=row[4],
                        transaction_id=row[5],
                        ip_address=row[6],
                        metadata=row[7] or {},
                    )
                    for row in rows
                ]

                return events

        finally:
            connection.close()
