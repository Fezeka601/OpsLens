from psycopg.types.json import Jsonb

from opslens.database.connection import get_connection
from opslens.models.security_alert import SecurityAlert


class AlertRepository:

    def save(self, alert: SecurityAlert) -> None:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO security_alerts (
                        alert_id,
                        detected_at,
                        rule,
                        severity,
                        user_id,
                        event_ids,
                        message,
                        metadata
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        alert.alert_id,
                        alert.detected_at,
                        alert.rule,
                        alert.severity,
                        alert.user_id,
                        alert.event_ids,
                        alert.message,
                        Jsonb(alert.metadata)
                    )
                )

            connection.commit()

        finally:
            connection.close()

    def get_all(self, limit: int = 100) -> list[dict]:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        alert_id,
                        detected_at,
                        rule,
                        severity,
                        user_id,
                        event_ids,
                        message,
                        metadata
                    FROM security_alerts
                    ORDER BY detected_at DESC
                    LIMIT %s
                    """,
                    (limit,)
                )

                rows = cursor.fetchall()

                return [
                    {
                        "alert_id": str(row[0]),
                        "detected_at": row[1].isoformat(),
                        "rule": row[2],
                        "severity": row[3],
                        "user_id": row[4],
                        "event_ids": [
                            str(event_id) for event_id in (row[5] or [])
                        ],
                        "message": row[6],
                        "metadata": row[7]
                    }
                    for row in rows
                ]

        finally:
            connection.close()