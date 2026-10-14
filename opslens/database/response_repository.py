import uuid

from opslens.database.connection import get_connection


class ResponseRepository:

    def save_action(
        self,
        incident_id: str,
        alert_id: str,
        action: dict
    ) -> str:
        response_action_id = str(uuid.uuid4())

        connection = get_connection()

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
                        incident_id,
                        alert_id,
                        action["action"],
                        action["priority"],
                        action["reason"],
                        "RECOMMENDED"
                    )
                )

            connection.commit()
            return response_action_id

        finally:
            connection.close()

    def get_by_incident_id(
        self,
        incident_id: str
    ) -> list[dict]:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        response_action_id,
                        incident_id,
                        alert_id,
                        action,
                        priority,
                        reason,
                        status,
                        created_at
                    FROM incident_response_actions
                    WHERE incident_id = %s
                    ORDER BY created_at DESC
                    """,
                    (incident_id,)
                )

                rows = cursor.fetchall()

                return [
                    {
                        "response_action_id": str(row[0]),
                        "incident_id": str(row[1]),
                        "alert_id": str(row[2]),
                        "action": row[3],
                        "priority": row[4],
                        "reason": row[5],
                        "status": row[6],
                        "created_at": (
                            row[7].isoformat()
                            if row[7]
                            else None
                        )
                    }
                    for row in rows
                ]

        finally:
            connection.close()

    def update_status(
        self,
        incident_id: str,
        response_action_id: str,
        status: str
    ) -> bool:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE incident_response_actions
                    SET status = %s
                    WHERE incident_id = %s
                      AND response_action_id = %s
                    """,
                    (
                        status,
                        incident_id,
                        response_action_id
                    )
                )

                updated = cursor.rowcount > 0

            connection.commit()
            return updated

        finally:
            connection.close()