from psycopg.types.json import Jsonb

from opslens.database.connection import get_connection
from opslens.models.security_incident import SecurityIncident


class IncidentRepository:

    def save(self, incident: SecurityIncident) -> None:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO security_incidents (
                        incident_id,
                        created_at,
                        severity,
                        status,
                        title,
                        description,
                        user_id,
                        alert_ids,
                        event_ids,
                        metadata
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        incident.incident_id,
                        incident.created_at,
                        incident.severity,
                        incident.status,
                        incident.title,
                        incident.description,
                        incident.user_id,
                        incident.alert_ids,
                        incident.event_ids,
                        Jsonb(incident.metadata)
                    )
                )

            connection.commit()

        finally:
            connection.close()

    def update_status(self, incident_id: str, status: str) -> None:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE security_incidents
                    SET status = %s
                    WHERE incident_id = %s
                    """,
                    (status, incident_id)
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
                        incident_id,
                        created_at,
                        severity,
                        status,
                        title,
                        description,
                        user_id,
                        alert_ids,
                        event_ids,
                        metadata
                    FROM security_incidents
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,)
                )

                rows = cursor.fetchall()

                return [
                    {
                        "incident_id": str(row[0]),
                        "created_at": (
                            row[1].isoformat() if row[1] else None
                        ),
                        "severity": row[2],
                        "status": row[3],
                        "title": row[4],
                        "description": row[5],
                        "user_id": row[6],
                        "alert_ids": [
                            str(item) for item in (row[7] or [])
                        ],
                        "event_ids": [
                            str(item) for item in (row[8] or [])
                        ],
                        "metadata": row[9] or {}
                    }
                    for row in rows
                ]

        finally:
            connection.close()

    def get_by_id(self, incident_id: str) -> dict | None:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        incident_id,
                        created_at,
                        severity,
                        status,
                        title,
                        description,
                        user_id,
                        alert_ids,
                        event_ids,
                        metadata
                    FROM security_incidents
                    WHERE incident_id = %s
                    """,
                    (incident_id,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return {
                    "incident_id": str(row[0]),
                    "created_at": (
                        row[1].isoformat() if row[1] else None
                    ),
                    "severity": row[2],
                    "status": row[3],
                    "title": row[4],
                    "description": row[5],
                    "user_id": row[6],
                    "alert_ids": [
                        str(item) for item in (row[7] or [])
                    ],
                    "event_ids": [
                        str(item) for item in (row[8] or [])
                    ],
                    "metadata": row[9] or {}
                }

        finally:
            connection.close()

    def get_model_by_id(
        self,
        incident_id: str
    ) -> SecurityIncident | None:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        incident_id,
                        created_at,
                        severity,
                        status,
                        title,
                        description,
                        user_id,
                        alert_ids,
                        event_ids,
                        metadata
                    FROM security_incidents
                    WHERE incident_id = %s
                    """,
                    (incident_id,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return SecurityIncident(
                    incident_id=str(row[0]),
                    created_at=row[1],
                    severity=row[2],
                    status=row[3],
                    title=row[4],
                    description=row[5],
                    user_id=row[6],
                    alert_ids=[
                        str(item) for item in (row[7] or [])
                    ],
                    event_ids=[
                        str(item) for item in (row[8] or [])
                    ],
                    metadata=row[9] or {}
                )

        finally:
            connection.close()