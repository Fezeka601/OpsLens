import uuid

from psycopg.types.json import Jsonb

from opslens.database.connection import get_connection


class InvestigationRepository:

    def save(self, investigation: dict) -> str:
        investigation_id = str(uuid.uuid4())
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO investigation_findings (
                        investigation_id,
                        incident_id,
                        investigated_at,
                        severity,
                        status,
                        user_id,
                        related_event_count,
                        timeline,
                        findings
                    )
                    VALUES (
                        %s,
                        %s,
                        NOW(),
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        investigation_id,
                        investigation["incident_id"],
                        investigation["severity"],
                        investigation["status"],
                        investigation["user_id"],
                        investigation["related_event_count"],
                        Jsonb(investigation["timeline"]),
                        Jsonb(investigation["findings"])
                    )
                )

            connection.commit()

        finally:
            connection.close()

        return investigation_id

    def get_by_incident_id(self, incident_id: str) -> list[dict]:
        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        investigation_id,
                        incident_id,
                        investigated_at,
                        severity,
                        status,
                        user_id,
                        related_event_count,
                        timeline,
                        findings
                    FROM investigation_findings
                    WHERE incident_id = %s
                    ORDER BY investigated_at DESC
                    """,
                    (incident_id,)
                )

                rows = cursor.fetchall()

                return [
                    {
                        "investigation_id": str(row[0]),
                        "incident_id": str(row[1]),
                        "investigated_at": (
                            row[2].isoformat() if row[2] else None
                        ),
                        "severity": row[3],
                        "status": row[4],
                        "user_id": row[5],
                        "related_event_count": row[6],
                        "timeline": row[7],
                        "findings": row[8]
                    }
                    for row in rows
                ]

        finally:
            connection.close()