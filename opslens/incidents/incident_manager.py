from opslens.models.security_alert import SecurityAlert
from opslens.models.security_incident import SecurityIncident


class IncidentManager:

    VALID_STATUSES = {
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED"
    }

    SEVERITY_LEVELS = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    def create_incidents(
        self,
        incident_groups: list[list[SecurityAlert]]
    ) -> list[SecurityIncident]:

        incidents = []

        for group in incident_groups:

            if not group:
                continue

            incident = SecurityIncident(
                severity=self._get_highest_severity(group),
                status="OPEN",
                title=self._build_title(group),
                description=self._build_description(group),
                user_id=group[0].user_id,
                alert_ids=[
                    alert.alert_id
                    for alert in group
                ],
                event_ids=self._collect_event_ids(group),
                metadata={
                    "detection_rules": [
                        alert.rule
                        for alert in group
                    ],
                    "alerts": [
                        {
                            "alert_id": alert.alert_id,
                            "rule": alert.rule,
                            "severity": alert.severity,
                            "metadata": alert.metadata
                        }
                        for alert in group
                    ]
                }
            )

            incidents.append(incident)

        return incidents

    def _get_highest_severity(
        self,
        alerts: list[SecurityAlert]
    ) -> str:

        return max(
            alerts,
            key=lambda alert: self.SEVERITY_LEVELS.get(
                alert.severity.upper(),
                0
            )
        ).severity

    def _collect_event_ids(
        self,
        alerts: list[SecurityAlert]
    ) -> list[str]:

        event_ids = []

        for alert in alerts:

            for event_id in alert.event_ids:

                if event_id not in event_ids:
                    event_ids.append(event_id)

        return event_ids

    def _build_title(
        self,
        alerts: list[SecurityAlert]
    ) -> str:

        rules = {
            alert.rule
            for alert in alerts
        }

        if "PAYMENT_FRAUD_DETECTION" in rules:
            return "Suspicious payment activity"

        if (
            "UNAUTHORIZED_ACCESS_DETECTION" in rules
            and "PRIVILEGE_ABUSE_DETECTION" in rules
        ):
            return "Unauthorized access and privilege abuse"

        if "PRIVILEGE_ABUSE_DETECTION" in rules:
            return "Potential privilege abuse"

        if "UNAUTHORIZED_ACCESS_DETECTION" in rules:
            return "Unauthorized access attempt"

        return "Security incident detected"

    def _build_description(
        self,
        alerts: list[SecurityAlert]
    ) -> str:

        messages = []

        for alert in alerts:

            if alert.message not in messages:
                messages.append(alert.message)

        return " ".join(messages)

    def update_status(
        self,
        incident: SecurityIncident,
        new_status: str
    ) -> SecurityIncident:

        new_status = new_status.upper()

        if new_status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid incident status: {new_status}"
            )

        incident.status = new_status

        return incident

    def start_investigation(
        self,
        incident: SecurityIncident
    ) -> SecurityIncident:

        return self.update_status(
            incident,
            "INVESTIGATING"
        )

    def contain_incident(
        self,
        incident: SecurityIncident
    ) -> SecurityIncident:

        return self.update_status(
            incident,
            "CONTAINED"
        )

    def resolve_incident(
        self,
        incident: SecurityIncident
    ) -> SecurityIncident:

        return self.update_status(
            incident,
            "RESOLVED"
        )