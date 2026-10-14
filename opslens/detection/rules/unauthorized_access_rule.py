from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class UnauthorizedAccessRule:

    name = "UNAUTHORIZED_ACCESS_DETECTION"
    severity = "HIGH"

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        events_by_user = {}

        for event in events:

            if event.event_type != "ACCESS_DENIED":
                continue

            if not event.user_id:
                continue

            if event.user_id not in events_by_user:
                events_by_user[event.user_id] = []

            events_by_user[event.user_id].append(event)

        for user_id, access_events in events_by_user.items():

            if not access_events:
                continue

            event_ids = [
                event.event_id
                for event in access_events
            ]

            resources = {
                event.metadata.get("resource")
                for event in access_events
                if event.metadata.get("resource")
            }

            source_ips = {
                event.ip_address
                for event in access_events
                if event.ip_address
            }

            alert = SecurityAlert(
                rule=self.name,
                severity=self.severity,
                user_id=user_id,
                event_ids=event_ids,
                message=(
                    f"Unauthorized access attempt detected "
                    f"for user {user_id}."
                ),
                metadata={
                    "denied_attempts": len(access_events),
                    "resources": list(resources),
                    "source_ips": list(source_ips)
                }
            )

            alerts.append(alert)

        return alerts