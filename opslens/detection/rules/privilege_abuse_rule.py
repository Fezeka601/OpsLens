from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class PrivilegeAbuseRule:

    name = "PRIVILEGE_ABUSE_DETECTION"
    severity = "HIGH"

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        for event in events:

            if event.event_type != "PRIVILEGE_VIOLATION":
                continue

            if not event.user_id:
                continue

            user_role = event.metadata.get("user_role")
            required_role = event.metadata.get("required_role")
            action = event.metadata.get("action")
            resource = event.metadata.get("resource")

            if not user_role or not required_role:
                continue

            if user_role == required_role:
                continue

            alert = SecurityAlert(
                rule=self.name,
                severity=self.severity,
                user_id=event.user_id,
                event_ids=[event.event_id],
                message=(
                    f"Privilege abuse detected for user "
                    f"{event.user_id}: role '{user_role}' "
                    f"attempted action '{action}' on "
                    f"resource '{resource}', which requires "
                    f"role '{required_role}'."
                ),
                metadata={
                    "user_role": user_role,
                    "required_role": required_role,
                    "action": action,
                    "resource": resource,
                    "ip_address": event.ip_address,
                    "privilege_violation": True
                }
            )

            alerts.append(alert)

        return alerts