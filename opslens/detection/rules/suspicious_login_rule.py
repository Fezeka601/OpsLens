from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class SuspiciousLoginRule:

    name = "SUSPICIOUS_LOGIN_DETECTION"
    severity = "MEDIUM"

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        events_by_user = {}

        for event in events:

            if event.event_type != "LOGIN_SUCCESS":
                continue

            if not event.user_id:
                continue

            if event.user_id not in events_by_user:
                events_by_user[event.user_id] = []

            events_by_user[event.user_id].append(event)

        for user_id, login_events in events_by_user.items():

            if len(login_events) < 2:
                continue

            known_ips = set()

            for event in login_events:

                if not event.ip_address:
                    continue

                if event.ip_address not in known_ips:

                    if known_ips:

                        alert = SecurityAlert(
                            rule=self.name,
                            severity=self.severity,
                            user_id=user_id,
                            event_ids=[
                                event.event_id
                            ],
                            message=(
                                f"Suspicious login detected for "
                                f"user {user_id} from a new "
                                f"IP address: "
                                f"{event.ip_address}."
                            ),
                            metadata={
                                "new_ip_address": event.ip_address,
                                "known_ip_addresses": list(
                                    known_ips
                                ),
                                "login_anomaly": True
                            }
                        )

                        alerts.append(alert)

                known_ips.add(event.ip_address)

        return alerts