from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class AccountTakeoverRule:

    name = "ACCOUNT_TAKEOVER_DETECTION"
    severity = "CRITICAL"

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        events_by_user = {}

        for event in events:

            if not event.user_id:
                continue

            if event.user_id not in events_by_user:
                events_by_user[event.user_id] = []

            events_by_user[event.user_id].append(event)

        for user_id, user_events in events_by_user.items():

            login_events = [
                event
                for event in user_events
                if event.event_type == "LOGIN_SUCCESS"
            ]

            if len(login_events) < 2:
                continue

            login_ips = {
                event.ip_address
                for event in login_events
                if event.ip_address
            }

            if len(login_ips) < 2:
                continue

            payment_events = [
                event
                for event in user_events
                if event.event_type in {
                    "PAYMENT_SUCCESS",
                    "PAYMENT_FAILED"
                }
            ]

            if not payment_events:
                continue

            event_ids = [
                event.event_id
                for event in user_events
            ]

            alert = SecurityAlert(
                rule=self.name,
                severity=self.severity,
                user_id=user_id,
                event_ids=event_ids,
                message=(
                    f"Possible account takeover detected for "
                    f"user {user_id}. Successful logins were "
                    f"observed from multiple IP addresses "
                    f"followed by payment activity."
                ),
                metadata={
                    "login_ip_count": len(login_ips),
                    "login_ips": list(login_ips),
                    "payment_events": len(payment_events),
                    "account_takeover_indicator": True
                }
            )

            alerts.append(alert)

        return alerts