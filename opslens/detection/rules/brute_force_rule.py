from datetime import timedelta

from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class BruteForceRule:

    name = "BRUTE_FORCE_DETECTION"
    severity = "HIGH"

    def __init__(
        self,
        threshold: int = 3,
        window_seconds: int = 300
    ):
        if threshold < 1:
            raise ValueError("threshold must be at least 1")

        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []
        failed_logins = {}

        # Group failed login events by user.
        for event in events:

            if event.event_type != "LOGIN_FAILED":
                continue

            if not event.user_id:
                continue

            failed_logins.setdefault(
                event.user_id, []
            ).append(event)

        window = timedelta(seconds=self.window_seconds)

        for user_id, user_events in failed_logins.items():

            # Sort chronologically before evaluating the window.
            user_events.sort(
                key=lambda event: event.timestamp
            )

            # Find the first group of threshold failures
            # occurring within the configured time window.
            for start_index, first_event in enumerate(user_events):

                window_end = (
                    first_event.timestamp + window
                )

                matching_events = [
                    event
                    for event in user_events[start_index:]
                    if event.timestamp <= window_end
                ]

                if len(matching_events) < self.threshold:
                    continue

                source_ips = sorted({
                    event.ip_address
                    for event in matching_events
                    if event.ip_address
                })

                event_ids = [
                    event.event_id
                    for event in matching_events
                ]

                alert = SecurityAlert(
                    rule=self.name,
                    severity=self.severity,
                    user_id=user_id,
                    event_ids=event_ids,
                    message=(
                        f"User {user_id} experienced "
                        f"{len(matching_events)} failed login "
                        f"attempts within "
                        f"{self.window_seconds} seconds."
                    ),
                    metadata={
                        "failed_attempts": len(matching_events),
                        "source_ips": source_ips,
                        "window_seconds": self.window_seconds
                    }
                )

                alerts.append(alert)
        return alerts