from datetime import timedelta

from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class RapidTransactionsRule:

    name = "RAPID_TRANSACTION_DETECTION"
    severity = "HIGH"

    def __init__(
        self,
        transaction_limit: int = 5,
        time_window_seconds: int = 60
    ):
        self.transaction_limit = transaction_limit
        self.time_window = timedelta(
            seconds=time_window_seconds
        )

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        events_by_user = {}

        for event in events:

            if event.event_type != "PAYMENT_SUCCESS":
                continue

            if not event.user_id:
                continue

            if event.user_id not in events_by_user:
                events_by_user[event.user_id] = []

            events_by_user[event.user_id].append(event)

        for user_id, user_events in events_by_user.items():

            user_events.sort(
                key=lambda event: event.timestamp
            )

            for index in range(len(user_events)):

                start_event = user_events[index]

                window_events = [
                    event
                    for event in user_events[index:]
                    if event.timestamp - start_event.timestamp
                    <= self.time_window
                ]

                if len(window_events) >= self.transaction_limit:

                    event_ids = [
                        event.event_id
                        for event in window_events
                    ]

                    transaction_ids = [
                        event.transaction_id
                        for event in window_events
                        if event.transaction_id
                    ]

                    alert = SecurityAlert(
                        rule=self.name,
                        severity=self.severity,
                        user_id=user_id,
                        event_ids=event_ids,
                        message=(
                            f"User {user_id} made "
                            f"{len(window_events)} successful "
                            f"transactions within "
                            f"{self.time_window.seconds} seconds."
                        ),
                        metadata={
                            "transaction_count": len(window_events),
                            "transaction_limit": self.transaction_limit,
                            "time_window_seconds": (
                                self.time_window.seconds
                            ),
                            "transaction_ids": transaction_ids
                        }
                    )

                    alerts.append(alert)

                    break

        return alerts