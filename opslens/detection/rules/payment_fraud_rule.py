from datetime import timedelta

from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class PaymentFraudRule:

    name = "PAYMENT_FRAUD_DETECTION"
    severity = "HIGH"

    def __init__(self, window_seconds: int = 300):
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.window_seconds = window_seconds

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []
        events_by_transaction = {}

        # Group events by both user and transaction.
        for event in events:

            if not event.user_id or not event.transaction_id:
                continue

            if event.event_type not in {
                "PAYMENT_FAILED",
                "PAYMENT_SUCCESS",
                "FRAUD_CHECK",
            }:
                continue

            key = (event.user_id, event.transaction_id)

            events_by_transaction.setdefault(key, []).append(event)

        window = timedelta(seconds=self.window_seconds)

        for (user_id, transaction_id), transaction_events in (
            events_by_transaction.items()
        ):

            transaction_events.sort(
                key=lambda event: event.timestamp
            )

            # Evaluate each successful payment against preceding
            # failures and fraud checks in the configured window.
            for success in transaction_events:

                if success.event_type != "PAYMENT_SUCCESS":
                    continue

                window_start = success.timestamp - window

                relevant_events = [
                    event
                    for event in transaction_events
                    if window_start <= event.timestamp <= success.timestamp
                ]

                failed_payments = [
                    event
                    for event in relevant_events
                    if event.event_type == "PAYMENT_FAILED"
                ]

                fraud_checks = [
                    event
                    for event in relevant_events
                    if event.event_type == "FRAUD_CHECK"
                ]

                if len(failed_payments) < 2 or not fraud_checks:
                    continue

                related_events = (
                    failed_payments
                    + fraud_checks
                    + [success]
                )

                # Keep the evidence chronological and avoid duplicate IDs.
                related_events.sort(
                    key=lambda event: event.timestamp
                )

                event_ids = list(dict.fromkeys(
                    event.event_id for event in related_events
                ))

                source_ips = sorted({
                    event.ip_address
                    for event in related_events
                    if event.ip_address
                })

                alert = SecurityAlert(
                    rule=self.name,
                    severity=self.severity,
                    user_id=user_id,
                    event_ids=event_ids,
                    message=(
                        f"User {user_id} had at least two failed payment "
                        f"attempts, a fraud check, and a subsequent "
                        f"successful payment for transaction "
                        f"{transaction_id} within "
                        f"{self.window_seconds} seconds."
                    ),
                    metadata={
                        "failed_payments": len(failed_payments),
                        "fraud_checks": len(fraud_checks),
                        "successful_payments": 1,
                        "source_ips": source_ips,
                        "transaction_id": transaction_id,
                        "window_seconds": self.window_seconds,
                    }
                )

                alerts.append(alert)

                # One alert per user/transaction for this evaluation.
                break

        return alerts