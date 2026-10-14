import math

from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class UnusualPaymentAmountRule:

    name = "UNUSUAL_PAYMENT_AMOUNT"
    severity = "HIGH"

    def __init__(self, threshold: float = 50000):
        self.threshold = threshold

    def evaluate(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        for event in events:

            if event.event_type != "PAYMENT_SUCCESS":
                continue

            amount = event.metadata.get("amount")

            # Ignore missing amounts and booleans.
            if amount is None or isinstance(amount, bool):
                continue

            # Safely convert numeric values and numeric strings.
            try:
                numeric_amount = float(amount)
            except (TypeError, ValueError, OverflowError):
                continue

            # Ignore NaN and infinite values.
            if not math.isfinite(numeric_amount):
                continue

            if numeric_amount < self.threshold:
                continue

            alert = SecurityAlert(
                rule=self.name,
                severity=self.severity,
                user_id=event.user_id,
                event_ids=[event.event_id],
                message=(
                    f"Unusually large payment detected for "
                    f"user {event.user_id}: "
                    f"{event.metadata.get('currency', '')} "
                    f"{amount}."
                ),
                metadata={
                    "amount": numeric_amount,
                    "currency": event.metadata.get("currency"),
                    "threshold": self.threshold,
                    "transaction_id": event.transaction_id,
                    "ip_address": event.ip_address
                }
            )

            alerts.append(alert)

        return alerts