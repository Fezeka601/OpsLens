from opslens.models.security_event import SecurityEvent
from opslens.models.security_alert import SecurityAlert


class DetectionEngine:

    def __init__(self, rules: list):
        self.rules = rules

    def detect(
        self,
        events: list[SecurityEvent]
    ) -> list[SecurityAlert]:

        alerts = []

        for rule in self.rules:
            rule_alerts = rule.evaluate(events)

            if rule_alerts is None:
                raise TypeError(
                    f"{rule.__class__.__name__}.evaluate() "
                    "returned None; expected a list of SecurityAlert objects."
                )

            if not isinstance(rule_alerts, list):
                raise TypeError(
                    f"{rule.__class__.__name__}.evaluate() "
                    f"returned {type(rule_alerts).__name__}; "
                    "expected a list of SecurityAlert objects."
                )

            alerts.extend(rule_alerts)

        return alerts
