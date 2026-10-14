from opslens.models.security_alert import SecurityAlert


class IncidentCorrelator:
    """
    Groups related security alerts into incident groups.
    """

    PAYMENT_RULES = {
        "PAYMENT_FRAUD_DETECTION",
        "UNUSUAL_PAYMENT_AMOUNT",
        "RAPID_TRANSACTION_DETECTION"
    }

    ACCESS_RULES = {
        "UNAUTHORIZED_ACCESS_DETECTION",
        "PRIVILEGE_ABUSE_DETECTION"
    }

    def correlate(
        self,
        alerts: list[SecurityAlert]
    ) -> list[list[SecurityAlert]]:

        groups: list[list[SecurityAlert]] = []

        for alert in alerts:

            matched_group = None

            for group in groups:

                if self._is_related(alert, group):
                    matched_group = group
                    break

            if matched_group:
                matched_group.append(alert)

            else:
                groups.append([alert])

        return groups

    def _is_related(
        self,
        alert: SecurityAlert,
        group: list[SecurityAlert]
    ) -> bool:

        for existing_alert in group:

            if alert.user_id != existing_alert.user_id:
                continue

            if self._same_activity_type(
                alert,
                existing_alert
            ):
                return True

        return False

    def _same_activity_type(
        self,
        alert: SecurityAlert,
        existing_alert: SecurityAlert
    ) -> bool:

        alert_rule = alert.rule
        existing_rule = existing_alert.rule

        # Payment-related alerts belong together.
        if (
            alert_rule in self.PAYMENT_RULES
            and existing_rule in self.PAYMENT_RULES
        ):
            return True

        # Access and privilege-related alerts belong together.
        if (
            alert_rule in self.ACCESS_RULES
            and existing_rule in self.ACCESS_RULES
        ):
            return True

        return False