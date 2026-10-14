from opslens.models.security_alert import SecurityAlert


class RiskScorer:

    def calculate(self, alert: SecurityAlert) -> dict:
        score = 0
        reasons = []

        metadata = alert.metadata

        # =========================
        # SEVERITY
        # =========================

        if alert.severity == "CRITICAL":
            score += 30
            reasons.append("Critical severity alert")

        elif alert.severity == "HIGH":
            score += 20
            reasons.append("High severity alert")

        elif alert.severity == "MEDIUM":
            score += 10
            reasons.append("Medium severity alert")

        # =========================
        # PAYMENT RISK
        # =========================

        failed_payments = metadata.get(
            "failed_payments",
            0
        )

        if failed_payments >= 2:
            score += 20
            reasons.append(
                "Multiple failed payment attempts"
            )

        successful_payments = metadata.get(
            "successful_payments",
            0
        )

        if (
            failed_payments > 0
            and successful_payments > 0
        ):
            score += 20
            reasons.append(
                "Successful payment activity followed "
                "failed payment attempts"
            )

        fraud_checks = metadata.get(
            "fraud_checks",
            0
        )

        if fraud_checks > 0:
            score += 15
            reasons.append(
                "Fraud check associated with activity"
            )

        # =========================
        # LARGE PAYMENT RISK
        # =========================

        amount = metadata.get(
            "amount",
            0
        )

        threshold = metadata.get(
            "threshold",
            0
        )

        if amount > 0 and threshold > 0 and amount >= threshold:
            score += 30
            reasons.append(
                "Payment amount exceeded the configured risk threshold"
            )

        # =========================
        # RAPID TRANSACTION RISK
        # =========================

        transaction_count = metadata.get(
            "transaction_count",
            0
        )

        transaction_limit = metadata.get(
            "transaction_limit",
            0
        )

        if (
            transaction_count > 0
            and transaction_limit > 0
            and transaction_count >= transaction_limit
        ):
            score += 25
            reasons.append(
                "Transaction activity reached the configured limit "
                "within a short time window"
            )

        # =========================
        # UNAUTHORIZED ACCESS RISK
        # =========================

        denied_attempts = metadata.get(
            "denied_attempts",
            0
        )

        if denied_attempts >= 1:
            score += 25
            reasons.append(
                "Unauthorized access attempt detected"
            )

        # =========================
        # PRIVILEGE ABUSE RISK
        # =========================

        privilege_violation = metadata.get(
            "privilege_violation",
            False
        )

        if privilege_violation:
            score += 35
            reasons.append(
                "User attempted an action requiring higher privileges"
            )

        # =========================
        # NETWORK RISK
        # =========================

        source_ips = metadata.get(
            "source_ips",
            []
        )

        if len(source_ips) > 1:
            score += 15
            reasons.append(
                "Activity originated from multiple IP addresses"
            )

        # =========================
        # ACCOUNT TAKEOVER RISK
        # =========================

        account_takeover = metadata.get(
            "account_takeover_indicator",
            False
        )

        if account_takeover:
            score += 30
            reasons.append(
                "Account takeover indicators detected"
            )

        login_ip_count = metadata.get(
            "login_ip_count",
            0
        )

        if login_ip_count > 1:
            score += 20
            reasons.append(
                "Successful logins originated from multiple IP addresses"
            )

        payment_events = metadata.get(
            "payment_events",
            0
        )

        if account_takeover and payment_events > 0:
            score += 20
            reasons.append(
                "Payment activity followed suspicious login activity"
            )

        # =========================
        # FINAL SCORE
        # =========================

        score = min(score, 100)

        risk_level = self._get_risk_level(score)

        return {
            "score": score,
            "risk_level": risk_level,
            "reasons": reasons
        }

    def _get_risk_level(
        self,
        score: int
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"