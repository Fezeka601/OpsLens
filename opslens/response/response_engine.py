from opslens.models.security_alert import SecurityAlert
from opslens.models.security_incident import SecurityIncident


class IncidentResponseEngine:

    def generate_actions(
        self,
        incident: SecurityIncident,
        alert: SecurityAlert
    ) -> list[dict]:

        actions = []

        rule = alert.rule

        if rule == "PAYMENT_FRAUD_DETECTION":
            actions.extend([
                {
                    "action": "FLAG_TRANSACTIONS",
                    "priority": "HIGH",
                    "reason": (
                        "Suspicious payment activity was detected."
                    )
                },
                {
                    "action": "LOCK_USER_ACCOUNT",
                    "priority": "HIGH",
                    "reason": (
                        "Repeated payment failures followed by "
                        "successful payment activity."
                    )
                },
                {
                    "action": "ESCALATE_TO_SECURITY",
                    "priority": "HIGH",
                    "reason": (
                        "Payment activity contains multiple "
                        "fraud indicators."
                    )
                }
            ])

        elif rule == "UNUSUAL_PAYMENT_AMOUNT":
            actions.extend([
                {
                    "action": "FLAG_TRANSACTION",
                    "priority": "HIGH",
                    "reason": (
                        "Payment amount exceeded the configured "
                        "risk threshold."
                    )
                },
                {
                    "action": "REVIEW_TRANSACTION",
                    "priority": "HIGH",
                    "reason": (
                        "Large transaction requires manual review."
                    )
                }
            ])

        elif rule == "RAPID_TRANSACTION_DETECTION":
            actions.extend([
                {
                    "action": "TEMPORARILY_RESTRICT_PAYMENTS",
                    "priority": "HIGH",
                    "reason": (
                        "Multiple successful transactions occurred "
                        "within a short time window."
                    )
                },
                {
                    "action": "FLAG_TRANSACTIONS",
                    "priority": "HIGH",
                    "reason": (
                        "Rapid transaction activity may indicate "
                        "automated or fraudulent behaviour."
                    )
                }
            ])

        elif rule == "UNAUTHORIZED_ACCESS_DETECTION":
            actions.extend([
                {
                    "action": "BLOCK_SOURCE_IP",
                    "priority": "HIGH",
                    "reason": (
                        "Unauthorized access was attempted."
                    )
                },
                {
                    "action": "REVIEW_USER_ACCESS",
                    "priority": "MEDIUM",
                    "reason": (
                        "User attempted to access a protected resource."
                    )
                }
            ])

        elif rule == "PRIVILEGE_ABUSE_DETECTION":
            actions.extend([
                {
                    "action": "BLOCK_PRIVILEGED_ACTION",
                    "priority": "CRITICAL",
                    "reason": (
                        "User attempted an action requiring "
                        "higher privileges."
                    )
                },
                {
                    "action": "REVIEW_USER_PERMISSIONS",
                    "priority": "HIGH",
                    "reason": (
                        "User permissions should be reviewed."
                    )
                },
                {
                    "action": "ESCALATE_TO_SECURITY",
                    "priority": "HIGH",
                    "reason": (
                        "Potential privilege abuse was detected."
                    )
                }
            ])

        elif rule == "ACCOUNT_TAKEOVER_DETECTION":
            actions.extend([
                {
                    "action": "LOCK_USER_ACCOUNT",
                    "priority": "CRITICAL",
                    "reason": (
                        "Account takeover indicators were detected."
                    )
                },
                {
                    "action": "BLOCK_SUSPICIOUS_IP",
                    "priority": "HIGH",
                    "reason": (
                        "Suspicious login activity originated "
                        "from multiple IP addresses."
                    )
                },
                {
                    "action": "ESCALATE_TO_SECURITY",
                    "priority": "CRITICAL",
                    "reason": (
                        "Potential account compromise requires "
                        "immediate investigation."
                    )
                }
            ])

        elif rule == "BRUTE_FORCE_DETECTION":
            actions.extend([
                {
                    "action": "LOCK_USER_ACCOUNT",
                    "priority": "HIGH",
                    "reason": (
                        "Multiple failed login attempts were detected."
                    )
                },
                {
                    "action": "BLOCK_SOURCE_IP",
                    "priority": "HIGH",
                    "reason": (
                        "Repeated authentication failures may "
                        "indicate a brute-force attack."
                    )
                }
            ])

        elif rule == "SUSPICIOUS_LOGIN_DETECTION":
            actions.extend([
                {
                    "action": "VERIFY_USER_IDENTITY",
                    "priority": "MEDIUM",
                    "reason": (
                        "A successful login was detected from "
                        "a new IP address."
                    )
                },
                {
                    "action": "REVIEW_LOGIN_ACTIVITY",
                    "priority": "MEDIUM",
                    "reason": (
                        "Login activity should be reviewed "
                        "for account compromise."
                    )
                }
            ])

        return actions