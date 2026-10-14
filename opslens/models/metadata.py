from opslens.models.security_alert import SecurityAlert
from opslens.detection.anomaly_detector import DetectionEngine
from opslens.detection.rules.brute_force_rule import BruteForceRule
from opslens.detection.rules.payment_fraud_rule import PaymentFraudRule


alert = SecurityAlert(
    rule="BRUTE_FORCE_DETECTION",
    severity="HIGH",
    user_id="U102",
    message="Multiple failed login attempts detected.",
    metadata={
        "failed_attempts": 3,
        "source_ips": [
            "192.168.1.20",
            "192.168.1.21"
        ]
    }
)

print(alert)
print()
print(alert.to_dict())