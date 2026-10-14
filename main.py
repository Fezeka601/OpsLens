from opslens.ingestion.event_ingestor import EventIngestor
from opslens.normalization.event_normalizer import EventNormalizer
from opslens.database.response_repository import ResponseRepository

from opslens.incidents.incident_manager import IncidentManager
from opslens.investigation.incident_investigator import IncidentInvestigator
from opslens.risk.risk_scorer import RiskScorer
from opslens.response.response_engine import IncidentResponseEngine
from opslens.incidents.incident_correlator import IncidentCorrelator
from opslens.database.schema import create_tables
from opslens.database.event_repository import EventRepository
from opslens.database.alert_repository import AlertRepository
from opslens.database.incident_repository import IncidentRepository
from opslens.database.investigation_repository import InvestigationRepository
from opslens.detection.anomaly_detector import DetectionEngine

from opslens.detection.rules.brute_force_rule import BruteForceRule
from opslens.detection.rules.payment_fraud_rule import PaymentFraudRule
from opslens.detection.rules.account_takeover_rule import AccountTakeoverRule
from opslens.detection.rules.unusual_payment_amount_rule import (
    UnusualPaymentAmountRule
)
from opslens.detection.rules.rapid_transactions_rule import (
    RapidTransactionsRule
)
from opslens.detection.rules.suspicious_login_rule import (
    SuspiciousLoginRule
)
from opslens.detection.rules.unauthorized_access_rule import (
    UnauthorizedAccessRule
)
from opslens.detection.rules.privilege_abuse_rule import (
    PrivilegeAbuseRule
)

def main():

    # =========================
    # INITIALIZE COMPONENTS
    # =========================

    ingestor = EventIngestor()
    normalizer = EventNormalizer()

    detection_engine = DetectionEngine(
        rules=[
            BruteForceRule(),
            PaymentFraudRule(),
            AccountTakeoverRule(),
            UnusualPaymentAmountRule(),
            RapidTransactionsRule(),
            SuspiciousLoginRule(),
            UnauthorizedAccessRule(),
            PrivilegeAbuseRule()

        ]
    )

    incident_manager = IncidentManager()
    investigator = IncidentInvestigator()
    risk_scorer = RiskScorer()
    response_engine = IncidentResponseEngine()
    correlator = IncidentCorrelator()

    create_tables()

    event_repository = EventRepository()
    alert_repository = AlertRepository()
    incident_repository = IncidentRepository()
    investigation_repository = InvestigationRepository()
    response_repository = ResponseRepository()


    # =========================
    # RAW EVENTS
    # =========================

    raw_events = [
        {
            "service": "auth_service",
            "event_type": "LOGIN_SUCCESS",
            "user_id": "U102",
            "ip_address": "192.168.1.20"
        },

        {
            "service": "auth_service",
            "event_type": "LOGIN_SUCCESS",
            "user_id": "U102",
            "ip_address": "192.168.1.20"
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_FAILED",
            "user_id": "U102",
            "transaction_id": "TX9001",
            "ip_address": "192.168.1.20",
            "metadata": {
                "amount": 15000,
                "currency": "ZAR",
                "failure_reason": "INSUFFICIENT_FUNDS"
            }
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_FAILED",
            "user_id": "U102",
            "transaction_id": "TX9002",
            "ip_address": "192.168.1.20",
            "metadata": {
                "amount": 15000,
                "currency": "ZAR",
                "failure_reason": "DECLINED"
            }
        },

        {
            "service": "fraud_service",
            "event_type": "FRAUD_CHECK",
            "user_id": "U102",
            "transaction_id": "TX9002",
            "ip_address": "192.168.1.20"
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_SUCCESS",
            "user_id": "U102",
            "transaction_id": "TX9003",
            "ip_address": "192.168.1.21",
            "metadata": {
                "amount": 75000,
                "currency": "ZAR"
            }
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_SUCCESS",
            "user_id": "U102",
            "transaction_id": "TX9004",
            "ip_address": "192.168.1.21",
            "metadata": {
                "amount": 5000,
                "currency": "ZAR"
            }
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_SUCCESS",
            "user_id": "U102",
            "transaction_id": "TX9005",
            "ip_address": "192.168.1.21",
            "metadata": {
                "amount": 4500,
                "currency": "ZAR"
            }
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_SUCCESS",
            "user_id": "U102",
            "transaction_id": "TX9006",
            "ip_address": "192.168.1.21",
            "metadata": {
                "amount": 6000,
                "currency": "ZAR"
            }
        },

        {
            "service": "payment_service",
            "event_type": "PAYMENT_SUCCESS",
            "user_id": "U102",
            "transaction_id": "TX9007",
            "ip_address": "192.168.1.21",
            "metadata": {
                "amount": 5500,
                "currency": "ZAR"
            }
        },

        {
            "service": "api_gateway",
            "event_type": "ACCESS_DENIED",
            "user_id": "U102",
            "ip_address": "192.168.1.21",
            "metadata": {
                "resource": "/admin/users",
                "required_role": "ADMIN",
                "reason": "INSUFFICIENT_PRIVILEGES"
            }
        },

        {
            "service": "api_gateway",
            "event_type": "PRIVILEGE_VIOLATION",
            "user_id": "U102",
            "ip_address": "192.168.1.21",
            "metadata": {
                "user_role": "USER",
                "required_role": "ADMIN",
                "action": "DELETE_USER",
                "resource": "/admin/users"
            }
        }
    ]

    # =========================
    # INGESTION + NORMALIZATION
    # =========================

    events = []

    for raw_event in raw_events:
        event = ingestor.ingest(raw_event)
        event = normalizer.normalize(event)

        events.append(event)
        event_repository.save(event)

    print("\n=== INGESTION + NORMALIZATION ===")
    print(f"Events processed: {len(events)}")

    # =========================
    # DETECTION
    # =========================

    alerts = detection_engine.detect(events)

    for alert in alerts:
        alert_repository.save(alert)

    print("\n=== DETECTION ENGINE ===")

    if not alerts:
        print("No security alerts detected.")

    else:
        print(f"Alerts detected: {len(alerts)}")

        for alert in alerts:
            print("\n🚨 SECURITY ALERT")
            print(f"Alert ID: {alert.alert_id}")
            print(f"Rule: {alert.rule}")
            print(f"Severity: {alert.severity}")
            print(f"User: {alert.user_id}")
            print(f"Message: {alert.message}")
            print(f"Related events: {len(alert.event_ids)}")
            print(f"Metadata: {alert.metadata}")

    # =========================
    # INCIDENT CORRELATION
    # =========================

    incident_groups = correlator.correlate(alerts)

    print("\n=== INCIDENT CORRELATION ===")
    print(f"Correlated incident groups: {len(incident_groups)}")

    for index, group in enumerate(incident_groups, start=1):

        print(f"\nIncident Group {index}")
        print(f"Alerts: {len(group)}")

        for alert in group:
            print(
                f"- {alert.rule} | "
                f"Alert ID: {alert.alert_id}"
            )

    # =========================
    # INCIDENT MANAGEMENT
    # =========================

    incidents = incident_manager.create_incidents(
        incident_groups
    )
    for incident in incidents:
        incident_repository.save(incident)

    print("\n=== INCIDENT MANAGEMENT ===")

    if not incidents:
        print("No security incidents created.")

    else:
        print(f"Incidents created: {len(incidents)}")

        for incident in incidents:
            print("\n🚨 SECURITY INCIDENT")
            print(f"Incident ID: {incident.incident_id}")
            print(f"Title: {incident.title}")
            print(f"Severity: {incident.severity}")
            print(f"Status: {incident.status}")
            print(f"User: {incident.user_id}")
            print(f"Description: {incident.description}")
            print(f"Related alerts: {len(incident.alert_ids)}")
            print(f"Related events: {len(incident.event_ids)}")

    # =========================
    # RISK SCORING
    # =========================

    print("\n=== RISK SCORING ===")

    risk_scores = {}

    for alert in alerts:

        risk = risk_scorer.calculate(alert)

        risk_scores[alert.alert_id] = risk

        print("\n⚠️ RISK ASSESSMENT")
        print(f"Alert: {alert.alert_id}")
        print(f"Risk Score: {risk['score']}/100")
        print(f"Risk Level: {risk['risk_level']}")

        print("Reasons:")

        for reason in risk["reasons"]:
            print(f"- {reason}")

    # =========================
    # INVESTIGATION + RESPONSE
    # =========================

    print("\n=== INVESTIGATION + RESPONSE ===")

    alerts_by_id = {
        alert.alert_id: alert
        for alert in alerts
    }

    for index, incident in enumerate(incidents, start=1):

        print("\n" + "-" * 40)
        print(f"PROCESSING INCIDENT {index}")
        print("-" * 40)

        # =========================
        # START INVESTIGATION
        # =========================

        incident_manager.start_investigation(incident)

        incident_repository.update_status(
            incident.incident_id,
            incident.status
        )

        investigation = investigator.investigate(
            incident,
            events
        )

        investigation_repository.save(investigation)

        print("\n🔎 INCIDENT INVESTIGATION")
        print(f"Incident ID: {investigation['incident_id']}")
        print(f"Severity: {investigation['severity']}")
        print(f"Status: {investigation['status']}")
        print(f"User: {investigation['user_id']}")
        print(
            f"Related events: "
            f"{investigation['related_event_count']}"
        )

        # =========================
        # TIMELINE
        # =========================

        print("\nTimeline:")

        for event in investigation["timeline"]:
            print(
                f"{event['timestamp']} | "
                f"{event['service']} | "
                f"{event['event_type']} | "
                f"Transaction: {event['transaction_id']} | "
                f"IP: {event['ip_address']}"
            )

        # =========================
        # FINDINGS
        # =========================

        print("\nFindings:")

        if investigation["findings"]:

            for finding in investigation["findings"]:
                print(f"- {finding}")

        else:
            print("- No findings identified.")

        # =========================
        # FIND ALERTS FOR INCIDENT
        # =========================

        incident_alerts = [
            alerts_by_id[alert_id]
            for alert_id in incident.alert_ids
            if alert_id in alerts_by_id
        ]

        # =========================
        # INCIDENT RESPONSE
        # =========================

        print("\n🛡️ INCIDENT RESPONSE")

        for alert in incident_alerts:

            response_actions = response_engine.generate_actions(
                incident,
                alert
            )

            if response_actions:

                for action in response_actions:
                    response_action_id = response_repository.save_action(
                        incident_id=incident.incident_id,
                        alert_id=alert.alert_id,
                        action=action
                    )

                    print(f"Response Action ID: {response_action_id}")
                    print(f"Action: {action['action']}")
                    print(f"Priority: {action['priority']}")
                    print(f"Reason: {action['reason']}")
                    print("Status: RECOMMENDED")
                    print()
            else:
                print(
                    "No automated response recommendations."
                )

        # =========================
        # INCIDENT LIFECYCLE
        # =========================

        print("=== INCIDENT LIFECYCLE ===")

        print(
            f"Current status: "
            f"{incident.status}"
        )

        incident_manager.contain_incident(incident)

        incident_repository.update_status(
            incident.incident_id,
            incident.status
        )

        print(
            f"Incident contained: "
            f"{incident.status}"
        )

        incident_manager.resolve_incident(incident)

        incident_repository.update_status(
            incident.incident_id,
            incident.status
        )

        print(
            f"Incident resolved: "
            f"{incident.status}"
        )

    # =========================
    # PIPELINE COMPLETE
    # =========================

    print("\n========================================")
    print("        OPSLENS PIPELINE COMPLETE")
    print("========================================")

    print(f"Events processed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Incidents created: {len(incidents)}")
    print(f"Risk assessments: {len(risk_scores)}")


if __name__ == "__main__":
    main()