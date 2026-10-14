from opslens.models.security_event import SecurityEvent
from opslens.models.security_incident import SecurityIncident


class IncidentInvestigator:

    def investigate(
        self,
        incident: SecurityIncident,
        events: list[SecurityEvent]
    ) -> dict:

        related_events = [
            event
            for event in events
            if event.event_id in incident.event_ids
        ]

        related_events.sort(
            key=lambda event: event.timestamp
        )

        findings = []

        # =========================
        # EVENT CATEGORIES
        # =========================

        failed_payments = [
            event
            for event in related_events
            if event.event_type == "PAYMENT_FAILED"
        ]

        fraud_checks = [
            event
            for event in related_events
            if event.event_type == "FRAUD_CHECK"
        ]

        successful_payments = [
            event
            for event in related_events
            if event.event_type == "PAYMENT_SUCCESS"
        ]

        failed_logins = [
            event
            for event in related_events
            if event.event_type == "LOGIN_FAILED"
        ]

        access_denied_events = [
            event
            for event in related_events
            if event.event_type == "ACCESS_DENIED"
        ]

        privilege_violation_events = [
            event
            for event in related_events
            if event.event_type == "PRIVILEGE_VIOLATION"
        ]

        # =========================
        # LOGIN FINDINGS
        # =========================

        if failed_logins:

            findings.append(
                f"{len(failed_logins)} failed login attempt(s) "
                f"were detected."
            )

        # =========================
        # PAYMENT FINDINGS
        # =========================

        if failed_payments:

            findings.append(
                f"{len(failed_payments)} failed payment attempt(s) "
                f"were detected."
            )

        if fraud_checks:

            findings.append(
                f"{len(fraud_checks)} fraud check event(s) "
                f"were associated with the incident."
            )

        if successful_payments:

            findings.append(
                f"{len(successful_payments)} successful payment(s) "
                f"were detected."
            )

        if len(failed_payments) >= 2:

            findings.append(
                "Repeated payment failures indicate suspicious "
                "payment activity requiring further investigation."
            )

        if failed_payments and successful_payments:

            findings.append(
                "Successful payment activity occurred after "
                "failed payment attempts."
            )

        if fraud_checks and successful_payments:

            findings.append(
                "A successful payment occurred after a fraud "
                "check event."
            )

        # =========================
        # ACCESS CONTROL FINDINGS
        # =========================

        if access_denied_events:

            findings.append(
                f"{len(access_denied_events)} unauthorized access "
                f"attempt(s) were detected."
            )

            for event in access_denied_events:

                metadata = event.metadata

                resource = metadata.get(
                    "resource",
                    "unknown resource"
                )

                required_role = metadata.get(
                    "required_role",
                    "unknown role"
                )

                findings.append(
                    f"Access to {resource} was denied because "
                    f"{required_role} privileges were required."
                )

        # =========================
        # PRIVILEGE VIOLATION FINDINGS
        # =========================

        if privilege_violation_events:

            findings.append(
                f"{len(privilege_violation_events)} privilege "
                f"violation event(s) were detected."
            )

            for event in privilege_violation_events:

                metadata = event.metadata

                user_role = metadata.get(
                    "user_role",
                    "unknown role"
                )

                required_role = metadata.get(
                    "required_role",
                    "unknown role"
                )

                action = metadata.get(
                    "action",
                    "unknown action"
                )

                resource = metadata.get(
                    "resource",
                    "unknown resource"
                )

                findings.append(
                    f"User role '{user_role}' attempted "
                    f"'{action}' on {resource}, which requires "
                    f"'{required_role}' privileges."
                )

        # =========================
        # SOURCE IP FINDINGS
        # =========================

        suspicious_ips = {
            event.ip_address
            for event in related_events
            if event.ip_address
        }

        if (
            access_denied_events
            or privilege_violation_events
        ):

            for ip_address in suspicious_ips:

                findings.append(
                    f"Access-control activity originated from "
                    f"IP address {ip_address}."
                )

        # =========================
        # TIMELINE
        # =========================

        timeline = []

        for event in related_events:

            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "service": event.service,
                "event_type": event.event_type,
                "user_id": event.user_id,
                "transaction_id": event.transaction_id,
                "ip_address": event.ip_address
            })

        return {
            "incident_id": incident.incident_id,
            "severity": incident.severity,
            "status": incident.status,
            "user_id": incident.user_id,
            "related_event_count": len(related_events),
            "timeline": timeline,
            "findings": findings
        }