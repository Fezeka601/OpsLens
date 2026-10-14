from opslens.detection.rules.privilege_abuse_rule import PrivilegeAbuseRule
from opslens.models.security_event import SecurityEvent


def make_event(
    event_type="PRIVILEGE_VIOLATION",
    user_id="U102",
    user_role="USER",
    required_role="ADMIN",
    action="DELETE_USER",
    resource="/admin/users",
    ip_address="192.168.1.20",
    event_id="E1",
):
    metadata = {}

    if user_role is not None:
        metadata["user_role"] = user_role

    if required_role is not None:
        metadata["required_role"] = required_role

    if action is not None:
        metadata["action"] = action

    if resource is not None:
        metadata["resource"] = resource

    return SecurityEvent(
        service="authorization-service",
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        event_id=event_id,
        metadata=metadata,
    )


def test_detects_privilege_violation():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([make_event()])

    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.rule == "PRIVILEGE_ABUSE_DETECTION"
    assert alert.severity == "HIGH"
    assert alert.user_id == "U102"
    assert alert.event_ids == ["E1"]
    assert alert.metadata["user_role"] == "USER"
    assert alert.metadata["required_role"] == "ADMIN"
    assert alert.metadata["action"] == "DELETE_USER"
    assert alert.metadata["resource"] == "/admin/users"
    assert alert.metadata["ip_address"] == "192.168.1.20"
    assert alert.metadata["privilege_violation"] is True


def test_does_not_alert_when_roles_match():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([
        make_event(user_role="ADMIN", required_role="ADMIN")
    ])

    assert alerts == []


def test_ignores_unrelated_event_types():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([
        make_event(event_type="LOGIN_FAILED"),
        make_event(event_type="PAYMENT_SUCCESS"),
    ])

    assert alerts == []


def test_ignores_events_without_user_id():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([
        make_event(user_id=None)
    ])

    assert alerts == []


def test_ignores_missing_user_role():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([
        make_event(user_role=None)
    ])

    assert alerts == []


def test_ignores_missing_required_role():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([
        make_event(required_role=None)
    ])

    assert alerts == []


def test_detects_multiple_independent_violations():
    rule = PrivilegeAbuseRule()

    events = [
        make_event(event_id="E1", user_id="U102"),
        make_event(
            event_id="E2",
            user_id="U103",
            action="UPDATE_SETTINGS",
            resource="/admin/settings",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert [alert.event_ids for alert in alerts] == [["E1"], ["E2"]]
    assert {alert.user_id for alert in alerts} == {"U102", "U103"}


def test_handles_missing_optional_action_and_resource():
    rule = PrivilegeAbuseRule()

    alerts = rule.evaluate([
        make_event(action=None, resource=None)
    ])

    assert len(alerts) == 1
    assert alerts[0].metadata["action"] is None
    assert alerts[0].metadata["resource"] is None


def test_ignores_empty_role_values():
    rule = PrivilegeAbuseRule()

    events = [
        make_event(user_role=""),
        make_event(required_role=""),
    ]

    assert rule.evaluate(events) == []


def test_returns_empty_list_when_no_events_exist():
    rule = PrivilegeAbuseRule()

    assert rule.evaluate([]) == []
