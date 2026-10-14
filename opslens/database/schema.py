from opslens.database.connection import get_connection


CREATE_SECURITY_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    service VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(100),
    transaction_id VARCHAR(100),
    ip_address VARCHAR(45),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
"""


CREATE_SECURITY_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id UUID PRIMARY KEY,
    detected_at TIMESTAMPTZ NOT NULL,
    rule VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_id VARCHAR(100),
    event_ids UUID[] NOT NULL DEFAULT '{}',
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
"""


CREATE_SECURITY_INCIDENTS_TABLE = """
CREATE TABLE IF NOT EXISTS security_incidents (
    incident_id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    user_id VARCHAR(100),
    alert_ids UUID[] NOT NULL DEFAULT '{}',
    event_ids UUID[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
"""


CREATE_INVESTIGATION_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS investigation_findings (
    investigation_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL
        REFERENCES security_incidents(incident_id),
    investigated_at TIMESTAMPTZ NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL,
    user_id VARCHAR(100),
    related_event_count INTEGER NOT NULL,
    timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb
);
"""


CREATE_INCIDENT_RESPONSE_ACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS incident_response_actions (
    response_action_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL
        REFERENCES security_incidents(incident_id),
    alert_id UUID NOT NULL
        REFERENCES security_alerts(alert_id),
    action VARCHAR(100) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'RECOMMENDED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


def create_tables():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_SECURITY_EVENTS_TABLE)
            cursor.execute(CREATE_SECURITY_ALERTS_TABLE)
            cursor.execute(CREATE_SECURITY_INCIDENTS_TABLE)
            cursor.execute(CREATE_INVESTIGATION_FINDINGS_TABLE)
            cursor.execute(CREATE_INCIDENT_RESPONSE_ACTIONS_TABLE)

        connection.commit()

    finally:
        connection.close()
