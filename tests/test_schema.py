from opslens.database.test_connection import get_test_connection
from opslens.database import schema
from opslens.database.schema import create_tables
from opslens.database.connection import get_connection

def test_security_events_table_exists(monkeypatch):
    # Ensure schema operations use the test database.
    monkeypatch.setattr(
        schema,
        get_connection.__name__,
        get_test_connection,
    )

    create_tables()

    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name = 'security_events'
                );
            """)

            table_exists = cursor.fetchone()[0]

        assert table_exists is True

    finally:
        connection.close()
