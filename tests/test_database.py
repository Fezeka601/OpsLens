from opslens.database.test_connection import get_test_connection


def test_database_connection():
    connection = get_test_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database();")
            database_name = cursor.fetchone()[0]

        assert database_name == "opslens_test"

    finally:
        connection.close()