
from datetime import datetime, timezone

from database import get_db_connection


# ==================================================
# 1. CREATE RECORD
# ==================================================

def create_record(user_id, title, body):

    # Step 1: Validate user ID
    if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
        return False, "Invalid user"

    # Step 2: Validate title
    if not isinstance(title, str) or not 1 <= len(title.strip()) <= 100:
        return False, "Title must contain 1-100 characters"

    # Step 3: Validate body
    if not isinstance(body, str) or not 1 <= len(body.strip()) <= 5000:
        return False, "Body must contain 1-5000 characters"

    # Step 4: Get current UTC time
    created_at = datetime.now(timezone.utc).isoformat()

    connection = get_db_connection()

    try:

        # Step 5: Insert record using parameterized SQL
        cursor = connection.execute(
            """
            INSERT INTO records (user_id, title, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, title.strip(), body.strip(), created_at)
        )

        connection.commit()

        return True, cursor.lastrowid

    finally:
        connection.close()


# ==================================================
# 2. GET RECORD
# ==================================================

def get_record(record_id, current_user):

    # Step 1: Validate record ID
    if not isinstance(record_id, int) or isinstance(record_id, bool) or record_id <= 0:
        return False, "Invalid record ID"

    # Step 2: Validate authenticated user
    if not isinstance(current_user, dict):
        return False, "Authentication required"

    user_id = current_user.get("id")
    role = current_user.get("role")

    if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
        return False, "Authentication required"

    if role not in ("user", "admin"):
        return False, "Access denied"

    connection = get_db_connection()

    try:

        # Step 3: Retrieve the requested record
        record = connection.execute(
            """
            SELECT id, user_id, title, body, created_at
            FROM records
            WHERE id = ?
            """,
            (record_id,)
        ).fetchone()

        if record is None:
            return False, "Record not found"

        # Step 4: Check record ownership
        if role != "admin" and record["user_id"] != user_id:
            return False, "Access denied"

        # Step 5: Return record details
        return True, dict(record)

    finally:
        connection.close()
