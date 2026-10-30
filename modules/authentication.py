
import sqlite3
import bcrypt
import secrets
import hashlib

from datetime import datetime, timedelta, timezone
from database import get_db_connection


# ==================================================
# 1. USER REGISTRATION
# ==================================================

def register_user(username, password):

    # Step 1: Validate username
    if not isinstance(username, str) or not 3 <= len(username.strip()) <= 50:
        return False, "Invalid username"

    # Step 2: Validate password
    if not isinstance(password, str):
        return False, "Invalid password"

    password_bytes = password.encode("utf-8")

    if len(password_bytes) < 12 or len(password_bytes) > 72:
        return False, "Password must be 12-72 bytes"

    # Step 3: Hash password using bcrypt
    password_hash = bcrypt.hashpw(
        password_bytes,
        bcrypt.gensalt()
    )

    # Step 4: Connect to database
    connection = get_db_connection()

    try:

        # Step 5: Insert new user
        connection.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username.strip(), password_hash, "user")
        )

        connection.commit()

        return True, "Registration successful"

    except sqlite3.IntegrityError:
        return False, "Username already exists"

    finally:
        connection.close()


# ==================================================
# 2. USER LOGIN WITH ACCOUNT LOCKOUT
# ==================================================

def login_user(username, password):

    # Step 1: Validate input
    if not isinstance(username, str) or not isinstance(password, str):
        return False, "Invalid username or password"

    if not username.strip():
        return False, "Invalid username or password"

    password_bytes = password.encode("utf-8")

    if len(password_bytes) == 0 or len(password_bytes) > 72:
        return False, "Invalid username or password"

    connection = get_db_connection()

    try:

        # Step 2: Find the account
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()

        if user is None:
            return False, "Invalid username or password"

        current_time = datetime.now(timezone.utc)

        # Step 3: Check whether the account is locked
        if user["locked_until"] is not None:

            locked_until = datetime.fromisoformat(
                user["locked_until"]
            )

            if current_time < locked_until:
                return False, "Account temporarily locked"

            # Lock period has expired; reset attempts
            connection.execute(
                """
                UPDATE users
                SET failed_attempts = 0,
                    locked_until = NULL
                WHERE id = ?
                """,
                (user["id"],)
            )

            connection.commit()

        # Step 4: Verify password
        if not bcrypt.checkpw(
            password_bytes,
            user["password_hash"]
        ):

            failed_attempts = user["failed_attempts"] + 1

            if failed_attempts >= 5:

                locked_until = (
                    current_time + timedelta(minutes=15)
                ).isoformat()

                connection.execute(
                    """
                    UPDATE users
                    SET failed_attempts = ?,
                        locked_until = ?
                    WHERE id = ?
                    """,
                    (failed_attempts, locked_until, user["id"])
                )

                connection.commit()

                return False, "Account temporarily locked"

            connection.execute(
                """
                UPDATE users
                SET failed_attempts = ?
                WHERE id = ?
                """,
                (failed_attempts, user["id"])
            )

            connection.commit()

            return False, "Invalid username or password"

        # Step 5: Reset failed attempts after successful login
        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (user["id"],)
        )

        # Step 6: Generate an opaque session token
        session_token = secrets.token_urlsafe(32)

        # Step 7: Hash the token before storing it
        token_hash = hashlib.sha256(
            session_token.encode("utf-8")
        ).hexdigest()

        # Step 8: Set session expiry (30 minutes)
        expires_at = (
            current_time + timedelta(minutes=30)
        ).isoformat()

        # Step 9: Store the session
        connection.execute(
            """
            INSERT INTO sessions (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            """,
            (user["id"], token_hash, expires_at)
        )

        connection.commit()

        # Return original token to the client
        return True, session_token

    finally:
        connection.close()


# ==================================================
# 3. SESSION VERIFICATION
# ==================================================

def verify_session(session_token):

    # Step 1: Validate token
    if not isinstance(session_token, str) or not session_token:
        return None

    # Step 2: Hash received token
    token_hash = hashlib.sha256(
        session_token.encode("utf-8")
    ).hexdigest()

    connection = get_db_connection()

    try:

        # Step 3: Find session and associated user
        session = connection.execute(
            """
            SELECT users.id, users.username, users.role,
                   sessions.expires_at
            FROM sessions
            JOIN users ON sessions.user_id = users.id
            WHERE sessions.token_hash = ?
            """,
            (token_hash,)
        ).fetchone()

        if session is None:
            return None

        # Step 4: Check session expiry
        expiry_time = datetime.fromisoformat(
            session["expires_at"]
        )

        if datetime.now(timezone.utc) >= expiry_time:

            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (token_hash,)
            )

            connection.commit()

            return None

        # Step 5: Return authenticated user information
        return {
            "id": session["id"],
            "username": session["username"],
            "role": session["role"]
        }

    finally:
        connection.close()
