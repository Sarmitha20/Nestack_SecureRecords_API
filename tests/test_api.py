
import pytest
import database
from app import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Create a separate temporary database for each test
    test_db = tmp_path / "test_records.db"
    monkeypatch.setattr(database, "DATABASE_PATH", str(test_db))

    database.initialize_database()

    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


def register_user(client, username):
    return client.post("/register", json={
        "username": username,
        "password": "SecurePass@123"
    })


def login_user(client, username):
    response = client.post("/login", json={
        "username": username,
        "password": "SecurePass@123"
    })

    return response.get_json()["session_token"]


# Test 1: User registration
def test_user_registration(client):
    response = register_user(client, "student1")
    assert response.status_code == 201


# Test 2: Duplicate registration
def test_duplicate_registration(client):
    register_user(client, "student1")

    response = register_user(client, "student1")
    assert response.status_code == 409


# Test 3: Successful login
def test_login_success(client):
    register_user(client, "student1")

    response = client.post("/login", json={
        "username": "student1",
        "password": "SecurePass@123"
    })

    assert response.status_code == 200
    assert "session_token" in response.get_json()


# Test 4: Unauthorized record access
def test_unauthorized_record_access(client):
    response = client.get("/records/1")
    assert response.status_code == 401


# Test 5: Record creation and owner access
def test_record_creation_and_owner_access(client):
    register_user(client, "student1")
    token = login_user(client, "student1")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    created = client.post("/records", json={
        "title": "Test Record",
        "body": "Private record content"
    }, headers=headers)

    assert created.status_code == 201

    record_id = created.get_json()["record_id"]

    retrieved = client.get(
        f"/records/{record_id}",
        headers=headers
    )

    assert retrieved.status_code == 200
    assert retrieved.get_json()["record"]["title"] == "Test Record"


# Test 6: User cannot access another user's record
def test_user_cannot_access_another_users_record(client):
    register_user(client, "student1")
    token1 = login_user(client, "student1")

    created = client.post("/records", json={
        "title": "Private Record",
        "body": "Only the owner should access this"
    }, headers={
        "Authorization": f"Bearer {token1}"
    })

    record_id = created.get_json()["record_id"]

    register_user(client, "student2")
    token2 = login_user(client, "student2")

    response = client.get(
        f"/records/{record_id}",
        headers={
            "Authorization": f"Bearer {token2}"
        }
    )

    assert response.status_code == 403


# Test 7: Admin can access another user's record
def test_admin_can_access_another_users_record(client):
    register_user(client, "student1")
    user_token = login_user(client, "student1")

    created = client.post("/records", json={
        "title": "Admin Test",
        "body": "Admin access test"
    }, headers={
        "Authorization": f"Bearer {user_token}"
    })

    record_id = created.get_json()["record_id"]

    register_user(client, "admin1")

    # Simulate trusted server-side admin provisioning
    connection = database.get_db_connection()

    connection.execute(
        "UPDATE users SET role = ? WHERE username = ?",
        ("admin", "admin1")
    )

    connection.commit()
    connection.close()

    admin_token = login_user(client, "admin1")

    response = client.get(
        f"/records/{record_id}",
        headers={
            "Authorization": f"Bearer {admin_token}"
        }
    )

    assert response.status_code == 200


# Test 8: Account lockout after five failed attempts
def test_login_lockout(client):
    register_user(client, "locktest")

    # First four failed attempts return 401
    for _ in range(4):
        response = client.post("/login", json={
            "username": "locktest",
            "password": "WrongPassword@123"
        })

        assert response.status_code == 401

    # Fifth failed attempt locks the account
    response = client.post("/login", json={
        "username": "locktest",
        "password": "WrongPassword@123"
    })

    assert response.status_code == 429

    # Correct password is also blocked during lockout
    response = client.post("/login", json={
        "username": "locktest",
        "password": "SecurePass@123"
    })

    assert response.status_code == 429
