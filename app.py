
from flask import Flask, request, jsonify

from database import initialize_database
from config import Config

from modules.authentication import register_user, login_user, verify_session
from modules.records import create_record, get_record


app = Flask(__name__)

app.config.from_object(Config)

initialize_database()


# Helper function: Authenticate using a Bearer session token
def get_authenticated_user():

    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        return None

    session_token = authorization[len("Bearer "):].strip()

    if not session_token:
        return None

    return verify_session(session_token)


# Home route
@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "message": "Nestack Secure Records API",
        "status": "Running"
    }), 200


# 1. POST /register
@app.route("/register", methods=["POST"])
def register():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request"
        }), 400

    username = data.get("username")
    password = data.get("password")

    success, message = register_user(username, password)

    if not success:
        status_code = 409 if message == "Username already exists" else 400

        return jsonify({
            "error": message
        }), status_code

    return jsonify({
        "message": "Registration successful"
    }), 201


# 2. POST /login
@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request"
        }), 400

    username = data.get("username")
    password = data.get("password")

    success, result = login_user(username, password)

    if not success:

        if result == "Account temporarily locked":
            return jsonify({
                "error": result
            }), 429

        return jsonify({
            "error": result
        }), 401

    return jsonify({
        "message": "Login successful",
        "session_token": result
    }), 200


# 3. POST /records
@app.route("/records", methods=["POST"])
def create_new_record():

    current_user = get_authenticated_user()

    if current_user is None:
        return jsonify({
            "error": "Authentication required"
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request"
        }), 400

    title = data.get("title")
    body = data.get("body")

    success, result = create_record(
        current_user["id"],
        title,
        body
    )

    if not success:
        return jsonify({
            "error": result
        }), 400

    return jsonify({
        "message": "Record created successfully",
        "record_id": result
    }), 201


# 4. GET /records/<id>
@app.route("/records/<int:record_id>", methods=["GET"])
def read_record(record_id):

    current_user = get_authenticated_user()

    if current_user is None:
        return jsonify({
            "error": "Authentication required"
        }), 401

    success, result = get_record(
        record_id,
        current_user
    )

    if not success:

        if result == "Access denied":
            return jsonify({
                "error": result
            }), 403

        if result == "Record not found":
            return jsonify({
                "error": result
            }), 404

        return jsonify({
            "error": result
        }), 400

    return jsonify({
        "record": result
    }), 200


if __name__ == "__main__":
    app.run(debug=False)
