# Nestack Secure Records API

## Project Overview

The Nestack Secure Records API is a Python Flask-based REST API designed to securely register users, authenticate login requests, and manage private records.

The application uses password hashing, session-token authentication, role-based access control, input validation, and SQLite database storage.

## Technologies Used

- Python
- Flask
- SQLite
- bcrypt
- Requests / Postman
- Pytest

## Features

- User registration and login
- Secure password hashing using bcrypt
- Opaque session tokens
- Session expiration after 30 minutes
- Account lockout after five failed login attempts
- Account-based login abuse protection
- Authenticated record creation
- Record ownership verification
- Admin access to all records
- Input validation
- Parameterized SQL queries
- HTTP status-code handling

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/register` | Register a new user |
| POST | `/login` | Authenticate a user |
| POST | `/records` | Create a record |
| GET | `/records/<id>` | Retrieve an authorized record |

## Security Implementation

### Password Security

Passwords are hashed using bcrypt before being stored in the database. Plain-text passwords are not stored.

### Session Authentication

After successful login, the API generates an opaque session token. Only its SHA-256 hash is stored in the database. The token expires after 30 minutes.

### Role-Based Access Control

Normal users can access only their own records. Admin users can access records belonging to any user.

The role is assigned on the server side and cannot be selected during registration.

### Login Abuse Protection

After five failed login attempts, an account is temporarily locked for 15 minutes. Login attempts are tracked per account rather than by IP address.

### SQL Injection Protection

Parameterized SQL queries are used for database operations.

### Input Validation

The API validates required fields, data types, and input lengths before processing requests.

## Threat Model

| Threat | Security Control |
| --- | --- |
| Password exposure | bcrypt password hashing |
| Unauthorized access | Bearer-token authentication |
| Session misuse | Hashed token storage and expiry |
| Privilege escalation | Server-side role assignment |
| Unauthorized record access | Ownership verification |
| SQL injection | Parameterized queries |
| Login abuse | Account lockout |
| Invalid input | Input validation |

## Installation and Execution

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:

	```bash
	pip install -r requirements.txt
	```

4. Start the application:

	```bash
	python app.py
	```

5. The API runs locally at `http://127.0.0.1:5000`.

## Testing

API endpoints can be tested using Postman.

Test registration, login, record creation, authenticated record retrieval, and unauthorized access.

## Database

SQLite is used to store user accounts, session information, and records.

The database is created automatically when the application starts.

## Limitations

This project is a security-focused API demonstration. Production deployment would require additional hardening, secure secret management, HTTPS configuration, monitoring, and operational security controls.

## Author

sarmitha G
