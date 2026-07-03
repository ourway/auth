Auth | Enterprise Authorization System
======================================

A comprehensive, production-ready authorization system with role-based access control, audit logging, encryption, and high availability features.

**📚 For detailed documentation, see the project repository.**

Features
--------
**Core Features:**

- Role-based access control (RBAC) with hierarchical permissions
- Multiple storage backends (SQLite for development, PostgreSQL for production)
- Dual interface: REST API and Python library
- Optional deterministic field-level encryption for sensitive data
- Comprehensive audit logging for security compliance
- Workflow permission checking with APScheduler

**Security Features:**

- UUID4 client keys as isolated tenant namespaces
- Deterministic field-level encryption (AES-256-CTR, PBKDF2-derived keys)
- Input validation and sanitization
- Configurable CORS settings

**Production Features:**

- Connection pooling with retry logic
- Circuit breaker pattern for fault tolerance
- Health check endpoint
- Consistent API response formats
- Extensive test coverage

Requirements
------------
- Python 3.9+
- PostgreSQL (for production) or SQLite (for development/testing)

Installation
------------
.. code:: bash

    pip install auth

Security model
--------------
The REST API identifies callers by a client key: any valid UUID4 presented
as ``Authorization: Bearer <uuid4>`` acts as an isolated tenant namespace.
The key is **not** verified against a secret — treat it like an API key you
keep private, and deploy the service on a trusted network or behind an
authenticating gateway. Do not expose the server directly to the public
internet.

Quick Start
-----------
**Start the server** (default SQLite backend, port 4000):

.. code:: bash

    auth-server

**Test the API:**

.. code:: bash

    curl http://localhost:4000/ping

Production Deployment
---------------------
For production with PostgreSQL:

.. code:: bash

    export AUTH_DATABASE_TYPE=postgresql
    export AUTH_POSTGRESQL_URL=postgresql://user:pass@localhost:5432/authdb
    export AUTH_JWT_SECRET_KEY=your-secret-key
    export AUTH_ENABLE_ENCRYPTION=true
    export AUTH_ENCRYPTION_KEY=your-encryption-key

    # Using Waitress (recommended)
    pip install waitress
    waitress-serve --host=0.0.0.0 --port=4000 --threads=10 auth.main:app

    # Or using Gunicorn
    pip install gunicorn
    gunicorn -w 4 -b 0.0.0.0:4000 auth.main:app

Python Library Usage
--------------------
.. code:: python

    import uuid
    from auth import Authorization

    # Create authorization instance
    client_key = str(uuid.uuid4())
    auth = Authorization(client_key)

    # Create roles and permissions
    auth.add_role('admin', 'Administrator role')
    auth.add_permission('admin', 'manage_users')

    # Add user to role
    auth.add_membership('alice@example.com', 'admin')

    # Check permission
    if auth.user_has_permission('alice@example.com', 'manage_users'):
        print("Alice can manage users")

For detailed Python examples, see the project documentation.

REST API Usage
--------------
.. code:: bash

    # Generate client key
    CLIENT_KEY=$(uuidgen)

    # Create role
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:4000/api/role/admin

    # Add permission
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:4000/api/permission/admin/manage_users

    # Check user permission
    curl -X GET \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:4000/api/has_permission/alice@example.com/manage_users

For complete API reference, see the project documentation.

Key Endpoints
-------------
- ``GET /ping`` - Health check
- ``POST /api/role/{role}`` - Create role
- ``POST /api/permission/{role}/{name}`` - Add permission to role
- ``POST /api/membership/{user}/{role}`` - Add user to role
- ``GET /api/has_permission/{user}/{name}`` - Check user permission
- ``GET /api/user_permissions/{user}`` - Get all user permissions
- ``GET /api/which_users_can/{name}`` - Find users with permission

*See the project documentation for complete endpoint details*

Configuration
-------------
Environment variables (or use .env file):

- ``AUTH_DATABASE_TYPE`` - Database type (sqlite or postgresql) [default: sqlite]
- ``AUTH_DATABASE_URL`` - Full database connection URL (overrides other settings)
- ``AUTH_POSTGRESQL_URL`` - PostgreSQL connection string
- ``AUTH_SQLITE_PATH`` - SQLite database path [default: ~/.auth.sqlite3]
- ``AUTH_JWT_SECRET_KEY`` - Secret key for JWT tokens
- ``AUTH_JWT_ALGORITHM`` - JWT algorithm [default: HS256]
- ``AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES`` - Token expiration [default: 1440]
- ``AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS`` - Refresh token expiration [default: 7]
- ``AUTH_ENABLE_ENCRYPTION`` - Enable data encryption [default: false]
- ``AUTH_ENCRYPTION_KEY`` - Encryption key [required if encryption enabled]
- ``AUTH_SERVER_HOST`` - Server host [default: 127.0.0.1]
- ``AUTH_SERVER_PORT`` - Server port [default: 8000]
- ``AUTH_DEBUG_MODE`` - Debug mode [default: false]
- ``AUTH_ALLOW_CORS`` - Enable CORS [default: true]
- ``AUTH_CORS_ORIGINS`` - Allowed CORS origins [default: \*]
- ``AUTH_ENABLE_AUDIT_LOGGING`` - Enable audit logging [default: true]

Testing
-------
Run the complete test suite (from a source checkout):

.. code:: bash

    # SQLite suite
    python -m pytest tests/ -v

    # PostgreSQL integration suite (Docker required)
    make test-postgres

    # With coverage
    python -m pytest tests/ --cov=auth --cov-report=html

Architecture
------------
The system follows a layered architecture:

- **API Layer:** Flask-based REST endpoints with validation
- **Service Layer:** Business logic with authorization rules
- **Data Access Layer:** SQLAlchemy ORM with encryption support
- **Database Layer:** PostgreSQL (production) or SQLite (development)

Documentation
-------------
Complete documentation including API reference and Python examples is available in the project repository.

License
-------
MIT License

Copyright (c) Farshid Ashouri