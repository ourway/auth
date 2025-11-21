Auth | Enterprise Authorization System
======================================

A comprehensive, production-ready authorization system with role-based access control, audit logging, encryption, and high availability features.

**📚 For detailed documentation, see:**

- `README.md <README.md>`_ - Complete guide with examples
- `docs/API.md <docs/API.md>`_ - Full API reference
- `docs/PYTHON_EXAMPLES.md <docs/PYTHON_EXAMPLES.md>`_ - Python usage examples

**✅ Fully Tested:** 152/152 tests passing (100% pass rate)

Features
--------
**Core Features:**

- Role-based access control (RBAC) with hierarchical permissions
- Multiple storage backends (SQLite for development, PostgreSQL for production)
- Dual interface: REST API and Python library
- JWT-based authentication and authorization
- Optional field-level encryption for sensitive data
- Comprehensive audit logging for security compliance
- Workflow permission checking with APScheduler

**Security Features:**

- UUID4-based client authentication
- JWT token-based authorization
- Field-level encryption with Fernet
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

    pip install -r requirements.txt

Quick Start
-----------
**Start the server** (default SQLite on port 5000):

.. code:: bash

    python -m auth.main

**Test the API:**

.. code:: bash

    bash showcase_api.sh

Production Deployment
---------------------
For production with PostgreSQL:

.. code:: bash

    export AUTH_DB_TYPE=postgresql
    export POSTGRESQL_URL=postgresql://user:pass@localhost:5432/authdb
    export JWT_SECRET_KEY=your-secret-key
    export ENABLE_ENCRYPTION=true
    export ENCRYPTION_KEY=your-encryption-key

    # Using Waitress (recommended)
    pip install waitress
    waitress-serve --host=0.0.0.0 --port=5000 --threads=10 auth.main:app

    # Or using Gunicorn
    pip install gunicorn
    gunicorn -w 4 -b 0.0.0.0:5000 auth.main:app

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

For detailed Python examples, see `docs/PYTHON_EXAMPLES.md <docs/PYTHON_EXAMPLES.md>`_

REST API Usage
--------------
.. code:: bash

    # Generate client key
    CLIENT_KEY=$(uuidgen)

    # Create role
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/role/admin

    # Add permission
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/permission/admin/manage_users

    # Check user permission
    curl -X GET \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/has_permission/alice@example.com/manage_users

For complete API reference, see `docs/API.md <docs/API.md>`_

Key Endpoints
-------------
- ``GET /ping`` - Health check
- ``POST /api/role/{role}`` - Create role
- ``POST /api/permission/{role}/{name}`` - Add permission to role
- ``POST /api/membership/{user}/{role}`` - Add user to role
- ``GET /api/has_permission/{user}/{name}`` - Check user permission
- ``GET /api/user_permissions/{user}`` - Get all user permissions
- ``GET /api/which_users_can/{name}`` - Find users with permission

*See docs/API.md for complete endpoint documentation*

Configuration
-------------
Environment variables (or use .env file):

- ``AUTH_DB_TYPE`` - Database type (sqlite or postgresql) [default: sqlite]
- ``POSTGRESQL_URL`` - PostgreSQL connection string
- ``SQLITE_PATH`` - SQLite database path [default: ~/.auth.sqlite3]
- ``JWT_SECRET_KEY`` - Secret key for JWT tokens
- ``ENABLE_ENCRYPTION`` - Enable data encryption [default: false]
- ``ENCRYPTION_KEY`` - Encryption key [required if encryption enabled]
- ``SERVER_HOST`` - Server host [default: 0.0.0.0]
- ``SERVER_PORT`` - Server port [default: 5000]
- ``ALLOW_CORS`` - Enable CORS [default: true]
- ``CORS_ORIGINS`` - Allowed CORS origins [default: *]

Testing
-------
Run the complete test suite:

.. code:: bash

    # All tests (152 tests)
    python -m pytest tests/ -v

    # With coverage
    python -m pytest tests/ --cov=auth --cov-report=html

    # Run showcase script
    bash showcase_api.sh

Architecture
------------
The system follows a layered architecture:

- **API Layer:** Flask-based REST endpoints with validation
- **Service Layer:** Business logic with authorization rules
- **Data Access Layer:** SQLAlchemy ORM with encryption support
- **Database Layer:** PostgreSQL (production) or SQLite (development)

Documentation
-------------
- `README.md <README.md>`_ - Complete user guide
- `docs/API.md <docs/API.md>`_ - Full API reference
- `docs/PYTHON_EXAMPLES.md <docs/PYTHON_EXAMPLES.md>`_ - Python usage examples

License & Copyright
-------------------
MIT License

© Farshid Ashouri @RODMENA LIMITED