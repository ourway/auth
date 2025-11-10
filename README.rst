Auth | Enterprise Authorization System
======================================

A comprehensive, bank-grade authorization system with role-based access control, audit logging, and high availability features.

Features
--------
- Role-based access control (RBAC) with user, role, and permission management
- JWT-based authentication and authorization
- Comprehensive audit logging for security compliance
- Database encryption for sensitive data protection
- Rate limiting and circuit breaker resilience patterns
- PostgreSQL and SQLite support
- API versioning and consistent response formats
- APScheduler integration for workflow permission checking
- Enhanced client with connection pooling and retry logic
- Configurable CORS and security settings

Requirements
------------
- Python 3.9+
- PostgreSQL (for production) or SQLite (for development)

Installation
------------
.. code:: Bash

    pip install auth

Quick Start
-----------
To start the server with default SQLite configuration:

.. code:: Bash

    auth-server

Server Configuration with PostgreSQL
------------------------------------
To configure the server with PostgreSQL, set the following environment variables:

.. code:: Bash

    export AUTH_DB_TYPE=postgresql
    export POSTGRESQL_URL=postgresql://username:password@localhost:5432/auth_db
    export JWT_SECRET_KEY=your_secure_secret_key
    export ENABLE_ENCRYPTION=true
    export ENCRYPTION_KEY=your_encryption_key
    export RATE_LIMIT_DEFAULT=500 per hour

Then start the server:

.. code:: Bash

    auth-server

API Usage
---------
All API endpoints require a valid UUID4 Bearer token in the Authorization header:

.. code:: Python

    import uuid
    from auth.client import EnhancedAuthClient
    
    # Generate a client key
    client_key = str(uuid.uuid4())
    
    # Create client instance
    client = EnhancedAuthClient(
        api_key=client_key, 
        service_url='http://127.0.0.1:4000'
    )
    
    # Add a role
    client.create_role('admin')
    
    # Add a permission
    client.add_permission('admin', 'manage_users')
    
    # Add user to role
    client.add_membership('john_doe', 'admin')
    
    # Check user permission
    result = client.user_has_permission('john_doe', 'manage_users')
    print(result)

Key API Endpoints
-----------------
- ``/ping`` [GET] - Health check
- ``/api/role/{role}`` [POST/DELETE] - Manage roles
- ``/api/permission/{group}/{name}`` [POST/GET/DELETE] - Manage permissions
- ``/api/membership/{user}/{group}`` [POST/GET/DELETE] - Manage memberships
- ``/api/has_permission/{user}/{name}`` [GET] - Check user permissions
- ``/api/user_permissions/{user}`` [GET] - Get user permissions
- ``/api/which_users_can/{name}`` [GET] - Get users who can perform action
- ``/api/workflow/users/{workflow_name}`` [GET] - Get users who can run workflow
- ``/api/workflow/user/{user}/can_run/{workflow_name}`` [GET] - Check user workflow permission

Environment Variables
---------------------
- ``AUTH_DB_TYPE`` - Database type (sqlite or postgresql) [default: sqlite]
- ``POSTGRESQL_URL`` - PostgreSQL connection string
- ``AUTH_DB_PATH`` - SQLite database path [default: ~/.auth.sqlite3]
- ``JWT_SECRET_KEY`` - Secret key for JWT tokens [required for production]
- ``JWT_ALGORITHM`` - JWT algorithm [default: HS256]
- ``JWT_ACCESS_TOKEN_EXPIRE_MINUTES`` - Token expiration [default: 1440]
- ``ENABLE_ENCRYPTION`` - Enable data encryption [default: false]
- ``ENCRYPTION_KEY`` - Encryption key [required if encryption enabled]
- ``RATE_LIMIT_DEFAULT`` - Default rate limit [default: 1000 per hour]
- ``RATELIMIT_STORAGE_URL`` - Rate limiting storage backend (redis://localhost:6379 for Redis, memory:// for in-memory) [default: memory://]
- ``SERVER_HOST`` - Server host [default: 0.0.0.0]
- ``SERVER_PORT`` - Server port [default: 4000]
- ``ALLOW_CORS`` - Enable CORS [default: true]
- ``CORS_ORIGINS`` - Allowed CORS origins [default: *]

Production Deployment
---------------------
For production deployment with multiple workers:

.. code:: Bash

    pip install waitress
    waitress-serve --host=0.0.0.0 --port=4000 --threads=10 auth.main:app

Docker Deployment
-----------------
To run with default configuration (SQLite database, memory-based rate limiting):

.. code:: Bash

    docker-compose up

To run with Redis for rate limiting (recommended for production):

.. code:: Bash

    docker-compose -f docker-compose.redis.yml up

Rate Limiting with Redis
------------------------
To use Redis for rate limiting (recommended for production), set the ``RATELIMIT_STORAGE_URL`` environment variable:

.. code:: Bash

    export RATELIMIT_STORAGE_URL=redis://localhost:6379

This provides better performance and allows rate limits to be shared across multiple server instances. If not specified, the system defaults to in-memory rate limiting which is not recommended for production use.

Architecture
------------
The system follows a layered architecture with clear separation of concerns:
- API Layer: Flask-based REST endpoints with validation and rate limiting
- Service Layer: Business logic with authorization rules
- Data Layer: SQLAlchemy ORM with encryption support
- Security Layer: JWT authentication, audit logging, and circuit breakers

The system is designed for high availability and can be deployed in containerized environments with load balancers for horizontal scaling.

Copyright
---------
Farshid Ashouri @RODMENA LIMITED