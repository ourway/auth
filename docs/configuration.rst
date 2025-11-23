=============
Configuration
=============

Auth can be configured through environment variables or a ``.env`` file. This page covers all available configuration options.

Environment Variables
=====================

Database Configuration
----------------------

**AUTH_DATABASE_TYPE**
    Database backend to use.

    - **Type:** String
    - **Options:** ``sqlite``, ``postgresql``
    - **Default:** ``sqlite``
    - **Example:** ``export AUTH_DATABASE_TYPE=postgresql``

**AUTH_DATABASE_URL**
    Full database connection URL (overrides other database settings).

    - **Type:** String (connection URL)
    - **Default:** None
    - **Example:** ``export AUTH_DATABASE_URL=postgresql://user:pass@localhost:5432/authdb``

**AUTH_POSTGRESQL_URL**
    PostgreSQL-specific connection string.

    - **Type:** String (PostgreSQL connection URL)
    - **Default:** None
    - **Example:** ``export AUTH_POSTGRESQL_URL=postgresql://authuser:password@localhost:5432/auth_db``

**AUTH_SQLITE_PATH**
    Path to SQLite database file.

    - **Type:** String (file path)
    - **Default:** ``~/.auth.sqlite3``
    - **Example:** ``export AUTH_SQLITE_PATH=/var/lib/auth/auth.db``

JWT Configuration
-----------------

**AUTH_JWT_SECRET_KEY**
    Secret key for signing JWT tokens.

    - **Type:** String
    - **Default:** Auto-generated on startup
    - **Example:** ``export AUTH_JWT_SECRET_KEY=your-very-secure-secret-key-here``
    - **Security:** Use a strong, random key (32+ characters). Change this in production!

**AUTH_JWT_ALGORITHM**
    Algorithm used for JWT signing.

    - **Type:** String
    - **Options:** ``HS256``, ``HS384``, ``HS512``, ``RS256``, etc.
    - **Default:** ``HS256``
    - **Example:** ``export AUTH_JWT_ALGORITHM=HS256``

**AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES**
    JWT access token expiration time in minutes.

    - **Type:** Integer
    - **Default:** ``1440`` (24 hours)
    - **Example:** ``export AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60``

**AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS**
    JWT refresh token expiration time in days.

    - **Type:** Integer
    - **Default:** ``7``
    - **Example:** ``export AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS=30``

Encryption Configuration
-------------------------

**AUTH_ENABLE_ENCRYPTION**
    Enable field-level encryption for sensitive data.

    - **Type:** Boolean
    - **Options:** ``true``, ``false``
    - **Default:** ``false``
    - **Example:** ``export AUTH_ENABLE_ENCRYPTION=true``

**AUTH_ENCRYPTION_KEY**
    Encryption key for field-level encryption (required if encryption is enabled).

    - **Type:** String (base64-encoded key)
    - **Default:** None
    - **Example:** ``export AUTH_ENCRYPTION_KEY=your-base64-encoded-encryption-key``
    - **Generate:** ``python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"``

Server Configuration
--------------------

**AUTH_SERVER_HOST**
    Server bind address.

    - **Type:** String (IP address)
    - **Default:** ``127.0.0.1``
    - **Example:** ``export AUTH_SERVER_HOST=0.0.0.0``
    - **Security:** Use ``127.0.0.1`` for local only, ``0.0.0.0`` for all interfaces

**AUTH_SERVER_PORT**
    Server port number.

    - **Type:** Integer
    - **Default:** ``5000``
    - **Example:** ``export AUTH_SERVER_PORT=8000``

**AUTH_DEBUG_MODE**
    Enable Flask debug mode.

    - **Type:** Boolean
    - **Options:** ``true``, ``false``
    - **Default:** ``false``
    - **Example:** ``export AUTH_DEBUG_MODE=false``
    - **Security:** NEVER enable in production!

CORS Configuration
------------------

**AUTH_ALLOW_CORS**
    Enable Cross-Origin Resource Sharing.

    - **Type:** Boolean
    - **Options:** ``true``, ``false``
    - **Default:** ``true``
    - **Example:** ``export AUTH_ALLOW_CORS=true``

**AUTH_CORS_ORIGINS**
    Allowed CORS origins (comma-separated).

    - **Type:** String (comma-separated URLs)
    - **Default:** ``*`` (all origins)
    - **Example:** ``export AUTH_CORS_ORIGINS=https://app.example.com,https://admin.example.com``
    - **Security:** Specify exact origins in production, not ``*``

Audit Logging
-------------

**AUTH_ENABLE_AUDIT_LOGGING**
    Enable comprehensive audit logging.

    - **Type:** Boolean
    - **Options:** ``true``, ``false``
    - **Default:** ``true``
    - **Example:** ``export AUTH_ENABLE_AUDIT_LOGGING=true``

Configuration File (.env)
==========================

You can use a ``.env`` file in your project root:

Development Configuration
--------------------------

.. code-block:: bash

    # .env (development)
    AUTH_DATABASE_TYPE=sqlite
    AUTH_SQLITE_PATH=./dev.db
    AUTH_DEBUG_MODE=true
    AUTH_ALLOW_CORS=true
    AUTH_CORS_ORIGINS=*

Production Configuration
------------------------

.. code-block:: bash

    # .env (production)
    AUTH_DATABASE_TYPE=postgresql
    AUTH_POSTGRESQL_URL=postgresql://authuser:SecurePassword123@postgres.example.com:5432/auth_production
    
    # JWT Configuration
    AUTH_JWT_SECRET_KEY=your-production-secret-key-minimum-32-characters
    AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
    AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
    
    # Encryption
    AUTH_ENABLE_ENCRYPTION=true
    AUTH_ENCRYPTION_KEY=your-generated-fernet-key-here
    
    # Server
    AUTH_SERVER_HOST=0.0.0.0
    AUTH_SERVER_PORT=5000
    AUTH_DEBUG_MODE=false
    
    # CORS
    AUTH_ALLOW_CORS=true
    AUTH_CORS_ORIGINS=https://app.example.com,https://admin.example.com
    
    # Audit
    AUTH_ENABLE_AUDIT_LOGGING=true

Loading Configuration
=====================

From Environment Variables
---------------------------

Export variables before running:

.. code-block:: bash

    export AUTH_DATABASE_TYPE=postgresql
    export AUTH_POSTGRESQL_URL=postgresql://user:pass@localhost/authdb
    python -m auth.main

From .env File
--------------

Create a ``.env`` file and run:

.. code-block:: bash

    python -m auth.main

The application automatically loads ``.env`` if present.

Programmatic Configuration
---------------------------

.. code-block:: python

    import os
    from auth import Authorization

    # Set configuration before importing
    os.environ['AUTH_DATABASE_TYPE'] = 'postgresql'
    os.environ['AUTH_POSTGRESQL_URL'] = 'postgresql://user:pass@localhost/db'
    
    # Now create instances
    client_key = "your-client-key"
    auth = Authorization(client_key)

Configuration Precedence
=========================

Configuration values are loaded in this order (later overrides earlier):

1. Default values (defined in code)
2. ``.env`` file values
3. Environment variables
4. Command-line arguments (if applicable)

Example:

.. code-block:: bash

    # .env file has:
    AUTH_SERVER_PORT=8000
    
    # Environment variable overrides it:
    export AUTH_SERVER_PORT=9000
    
    # Server will run on port 9000

Validation
==========

The configuration system validates settings on startup:

**Database URL Format**
    Ensures valid connection string format

**Port Numbers**
    Validates port range (1-65535)

**Boolean Values**
    Accepts: ``true``, ``false``, ``1``, ``0``, ``yes``, ``no``

**Encryption Key**
    Validates Fernet key format if encryption is enabled

Common Configuration Patterns
==============================

Development Setup
-----------------

.. code-block:: bash

    # Minimal development config
    AUTH_DATABASE_TYPE=sqlite
    AUTH_DEBUG_MODE=true

Production Setup
----------------

.. code-block:: bash

    # Full production config
    AUTH_DATABASE_TYPE=postgresql
    AUTH_POSTGRESQL_URL=postgresql://authuser:password@db.example.com:5432/authdb
    AUTH_JWT_SECRET_KEY=<generated-secret>
    AUTH_ENABLE_ENCRYPTION=true
    AUTH_ENCRYPTION_KEY=<generated-key>
    AUTH_SERVER_HOST=0.0.0.0
    AUTH_SERVER_PORT=5000
    AUTH_DEBUG_MODE=false
    AUTH_CORS_ORIGINS=https://app.example.com

Docker Setup
------------

.. code-block:: yaml

    # docker-compose.yml
    version: '3.8'
    services:
      auth:
        image: auth:latest
        environment:
          - AUTH_DATABASE_TYPE=postgresql
          - AUTH_POSTGRESQL_URL=postgresql://authuser:password@postgres:5432/authdb
          - AUTH_JWT_SECRET_KEY=${JWT_SECRET}
          - AUTH_ENABLE_ENCRYPTION=true
          - AUTH_ENCRYPTION_KEY=${ENCRYPTION_KEY}
        env_file:
          - .env.production

Kubernetes Setup
----------------

.. code-block:: yaml

    # ConfigMap
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: auth-config
    data:
      AUTH_DATABASE_TYPE: "postgresql"
      AUTH_SERVER_HOST: "0.0.0.0"
      AUTH_SERVER_PORT: "5000"
      AUTH_ENABLE_AUDIT_LOGGING: "true"

    # Secret
    apiVersion: v1
    kind: Secret
    metadata:
      name: auth-secrets
    type: Opaque
    data:
      AUTH_JWT_SECRET_KEY: <base64-encoded>
      AUTH_ENCRYPTION_KEY: <base64-encoded>
      AUTH_POSTGRESQL_URL: <base64-encoded>

Security Considerations
=======================

Secrets Management
------------------

**Never commit secrets to version control:**

.. code-block:: bash

    # .gitignore
    .env
    .env.production
    .env.local

**Use environment-specific files:**

.. code-block:: bash

    .env.development
    .env.staging
    .env.production

**Use secrets management in production:**

- AWS Secrets Manager
- HashiCorp Vault
- Kubernetes Secrets
- Azure Key Vault

Key Rotation
------------

Regularly rotate sensitive keys:

.. code-block:: bash

    # Generate new JWT secret
    openssl rand -base64 32

    # Generate new encryption key
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Monitoring and Logging
=======================

Enable audit logging in production:

.. code-block:: bash

    AUTH_ENABLE_AUDIT_LOGGING=true

Configure log levels:

.. code-block:: python

    import logging
    
    # In your application
    logging.basicConfig(level=logging.INFO)

Next Steps
==========

- :doc:`security` - Security best practices
- :doc:`encryption` - Encryption configuration
- :doc:`deployment` - Deployment strategies
- :doc:`production` - Production hardening
