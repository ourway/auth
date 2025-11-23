============
Installation
============

Auth can be installed via pip or from source. It supports Python 3.9 and newer.

Requirements
============

System Requirements
-------------------

- Python 3.9 or higher
- PostgreSQL 12+ (for production) or SQLite 3 (for development)
- 512MB RAM minimum (1GB+ recommended for production)

Python Dependencies
-------------------

Core dependencies are automatically installed:

- Flask >= 2.0.0
- Flask-CORS >= 3.0.0
- SQLAlchemy >= 1.4.0
- Waitress >= 2.0.0
- PyJWT >= 2.0.0
- cryptography >= 3.0.0
- APScheduler >= 3.0.0
- psycopg3[binary] >= 3.0.0

Installation Methods
====================

Install from PyPI (Recommended)
--------------------------------

.. code-block:: bash

    pip install auth

This will install the latest stable version with all required dependencies.

Install from Source
-------------------

Clone the repository and install:

.. code-block:: bash

    git clone https://github.com/rodmena-limited/auth.git
    cd auth
    pip install -e .

Development Installation
------------------------

For development with testing and linting tools:

.. code-block:: bash

    pip install auth[dev]

This includes pytest, coverage, ruff, mypy, black, and other development tools.

Database Setup
==============

SQLite (Development)
--------------------

No setup required! Auth will automatically create a SQLite database at ``~/.auth.sqlite3`` on first run.

PostgreSQL (Production)
-----------------------

1. Install PostgreSQL:

.. code-block:: bash

    # Ubuntu/Debian
    sudo apt-get install postgresql postgresql-contrib

    # macOS
    brew install postgresql

2. Create a database and user:

.. code-block:: sql

    CREATE DATABASE authdb;
    CREATE USER authuser WITH PASSWORD 'your_password';
    GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;

3. Configure Auth to use PostgreSQL:

.. code-block:: bash

    export AUTH_DATABASE_TYPE=postgresql
    export AUTH_POSTGRESQL_URL=postgresql://authuser:your_password@localhost:5432/authdb

Verification
============

Verify the installation:

.. code-block:: python

    import auth
    print(auth.__author__)  # Should print: Farshid Ashouri

Or run the server to check if everything works:

.. code-block:: bash

    python -m auth.main

You should see output indicating the server is running on ``http://127.0.0.1:5000``.

Quick Health Check
------------------

Test the server endpoint:

.. code-block:: bash

    curl http://localhost:5000/ping

Expected response:

.. code-block:: json

    {
      "message": "pong",
      "status": "ok",
      "timestamp": "2025-11-23T12:34:56.789012"
    }

Troubleshooting
===============

Common Issues
-------------

**ModuleNotFoundError: No module named 'auth'**
    Ensure you have activated your virtual environment and installed the package.

**Database connection errors with PostgreSQL**
    - Verify PostgreSQL is running: ``sudo systemctl status postgresql``
    - Check connection string format
    - Ensure the database and user exist
    - Verify firewall settings allow connections

**Permission denied errors**
    - For SQLite: Check write permissions on ``~/.auth.sqlite3``
    - For PostgreSQL: Verify user has appropriate privileges

**Port already in use**
    Change the default port using:

    .. code-block:: bash

        export AUTH_SERVER_PORT=8080

Docker Installation
===================

Using Docker Compose (Recommended)
----------------------------------

Create a ``docker-compose.yml`` file:

.. code-block:: yaml

    version: '3.8'
    services:
      postgres:
        image: postgres:15
        environment:
          POSTGRES_DB: authdb
          POSTGRES_USER: authuser
          POSTGRES_PASSWORD: your_password
        ports:
          - "5432:5432"
        volumes:
          - postgres_data:/var/lib/postgresql/data

      auth:
        image: auth:latest
        environment:
          AUTH_DATABASE_TYPE: postgresql
          AUTH_POSTGRESQL_URL: postgresql://authuser:your_password@postgres:5432/authdb
          AUTH_JWT_SECRET_KEY: your_secret_key_here
          AUTH_ENABLE_ENCRYPTION: "true"
          AUTH_ENCRYPTION_KEY: your_encryption_key_here
        ports:
          - "5000:5000"
        depends_on:
          - postgres

    volumes:
      postgres_data:

Then run:

.. code-block:: bash

    docker-compose up -d

Build Docker Image
------------------

Build your own Docker image:

.. code-block:: bash

    docker build -t auth:latest .

Next Steps
==========

Now that you have Auth installed, continue to:

- :doc:`quickstart` - Get started with basic usage
- :doc:`configuration` - Configure Auth for your needs
- :doc:`deployment` - Deploy to production
