===============
Troubleshooting
===============

Common issues and solutions.

Database Issues
===============

Connection Errors
-----------------

**PostgreSQL connection refused:**

.. code-block:: bash

    # Check PostgreSQL is running
    sudo systemctl status postgresql
    
    # Test connection
    psql -U authuser -d authdb -h localhost

**Solution:** Ensure PostgreSQL is running and credentials are correct.

SQLite Permission Errors
-------------------------

**Permission denied on ~/.auth.sqlite3:**

.. code-block:: bash

    chmod 600 ~/.auth.sqlite3
    chown $USER:$USER ~/.auth.sqlite3

Authentication Issues
=====================

Invalid Client Key
------------------

**Error:** "Unauthorized" or "Invalid client key"

**Solution:** Ensure you're using a valid UUID4:

.. code-block:: python

    import uuid
    client_key = str(uuid.uuid4())  # Correct format

Encryption Issues
=================

Decryption Failed
-----------------

**Error:** "Invalid token" or "Decryption failed"

**Cause:** Wrong encryption key or data encrypted with different key.

**Solution:**

.. code-block:: bash

    # Verify encryption key
    echo $AUTH_ENCRYPTION_KEY
    
    # Check key format (should be base64)
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Performance Issues
==================

Slow Queries
------------

**Symptom:** Permission checks taking too long.

**Solution:** Add database indexes:

.. code-block:: sql

    CREATE INDEX idx_membership_user ON auth_membership(user);
    CREATE INDEX idx_permission_name ON auth_permission(name);

See :doc:`security`, :doc:`deployment`, and :doc:`configuration` for more information.
