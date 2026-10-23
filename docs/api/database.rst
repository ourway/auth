========
Database
========

.. automodule:: auth.database
   :members:
   :undoc-members:
   :show-inheritance:

Database Configuration
======================

.. autofunction:: auth.database.create_tables
.. autofunction:: auth.database.get_db

Schema Check
============

.. autofunction:: auth.schema_check.check_schema
.. autofunction:: auth.schema_check.find_schema_drift
.. autoexception:: auth.schema_check.SchemaMismatchError

Session Management
==================

.. autodata:: auth.database.SessionLocal
