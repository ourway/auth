Auth Documentation
==================

Welcome to the official documentation for **Auth**, an enterprise-grade authorization system with role-based access control (RBAC), audit logging, encryption, and high availability features.

.. image:: https://img.shields.io/badge/tests-152%20passing-brightgreen
   :alt: Tests

.. image:: https://img.shields.io/badge/python-3.9%2B-blue
   :alt: Python Version

.. image:: https://img.shields.io/badge/license-MIT-blue
   :alt: License

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   concepts
   python_usage
   rest_api
   configuration
   security
   encryption
   audit_logging

.. toctree::
   :maxdepth: 2
   :caption: Deployment

   deployment
   production

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/authorization
   api/client
   api/service
   api/database
   api/models

.. toctree::
   :maxdepth: 2
   :caption: Additional Resources

   troubleshooting
   examples
   changelog
   contributing


About Auth
----------

Auth is a comprehensive, production-ready authorization system designed for enterprise applications. It provides a robust foundation for managing user permissions, roles, and access control with both REST API and Python library interfaces.

Key Features
------------

**Core Features:**

- **Role-Based Access Control (RBAC)** - Hierarchical user, role, and permission management
- **Multiple Storage Backends** - SQLite (development) and PostgreSQL (production)
- **Dual Interface** - REST API and Python library
- **JWT Authentication** - Secure token-based authentication
- **Data Encryption** - Optional encryption for sensitive data fields
- **Audit Logging** - Comprehensive audit trail for compliance
- **Workflow Permissions** - APScheduler integration for workflow permission checking

**Security Features:**

- UUID4-based client authentication
- JWT token-based authorization
- **Deterministic field-level encryption** (AES-256-CTR) - Queryable encrypted data
- Comprehensive audit logging with timestamps
- Input validation and sanitization
- CORS configuration

**Production Features:**

- Connection pooling with retry logic
- Circuit breaker pattern for fault tolerance
- Configurable CORS settings
- Health check endpoint
- Consistent API response formats
- Extensive test coverage (152 tests)

Quick Example
-------------

Python Library Usage:

.. code-block:: python

   import uuid
   from auth import Authorization

   # Generate a client key
   client_key = str(uuid.uuid4())

   # Create authorization instance
   auth = Authorization(client_key)

   # Create roles
   auth.add_role('admin', description='Administrator role')
   auth.add_role('editor', description='Content editor role')

   # Add permissions
   auth.add_permission('admin', 'manage_users')
   auth.add_permission('editor', 'edit_content')

   # Add users to roles
   auth.add_membership('alice@example.com', 'admin')
   auth.add_membership('bob@example.com', 'editor')

   # Check permissions
   if auth.user_has_permission('alice@example.com', 'manage_users'):
       print("Alice can manage users")


REST API Usage:

.. code-block:: bash

   # Create a role
   CLIENT_KEY=$(uuidgen)
   curl -X POST \
     http://localhost:5000/api/role/admin \
     -H "Authorization: Bearer $CLIENT_KEY"

   # Add permission to role
   curl -X POST \
     http://localhost:5000/api/permission/admin/manage_users \
     -H "Authorization: Bearer $CLIENT_KEY"

   # Check user permission
   curl -X GET \
     http://localhost:5000/api/has_permission/alice@example.com/manage_users \
     -H "Authorization: Bearer $CLIENT_KEY"


Why Auth?
---------

**Production-Ready**
  Built with enterprise requirements in mind, featuring comprehensive error handling, audit logging, and extensive test coverage.

**Flexible Deployment**
  Use as a standalone REST API service or integrate directly into your Python application as a library.

**Security First**
  Multiple layers of security including JWT authentication, field-level encryption, and comprehensive audit trails.

**High Availability**
  Circuit breaker pattern, connection pooling, and PostgreSQL support for production deployments.

**Developer Friendly**
  Clean API design, comprehensive documentation, and extensive examples make integration straightforward.


Use Cases
---------

- **Web Applications** - Secure user access control and role management
- **Microservices** - Centralized authorization service for distributed systems
- **Workflow Engines** - APScheduler integration for workflow-based permissions
- **Compliance** - Comprehensive audit logging for regulatory requirements
- **Multi-tenant Applications** - Client-based isolation and permission management


Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
