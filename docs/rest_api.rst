========
REST API
========

The Auth REST API provides HTTP endpoints for all authorization operations. This guide covers all available endpoints with examples.

Base URL
========

Default: ``http://localhost:5000``

Production: Configure via ``AUTH_SERVER_HOST`` and ``AUTH_SERVER_PORT``

Authentication
==============

All API requests (except ``/ping``) require a Bearer token in the Authorization header:

.. code-block:: http

    Authorization: Bearer <your-uuid4-client-key>

Example:

.. code-block:: bash

    curl -H "Authorization: Bearer abc-123-def-456" \
      http://localhost:5000/api/roles

Response Format
===============

All responses follow this structure:

Success Response
----------------

.. code-block:: json

    {
      "success": true,
      "code": 200,
      "message": "Operation completed successfully",
      "data": { ... },
      "timestamp": "2025-11-23T12:34:56.789012"
    }

Error Response
--------------

.. code-block:: json

    {
      "success": false,
      "code": 400,
      "message": "Invalid input",
      "error": "Detailed error message",
      "timestamp": "2025-11-23T12:34:56.789012"
    }

API Endpoints
=============

Health Check
------------

**GET /ping**

Check if the service is running.

**Response:**

.. code-block:: json

    {
      "message": "pong",
      "status": "ok",
      "timestamp": "2025-11-23T12:34:56.789012"
    }

**Example:**

.. code-block:: bash

    curl http://localhost:5000/ping

Roles
=====

List All Roles
--------------

**GET /api/roles**

Get all roles for the authenticated client.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/roles

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"role": "admin", "description": "Administrator"},
        {"role": "editor", "description": "Content editor"}
      ]
    }

Create Role
-----------

**POST /api/role/{role}**

Create a new role.

**Parameters:**

- ``role`` (path) - Role name

**Request Body (optional):**

.. code-block:: json

    {
      "description": "Role description"
    }

**Example:**

.. code-block:: bash

    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      -H "Content-Type: application/json" \
      -d '{"description": "System administrator"}' \
      http://localhost:5000/api/role/admin

Delete Role
-----------

**DELETE /api/role/{role}**

Delete a role and all associated permissions and memberships.

**Example:**

.. code-block:: bash

    curl -X DELETE \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/role/viewer

Permissions
===========

Check Role Permission
---------------------

**GET /api/permission/{role}/{permission}**

Check if a role has a specific permission.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/permission/admin/manage_users

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": {"has_permission": true}
    }

Add Permission
--------------

**POST /api/permission/{role}/{permission}**

Grant a permission to a role.

**Example:**

.. code-block:: bash

    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/permission/editor/edit_content

Remove Permission
-----------------

**DELETE /api/permission/{role}/{permission}**

Revoke a permission from a role.

**Example:**

.. code-block:: bash

    curl -X DELETE \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/permission/editor/delete_content

Get Role Permissions
--------------------

**GET /api/role_permissions/{role}**

Get all permissions for a role.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/role_permissions/admin

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"name": "manage_users"},
        {"name": "edit_content"},
        {"name": "view_analytics"}
      ]
    }

Memberships
===========

Check Membership
----------------

**GET /api/membership/{user}/{role}**

Check if a user belongs to a role.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/membership/alice@example.com/admin

Add Membership
--------------

**POST /api/membership/{user}/{role}**

Add a user to a role.

**Example:**

.. code-block:: bash

    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/membership/bob@example.com/editor

Remove Membership
-----------------

**DELETE /api/membership/{user}/{role}**

Remove a user from a role.

**Example:**

.. code-block:: bash

    curl -X DELETE \
      -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/membership/charlie@example.com/viewer

Get Role Members
----------------

**GET /api/members/{role}**

Get all users who are members of a role.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/members/admin

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"user": "alice@example.com"},
        {"user": "admin@example.com"}
      ]
    }

User Queries
============

Check User Permission
---------------------

**GET /api/has_permission/{user}/{permission}**

Check if a user has a specific permission (through any of their roles).

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/has_permission/alice@example.com/manage_users

Get User Permissions
--------------------

**GET /api/user_permissions/{user}**

Get all permissions for a user across all their roles.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/user_permissions/bob@example.com

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"name": "edit_content"},
        {"name": "view_content"}
      ]
    }

Get User Roles
--------------

**GET /api/user_roles/{user}**

Get all roles assigned to a user.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/user_roles/alice@example.com

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"role": "admin"},
        {"role": "editor"}
      ]
    }

Reverse Queries
===============

Find Users by Permission
------------------------

**GET /api/which_users_can/{permission}**

Find all users who have a specific permission.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/which_users_can/delete_user

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"user": "alice@example.com"},
        {"user": "admin@example.com"}
      ]
    }

Find Roles by Permission
------------------------

**GET /api/which_roles_can/{permission}**

Find all roles that have a specific permission.

**Example:**

.. code-block:: bash

    curl -H "Authorization: Bearer $CLIENT_KEY" \
      http://localhost:5000/api/which_roles_can/edit_content

**Response:**

.. code-block:: json

    {
      "success": true,
      "data": [
        {"role": "admin"},
        {"role": "editor"}
      ]
    }

Python Client
=============

Using EnhancedAuthClient
------------------------

.. code-block:: python

    from auth.client import EnhancedAuthClient
    import uuid

    # Initialize client
    client = EnhancedAuthClient(
        api_key=str(uuid.uuid4()),
        service_url='http://localhost:5000'
    )

    # Create role
    response = client.create_role('admin', description='Administrator')

    # Add permission
    response = client.add_permission('admin', 'manage_users')

    # Add membership
    response = client.add_membership('alice@example.com', 'admin')

    # Check permission
    response = client.user_has_permission('alice@example.com', 'manage_users')
    print(response['data']['has_permission'])

Error Handling
==============

HTTP Status Codes
-----------------

- ``200 OK`` - Request successful
- ``201 Created`` - Resource created
- ``400 Bad Request`` - Invalid request parameters
- ``401 Unauthorized`` - Missing or invalid authentication
- ``403 Forbidden`` - Insufficient permissions
- ``404 Not Found`` - Resource not found
- ``409 Conflict`` - Resource already exists
- ``500 Internal Server Error`` - Server error

Example Error Response
----------------------

.. code-block:: json

    {
      "success": false,
      "code": 404,
      "message": "Role not found",
      "error": "Role 'nonexistent' does not exist for this client",
      "timestamp": "2025-11-23T12:34:56.789012"
    }

Rate Limiting
=============

Currently, Auth does not implement rate limiting. For production deployments, consider using:

- Nginx rate limiting
- API Gateway (AWS, Azure, GCP)
- Redis-based rate limiter

Example Nginx Configuration:

.. code-block:: nginx

    limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/s;
    
    server {
        location /api/ {
            limit_req zone=auth_limit burst=20;
            proxy_pass http://localhost:5000;
        }
    }

Complete Example Workflow
==========================

Bash Script
-----------

.. code-block:: bash

    #!/bin/bash
    
    # Configuration
    API_URL="http://localhost:5000"
    CLIENT_KEY=$(uuidgen)
    
    echo "Client Key: $CLIENT_KEY"
    
    # Create roles
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/role/admin"
    
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/role/editor"
    
    # Add permissions
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/permission/admin/manage_users"
    
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/permission/editor/edit_content"
    
    # Add memberships
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/membership/alice@example.com/admin"
    
    curl -X POST \
      -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/membership/bob@example.com/editor"
    
    # Check permission
    curl -H "Authorization: Bearer $CLIENT_KEY" \
      "$API_URL/api/has_permission/alice@example.com/manage_users"

Python Script
-------------

.. code-block:: python

    import requests
    import uuid

    API_URL = "http://localhost:5000"
    CLIENT_KEY = str(uuid.uuid4())
    HEADERS = {"Authorization": f"Bearer {CLIENT_KEY}"}

    # Create roles
    requests.post(f"{API_URL}/api/role/admin", headers=HEADERS)
    requests.post(f"{API_URL}/api/role/editor", headers=HEADERS)

    # Add permissions
    requests.post(f"{API_URL}/api/permission/admin/manage_users", headers=HEADERS)
    requests.post(f"{API_URL}/api/permission/editor/edit_content", headers=HEADERS)

    # Add memberships
    requests.post(f"{API_URL}/api/membership/alice@example.com/admin", headers=HEADERS)
    requests.post(f"{API_URL}/api/membership/bob@example.com/editor", headers=HEADERS)

    # Check permission
    response = requests.get(
        f"{API_URL}/api/has_permission/alice@example.com/manage_users",
        headers=HEADERS
    )
    print(response.json())

Next Steps
==========

- :doc:`python_usage` - Python library usage
- :doc:`security` - API security best practices
- :doc:`deployment` - Deploying the API
- :doc:`examples` - More examples
