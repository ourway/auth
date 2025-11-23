===========
Quick Start
===========

This guide will get you up and running with Auth in minutes.

Starting the Server
===================

Development Mode (SQLite)
--------------------------

Start the server with default settings:

.. code-block:: bash

    python -m auth.main

The server will start on ``http://127.0.0.1:5000`` using an SQLite database.

Production Mode (PostgreSQL)
-----------------------------

Configure environment variables and start:

.. code-block:: bash

    export AUTH_DATABASE_TYPE=postgresql
    export AUTH_POSTGRESQL_URL=postgresql://username:password@localhost:5432/auth_db
    export AUTH_JWT_SECRET_KEY=your_secure_secret_key
    export AUTH_ENABLE_ENCRYPTION=true
    export AUTH_ENCRYPTION_KEY=your_encryption_key

    python -m auth.main

Python Library Usage
====================

Basic RBAC Example
------------------

.. code-block:: python

    import uuid
    from auth import Authorization

    # Generate a client key (UUID4)
    client_key = str(uuid.uuid4())

    # Create authorization instance
    auth = Authorization(client_key)

    # Create roles
    auth.add_role('admin', description='Administrator role')
    auth.add_role('editor', description='Content editor role')
    auth.add_role('viewer', description='Read-only role')

    # Add permissions to roles
    auth.add_permission('admin', 'manage_users')
    auth.add_permission('admin', 'edit_content')
    auth.add_permission('admin', 'view_content')
    auth.add_permission('editor', 'edit_content')
    auth.add_permission('editor', 'view_content')
    auth.add_permission('viewer', 'view_content')

    # Add users to roles
    auth.add_membership('alice@example.com', 'admin')
    auth.add_membership('bob@example.com', 'editor')
    auth.add_membership('charlie@example.com', 'viewer')

Checking Permissions
--------------------

.. code-block:: python

    # Check if user has specific permission
    if auth.user_has_permission('alice@example.com', 'manage_users'):
        print("Alice can manage users")

    # Check if user belongs to a role
    if auth.has_membership('bob@example.com', 'editor'):
        print("Bob is an editor")

    # Check if role has permission
    if auth.has_permission('viewer', 'view_content'):
        print("Viewers can view content")

Querying User Information
--------------------------

.. code-block:: python

    # Get all permissions for a user
    permissions = auth.get_user_permissions('alice@example.com')
    print(f"Alice's permissions: {[p['name'] for p in permissions]}")

    # Get all roles for a user
    roles = auth.get_user_roles('bob@example.com')
    print(f"Bob's roles: {[r['role'] for r in roles]}")

    # Get all users with a specific permission
    users = auth.which_users_can('edit_content')
    print(f"Users who can edit: {[u['user'] for u in users]}")

    # Get all roles with a specific permission
    roles = auth.which_roles_can('manage_users')
    print(f"Roles that can manage users: {[r['role'] for r in roles]}")

Querying Role Information
--------------------------

.. code-block:: python

    # Get all members of a role
    members = auth.get_role_members('admin')
    print(f"Admin users: {[m['user'] for m in members]}")

    # Get all permissions for a role
    permissions = auth.get_permissions('editor')
    print(f"Editor permissions: {[p['name'] for p in permissions]}")

    # Get all roles
    all_roles = auth.roles
    print(f"All roles: {[r['role'] for r in all_roles]}")

Modifying Permissions and Memberships
--------------------------------------

.. code-block:: python

    # Remove permission from role
    auth.del_permission('editor', 'edit_content')

    # Remove user from role
    auth.del_membership('charlie@example.com', 'viewer')

    # Delete role (also removes all memberships and permissions)
    auth.del_role('viewer')

REST API Usage
==============

Using cURL
----------

Set up your client key:

.. code-block:: bash

    CLIENT_KEY=$(uuidgen)
    echo "Your client key: $CLIENT_KEY"

Health Check:

.. code-block:: bash

    curl http://localhost:5000/ping

Create a Role:

.. code-block:: bash

    curl -X POST \
      http://localhost:5000/api/role/admin \
      -H "Authorization: Bearer $CLIENT_KEY" \
      -H "Content-Type: application/json"

Add Permission to Role:

.. code-block:: bash

    curl -X POST \
      http://localhost:5000/api/permission/admin/manage_users \
      -H "Authorization: Bearer $CLIENT_KEY" \
      -H "Content-Type: application/json"

Add User to Role:

.. code-block:: bash

    curl -X POST \
      http://localhost:5000/api/membership/alice@example.com/admin \
      -H "Authorization: Bearer $CLIENT_KEY" \
      -H "Content-Type: application/json"

Check User Permission:

.. code-block:: bash

    curl -X GET \
      http://localhost:5000/api/has_permission/alice@example.com/manage_users \
      -H "Authorization: Bearer $CLIENT_KEY"

Get User Permissions:

.. code-block:: bash

    curl -X GET \
      http://localhost:5000/api/user_permissions/alice@example.com \
      -H "Authorization: Bearer $CLIENT_KEY"

Using Python Client
-------------------

.. code-block:: python

    import uuid
    from auth.client import EnhancedAuthClient

    # Generate a client key
    client_key = str(uuid.uuid4())

    # Create client instance
    client = EnhancedAuthClient(
        api_key=client_key,
        service_url='http://127.0.0.1:5000'
    )

    # Create a role
    response = client.create_role('admin')
    print(response)

    # Add permission to role
    response = client.add_permission('admin', 'manage_users')
    print(response)

    # Add user to role
    response = client.add_membership('alice@example.com', 'admin')
    print(response)

    # Check user permission
    response = client.user_has_permission('alice@example.com', 'manage_users')
    print(response)

Complete Example
================

Here's a complete example demonstrating a typical workflow:

.. code-block:: python

    import uuid
    from auth import Authorization

    # Initialize
    client_key = str(uuid.uuid4())
    auth = Authorization(client_key)

    # Set up roles and permissions
    auth.add_role('admin', description='Full system access')
    auth.add_role('manager', description='Department management')
    auth.add_role('employee', description='Basic access')

    # Admin permissions
    auth.add_permission('admin', 'create_user')
    auth.add_permission('admin', 'delete_user')
    auth.add_permission('admin', 'view_reports')
    auth.add_permission('admin', 'edit_data')

    # Manager permissions
    auth.add_permission('manager', 'view_reports')
    auth.add_permission('manager', 'edit_data')

    # Employee permissions
    auth.add_permission('employee', 'view_reports')

    # Assign roles to users
    auth.add_membership('admin@company.com', 'admin')
    auth.add_membership('manager@company.com', 'manager')
    auth.add_membership('employee@company.com', 'employee')

    # Check permissions in your application
    def can_create_user(user_email):
        return auth.user_has_permission(user_email, 'create_user')

    def can_view_reports(user_email):
        return auth.user_has_permission(user_email, 'view_reports')

    # Usage
    if can_create_user('admin@company.com'):
        print("Admin can create users")

    if can_view_reports('employee@company.com'):
        print("Employee can view reports")

    # Get audit information
    print(f"All admins: {auth.get_role_members('admin')}")
    print(f"Manager permissions: {auth.get_permissions('manager')}")

Running the Showcase Script
============================

The repository includes a showcase script that demonstrates all API features:

.. code-block:: bash

    bash showcase_api.sh

This script will:

1. Start the Auth server
2. Create roles (admin, editor, viewer)
3. Add permissions to each role
4. Add users to roles
5. Demonstrate permission checks
6. Show audit queries

Next Steps
==========

Now that you're familiar with the basics, explore:

- :doc:`python_usage` - Detailed Python library documentation
- :doc:`rest_api` - Complete REST API reference
- :doc:`configuration` - Configuration options
- :doc:`security` - Security best practices
- :doc:`examples` - More advanced examples
