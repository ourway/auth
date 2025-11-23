=============
Python Usage
=============

This guide covers the Python library interface for Auth, providing detailed examples and best practices.

Basic Usage
===========

Initialization
--------------

.. code-block:: python

    import uuid
    from auth import Authorization

    # Generate a unique client key
    client_key = str(uuid.uuid4())

    # Create an Authorization instance
    auth = Authorization(client_key)

The client key isolates your authorization scope from other applications using the same Auth instance.

Working with Roles
==================

Creating Roles
--------------

.. code-block:: python

    # Create a role with description
    auth.add_role('admin', description='System administrator')
    auth.add_role('editor', description='Content editor')
    auth.add_role('viewer', description='Read-only access')

    # Create role without description
    auth.add_role('moderator')

Listing Roles
-------------

.. code-block:: python

    # Get all roles for this client
    roles = auth.roles
    for role in roles:
        print(f"Role: {role['role']}, Description: {role.get('description', 'N/A')}")

Deleting Roles
--------------

.. code-block:: python

    # Delete a role (also removes all memberships and permissions)
    success = auth.del_role('viewer')
    if success:
        print("Role deleted successfully")

Working with Permissions
=========================

Adding Permissions
------------------

.. code-block:: python

    # Add permissions to roles
    auth.add_permission('admin', 'create_user')
    auth.add_permission('admin', 'delete_user')
    auth.add_permission('admin', 'edit_settings')
    
    auth.add_permission('editor', 'create_post')
    auth.add_permission('editor', 'edit_post')
    auth.add_permission('editor', 'delete_post')
    
    auth.add_permission('viewer', 'view_content')

Checking Role Permissions
--------------------------

.. code-block:: python

    # Check if a role has a specific permission
    if auth.has_permission('editor', 'edit_post'):
        print("Editors can edit posts")

Listing Role Permissions
-------------------------

.. code-block:: python

    # Get all permissions for a role
    permissions = auth.get_permissions('admin')
    print(f"Admin permissions: {[p['name'] for p in permissions]}")

Removing Permissions
--------------------

.. code-block:: python

    # Remove a permission from a role
    success = auth.del_permission('editor', 'delete_post')
    if success:
        print("Permission removed")

Working with Memberships
=========================

Adding Users to Roles
---------------------

.. code-block:: python

    # Add users to roles
    auth.add_membership('alice@example.com', 'admin')
    auth.add_membership('bob@example.com', 'editor')
    auth.add_membership('charlie@example.com', 'viewer')
    
    # Users can have multiple roles
    auth.add_membership('alice@example.com', 'editor')

Checking Memberships
--------------------

.. code-block:: python

    # Check if a user belongs to a role
    if auth.has_membership('bob@example.com', 'editor'):
        print("Bob is an editor")

Listing Role Members
--------------------

.. code-block:: python

    # Get all members of a role
    members = auth.get_role_members('admin')
    print(f"Admins: {[m['user'] for m in members]}")

Removing Memberships
--------------------

.. code-block:: python

    # Remove a user from a role
    success = auth.del_membership('charlie@example.com', 'viewer')
    if success:
        print("Membership removed")

Permission Checking
===================

User Permission Checks
----------------------

.. code-block:: python

    # Check if a user has a specific permission
    if auth.user_has_permission('alice@example.com', 'create_user'):
        # Allow the operation
        create_new_user()
    else:
        # Deny access
        raise PermissionError("Insufficient permissions")

User Queries
------------

.. code-block:: python

    # Get all roles for a user
    user_roles = auth.get_user_roles('bob@example.com')
    print(f"Bob's roles: {[r['role'] for r in user_roles]}")
    
    # Get all permissions for a user
    user_permissions = auth.get_user_permissions('alice@example.com')
    print(f"Alice's permissions: {[p['name'] for p in user_permissions]}")

Reverse Queries
---------------

.. code-block:: python

    # Find all users with a specific permission
    users_can_delete = auth.which_users_can('delete_user')
    print(f"Users who can delete: {[u['user'] for u in users_can_delete]}")
    
    # Find all roles with a specific permission
    roles_can_edit = auth.which_roles_can('edit_post')
    print(f"Roles that can edit: {[r['role'] for r in roles_can_edit]}")

Advanced Usage
==============

Decorator Pattern
-----------------

Create decorators for permission checking:

.. code-block:: python

    from functools import wraps
    from auth import Authorization
    
    # Initialize auth instance
    auth = Authorization(client_key)
    
    def require_permission(permission):
        """Decorator to check if user has permission"""
        def decorator(func):
            @wraps(func)
            def wrapper(user_email, *args, **kwargs):
                if not auth.user_has_permission(user_email, permission):
                    raise PermissionError(f"User lacks permission: {permission}")
                return func(user_email, *args, **kwargs)
            return wrapper
        return decorator
    
    # Usage
    @require_permission('delete_user')
    def delete_user(user_email, target_user_id):
        # This only executes if user has permission
        print(f"{user_email} is deleting user {target_user_id}")

Context Manager Pattern
-----------------------

.. code-block:: python

    from contextlib import contextmanager
    
    @contextmanager
    def permission_context(user_email, permission):
        """Context manager for permission checking"""
        if not auth.user_has_permission(user_email, permission):
            raise PermissionError(f"User lacks permission: {permission}")
        yield
    
    # Usage
    try:
        with permission_context('alice@example.com', 'edit_settings'):
            # This code only runs if Alice has permission
            update_system_settings()
    except PermissionError as e:
        print(f"Access denied: {e}")

Bulk Operations
---------------

.. code-block:: python

    # Add multiple permissions to a role
    admin_permissions = [
        'create_user', 'delete_user', 'edit_user',
        'create_role', 'delete_role', 'edit_role',
        'view_logs', 'edit_settings'
    ]
    
    for permission in admin_permissions:
        auth.add_permission('admin', permission)
    
    # Add multiple users to a role
    admin_users = [
        'admin1@example.com',
        'admin2@example.com',
        'admin3@example.com'
    ]
    
    for user in admin_users:
        auth.add_membership(user, 'admin')

Database Session Management
============================

Custom Database Session
-----------------------

.. code-block:: python

    from auth import Authorization
    from auth.database import SessionLocal
    
    # Create your own database session
    db_session = SessionLocal()
    
    try:
        # Use the session with Authorization
        auth = Authorization(client_key, db_session=db_session)
        
        # Perform operations
        auth.add_role('custom_role')
        
        # Commit changes
        db_session.commit()
    except Exception as e:
        # Rollback on error
        db_session.rollback()
        raise
    finally:
        # Close session
        db_session.close()

Transaction Handling
--------------------

.. code-block:: python

    from auth.database import SessionLocal
    from auth.services.service import AuthorizationService
    
    def setup_new_department(dept_name, manager_email, members):
        """Set up a new department with roles and members"""
        db = SessionLocal()
        try:
            service = AuthorizationService(db, client_key)
            
            # Create roles
            service.add_role(f'{dept_name}_manager')
            service.add_role(f'{dept_name}_member')
            
            # Add permissions
            service.add_permission(f'{dept_name}_manager', 'approve_requests')
            service.add_permission(f'{dept_name}_manager', 'view_reports')
            service.add_permission(f'{dept_name}_member', 'view_reports')
            
            # Add members
            service.add_membership(manager_email, f'{dept_name}_manager')
            for member in members:
                service.add_membership(member, f'{dept_name}_member')
            
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            print(f"Error setting up department: {e}")
            return False
        finally:
            db.close()

Real-World Examples
===================

Example 1: Web Application
--------------------------

.. code-block:: python

    from flask import Flask, request, jsonify
    from auth import Authorization
    import uuid
    
    app = Flask(__name__)
    auth = Authorization(str(uuid.uuid4()))
    
    # Setup roles and permissions
    auth.add_role('admin')
    auth.add_role('user')
    auth.add_permission('admin', 'manage_users')
    auth.add_permission('admin', 'view_analytics')
    auth.add_permission('user', 'view_profile')
    
    def get_current_user():
        """Get current user from session/token"""
        return request.headers.get('X-User-Email')
    
    @app.route('/api/users', methods=['POST'])
    def create_user():
        current_user = get_current_user()
        
        if not auth.user_has_permission(current_user, 'manage_users'):
            return jsonify({'error': 'Permission denied'}), 403
        
        # Create user logic
        return jsonify({'message': 'User created'}), 201
    
    @app.route('/api/analytics')
    def view_analytics():
        current_user = get_current_user()
        
        if not auth.user_has_permission(current_user, 'view_analytics'):
            return jsonify({'error': 'Permission denied'}), 403
        
        # Return analytics
        return jsonify({'data': 'analytics data'})

Example 2: CLI Tool
-------------------

.. code-block:: python

    import click
    from auth import Authorization
    import uuid
    
    auth = Authorization(str(uuid.uuid4()))
    
    @click.group()
    def cli():
        """User management CLI"""
        pass
    
    @cli.command()
    @click.option('--user', required=True)
    @click.option('--permission', required=True)
    def check(user, permission):
        """Check if user has permission"""
        if auth.user_has_permission(user, permission):
            click.echo(f"✓ {user} has permission: {permission}")
        else:
            click.echo(f"✗ {user} lacks permission: {permission}")
    
    @cli.command()
    @click.option('--user', required=True)
    def show(user):
        """Show user roles and permissions"""
        roles = auth.get_user_roles(user)
        permissions = auth.get_user_permissions(user)
        
        click.echo(f"\nUser: {user}")
        click.echo(f"Roles: {', '.join(r['role'] for r in roles)}")
        click.echo(f"Permissions: {', '.join(p['name'] for p in permissions)}")
    
    if __name__ == '__main__':
        cli()

Example 3: Background Jobs
---------------------------

.. code-block:: python

    from apscheduler.schedulers.background import BackgroundScheduler
    from auth import Authorization
    import uuid
    
    auth = Authorization(str(uuid.uuid4()))
    
    def process_reports(user_email):
        """Background job to process reports"""
        if not auth.user_has_permission(user_email, 'generate_reports'):
            print(f"User {user_email} lacks permission for report generation")
            return
        
        print(f"Processing reports for {user_email}...")
        # Report generation logic
    
    # Schedule jobs
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=lambda: process_reports('admin@example.com'),
        trigger='cron',
        hour=9,
        minute=0
    )
    scheduler.start()

Best Practices
==============

1. **Always use UUID4 for client keys**

   .. code-block:: python

       import uuid
       client_key = str(uuid.uuid4())  # ✓ Good
       client_key = "my-app"           # ✗ Bad

2. **Cache authorization checks when appropriate**

   .. code-block:: python

       from functools import lru_cache
       
       @lru_cache(maxsize=128)
       def cached_permission_check(user, permission):
           return auth.user_has_permission(user, permission)

3. **Use descriptive role and permission names**

   .. code-block:: python

       # Good
       auth.add_role('content_editor')
       auth.add_permission('content_editor', 'edit_articles')
       
       # Bad
       auth.add_role('role1')
       auth.add_permission('role1', 'action1')

4. **Handle exceptions gracefully**

   .. code-block:: python

       try:
           auth.add_role('admin')
       except Exception as e:
           logger.error(f"Failed to create role: {e}")
           # Handle error appropriately

5. **Close database sessions properly**

   .. code-block:: python

       from contextlib import contextmanager
       from auth.database import SessionLocal
       
       @contextmanager
       def get_db_session():
           session = SessionLocal()
           try:
               yield session
               session.commit()
           except:
               session.rollback()
               raise
           finally:
               session.close()

Next Steps
==========

- :doc:`rest_api` - REST API usage
- :doc:`examples` - More examples
- :doc:`security` - Security best practices
- :doc:`troubleshooting` - Common issues
