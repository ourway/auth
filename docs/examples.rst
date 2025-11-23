========
Examples
========

This page provides real-world examples of using Auth.

Web Application Example
=======================

Flask Integration
-----------------

.. code-block:: python

    from flask import Flask, request, jsonify, g
    from functools import wraps
    from auth import Authorization
    import uuid

    app = Flask(__name__)
    auth = Authorization(str(uuid.uuid4()))

    # Setup roles
    auth.add_role('admin')
    auth.add_role('editor')
    auth.add_role('viewer')

    # Setup permissions
    auth.add_permission('admin', 'manage_users')
    auth.add_permission('admin', 'delete_posts')
    auth.add_permission('editor', 'create_post')
    auth.add_permission('editor', 'edit_post')
    auth.add_permission('viewer', 'view_posts')

    def get_current_user():
        return request.headers.get('X-User-Email')

    def require_permission(permission):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                user = get_current_user()
                if not auth.user_has_permission(user, permission):
                    return jsonify({'error': 'Permission denied'}), 403
                return f(*args, **kwargs)
            return decorated_function
        return decorator

    @app.route('/api/posts', methods=['POST'])
    @require_permission('create_post')
    def create_post():
        # Create post logic
        return jsonify({'message': 'Post created'}), 201

    @app.route('/api/users', methods=['POST'])
    @require_permission('manage_users')
    def create_user():
        # Create user logic
        return jsonify({'message': 'User created'}), 201

CLI Tool Example
================

.. code-block:: python

    import click
    from auth import Authorization
    import uuid

    auth = Authorization(str(uuid.uuid4()))

    @click.group()
    def cli():
        pass

    @cli.command()
    @click.option('--name', required=True)
    @click.option('--description')
    def create_role(name, description):
        if auth.add_role(name, description):
            click.echo(f"Role '{name}' created")

    @cli.command()
    @click.option('--role', required=True)
    @click.option('--permission', required=True)
    def grant(role, permission):
        if auth.add_permission(role, permission):
            click.echo(f"Granted '{permission}' to '{role}'")

    if __name__ == '__main__':
        cli()

Microservices Example
======================

.. code-block:: python

    from auth.client import EnhancedAuthClient
    import os

    # Centralized auth service
    auth_client = EnhancedAuthClient(
        api_key=os.environ['AUTH_CLIENT_KEY'],
        service_url='http://auth-service:5000'
    )

    def check_permission(user, permission):
        response = auth_client.user_has_permission(user, permission)
        return response['data']['has_permission']

    # Use in your service
    if check_permission('user@example.com', 'process_payment'):
        process_payment()

See :doc:`python_usage` and :doc:`rest_api` for more examples.
