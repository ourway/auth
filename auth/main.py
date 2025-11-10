"""
Flask application setup
"""

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from auth.audit import setup_audit_tables
from auth.database import create_tables
from auth.workflow_checker import initialize_workflow_checker


def create_app():
    # Create Flask app
    app = Flask(__name__)

    # Configure rate limiting
    app.config.setdefault("RATELIMIT_STORAGE_URL", "memory://")

    # Initialize rate limiter
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute"],
    )

    # Enable CORS
    CORS(app)

    # Create tables on startup
    with app.app_context():
        create_tables()
        setup_audit_tables()  # Set up audit tables
        initialize_workflow_checker()  # Initialize workflow permission checker

    # Import and register routes
    from auth.routes import register_routes

    register_routes(app)

    # Apply rate limiting to API endpoints
    from auth import routes

    limiter.limit("500 per hour")(routes.check_membership)
    limiter.limit("500 per hour")(routes.check_permission)
    limiter.limit("500 per hour")(routes.check_user_permission)
    limiter.limit("200 per hour")(routes.add_membership)
    limiter.limit("200 per hour")(routes.remove_membership)
    limiter.limit("200 per hour")(routes.add_permission)
    limiter.limit("200 per hour")(routes.remove_permission)
    limiter.limit("500 per hour")(routes.get_user_permissions)
    limiter.limit("500 per hour")(routes.get_role_permissions)
    limiter.limit("500 per hour")(routes.get_user_roles)
    limiter.limit("500 per hour")(routes.get_role_members)
    limiter.limit("500 per hour")(routes.list_roles)
    limiter.limit("500 per hour")(routes.which_roles_can)
    limiter.limit("500 per hour")(routes.which_users_can)
    limiter.limit("200 per hour")(routes.create_role)
    limiter.limit("200 per hour")(routes.delete_role)

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    app.run()
