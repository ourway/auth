"""
Flask application setup
"""

from flask import Flask
from flask_cors import CORS

from auth.audit import setup_audit_tables
from auth.database import create_tables
from auth.workflow_checker import initialize_workflow_checker


def create_app():
    # Create Flask app
    app = Flask(__name__)

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

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    app.run()
