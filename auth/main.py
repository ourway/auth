"""
Flask application setup
"""

from flask import Flask
from flask_cors import CORS

from auth.database import create_tables


def create_app():
    # Create Flask app
    app = Flask(__name__)

    # Enable CORS
    CORS(app)

    # Create tables on startup
    with app.app_context():
        create_tables()

    # Import and register routes
    from auth.routes import register_routes

    register_routes(app)

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    app.run()
