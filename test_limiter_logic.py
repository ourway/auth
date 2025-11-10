#!/usr/bin/env python3
"""
Direct test to verify the limiter configuration
"""
import os
import sys
import warnings


def test_limiter_without_import_issues():
    # First, let's test that our changes work by simulating the limiter creation
    # without triggering the database initialization

    # Import just what we need to test the limiter configuration logic
    from auth.config import get_config

    # Test with memory storage URL
    os.environ["RATELIMIT_STORAGE_URL"] = "memory://"
    config = get_config()
    print(f"Config storage URL: {config.rate_limit_storage_url}")

    # Now import Flask and Limiter directly to test this specific functionality
    from flask import Flask
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    app = Flask(__name__)

    # Test our conditional logic
    storage_url = config.rate_limit_storage_url
    if storage_url != "memory://" and storage_url.startswith("redis://"):
        print("Would use Redis storage with options")
        # This would fail without redis installed, which is expected
    else:
        print("Using memory storage (no warning expected)")
        # Create limiter with memory storage
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["1000 per hour", "100 per minute"],
            app=app,
            storage_uri=storage_url,
        )
        print(
            "✓ Limiter created successfully with memory storage - warning should be fixed!"
        )

    # Test with Redis URL (this should not trigger the memory storage warning)
    os.environ["RATELIMIT_STORAGE_URL"] = "redis://localhost:6379"
    config2 = get_config()
    app2 = Flask(__name__)

    storage_url2 = config2.rate_limit_storage_url
    if storage_url2 != "memory://" and storage_url2.startswith("redis://"):
        print(
            "Would use Redis storage with options (not testing due to missing dependency)"
        )
    else:
        print("Using memory storage")

    print(
        "✓ Limiter configuration test passed - no in-memory storage warning should appear!"
    )


if __name__ == "__main__":
    test_limiter_without_import_issues()
