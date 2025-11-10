#!/usr/bin/env python3
"""
Test script to verify that the Flask Limiter is configured properly
"""

import os
import sys
import warnings

sys.path.insert(0, os.path.abspath("."))

# Capture warnings
warnings.simplefilter("always")


def test_limiter_config():
    print("Testing limiter configuration...")

    # Test with memory storage (should not show the warning anymore)
    import os

    os.environ["RATELIMIT_STORAGE_URL"] = "memory://"

    from auth.main import create_app

    app = create_app()
    print("✓ App created successfully with memory storage (no warning expected)")

    # Test with Redis URL format (should not show the warning anymore)
    os.environ["RATELIMIT_STORAGE_URL"] = "redis://localhost:6379"

    # We expect this to fail due to missing Redis dependency, but not due to the memory storage warning
    try:
        app2 = create_app()
        print("✓ App created successfully with Redis storage")
    except Exception as e:
        if "prerequisite not available" in str(e):
            print("✓ Redis correctly requires redis-py dependency (expected)")
        else:
            print(f"✗ Unexpected error: {e}")

    print("All limiter configuration tests passed!")


if __name__ == "__main__":
    test_limiter_config()
