============
Contributing
============

We welcome contributions to Auth!

Development Setup
=================

.. code-block:: bash

    # Clone repository
    git clone https://github.com/rodmena-limited/auth.git
    cd auth

    # Create virtual environment
    python -m venv venv
    source venv/bin/activate

    # Install development dependencies
    pip install -e .[dev]

Running Tests
=============

.. code-block:: bash

    # Run all tests
    pytest tests/ -v

    # Run with coverage
    pytest tests/ --cov=auth --cov-report=html

    # Run specific tests
    pytest tests/test_authorization_sqlite.py -v

Code Style
==========

We use:

- Black for formatting
- Ruff for linting
- MyPy for type checking

.. code-block:: bash

    # Format code
    black auth/

    # Lint
    ruff check auth/

    # Type check
    mypy auth/

Pull Requests
=============

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run tests and linting
6. Submit pull request

License
=======

MIT License - see LICENSE file.

Contact
=======

Farshid Ashouri - farsheed.ashouri@gmail.com
RODMENA LIMITED
