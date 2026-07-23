.PHONY: help install format lint type-check test test-cov test-postgres version-check smoke build publish-test publish clean start-server list-keys start-remote start-remote-docker start-compose stop-compose start-compose-remote

# Pin pytest to the project virtualenv so `make test` / `make test-postgres`
# don't fall back to a system python that lacks the deps. Override if needed,
# e.g. `make test PYTEST=pytest` when the venv is already activated.
VENV ?= .venv
PYTEST ?= $(VENV)/bin/pytest

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@echo
	@grep -E '^[a-zA-Z_0-9%-]+:.*?## .*$$' $(word 1,$(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Install dependencies
install: ## Install project dependencies
	pip install -e .
	pip install -e .[dev]

# Format code with black and isort
format: ## Format code with black and isort
	black .
	isort .

# Lint code with ruff
lint: ## Lint code with ruff
	ruff check .

# Type check with mypy
type-check: ## Check types with mypy
	mypy .

# Run tests
test: ## Run tests with pytest
	$(PYTEST)

# Run tests with coverage
test-cov: ## Run tests with coverage
	$(PYTEST) --cov=auth --cov-report=html --cov-report=term

# PostgreSQL integration tests against a disposable Docker container.
# Runs in a separate pytest process: the engine singleton binds at import.
test-postgres: ## Run PostgreSQL integration tests (Docker required)
	docker run -d --rm --name auth-test-pg \
		-e POSTGRES_USER=auth_test -e POSTGRES_PASSWORD=auth_test \
		-e POSTGRES_DB=auth_test -p 127.0.0.1:55432:5432 postgres:16-alpine
	@until docker exec auth-test-pg pg_isready -U auth_test -q; do sleep 1; done
	AUTH_DATABASE_TYPE=postgresql \
	AUTH_DATABASE_URL="postgresql://auth_test:auth_test@127.0.0.1:55432/auth_test" \
	AUTH_POSTGRESQL_URL= AUTH_SQLITE_PATH= \
	AUTH_DATABASE_SCHEMA=auth_rbac \
	AUTH_ENABLE_ENCRYPTION=true \
	AUTH_ENCRYPTION_KEY=test-pg-encryption-key-1234 \
	AUTH_JWT_SECRET_KEY=test-secret \
	$(PYTEST) tests/postgres/ -m postgres; \
	status=$$?; docker stop auth-test-pg >/dev/null; exit $$status

version-check: ## Assert pyproject, docs/conf.py and changelog agree on the version
	@V=$$(grep -Po '(?<=^version = ")[^"]+' pyproject.toml); \
	grep -q "release = \"$$V\"" docs/conf.py || { echo "docs/conf.py release != $$V"; exit 1; }; \
	grep -q "Version $$V" docs/changelog.rst || { echo "changelog missing entry for $$V"; exit 1; }; \
	echo "version-check OK: $$V"

smoke: ## Build a wheel, install into a fresh venv, run the quick-start
	bash scripts/smoke_install.sh

build: version-check clean-dist ## Build sdist and wheel
	python -m pip install --quiet --upgrade build twine
	python -m build
	python -m twine check dist/*

clean-dist:
	rm -rf dist/ build/ *.egg-info

publish-test: build smoke ## Upload to TestPyPI
	python -m twine upload --repository testpypi dist/*

publish: build smoke ## Upload to PyPI
	python -m twine upload dist/*

# Clean cache files
clean: ## Clean cache files
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf __pycache__/
	rm -rf */__pycache__/
	rm -rf */*/__pycache__/
	rm -rf */*/*/__pycache__/
	rm -rf htmlcov/
	rm -rf .coverage

# Start server
start-server: ## Start the auth server
	python -m auth.server

# Build Docker image
build-docker: ## Build the auth server Docker image
	docker build -t auth-server .

# Start server with Docker
start-docker: ## Build and run the auth server in Docker
	$(MAKE) build-docker
	docker stop auth-server-container || true
	docker rm auth-server-container || true
	docker run -p 4000:4000 --name auth-server-container auth-server

# Stop Docker container
stop-docker: ## Stop the auth server Docker container
	@docker stop auth-server-container 2>/dev/null || echo "Container not running"
	@docker rm auth-server-container 2>/dev/null || echo "Container does not exist"
	@echo "Docker container stopped and removed (if it existed)"

# List keys - example operation to show available API keys/users/roles
list-keys: ## List available API keys or example data
	@echo "This would list available API keys, users, or roles if implemented"
	@echo "Available operations:"
	@echo "  - Add custom command implementations as needed"

# Start server with reTunnel (remote access)
start-remote: ## Start the auth server with reTunnel for remote access
	pip install retunnel
	python -c "from auth.main import app; app.run(host='0.0.0.0', port=11788, threaded=True, debug=False)" & \
	sleep 3 && \
	retunnel http 11788

# Start Docker container with reTunnel (requires local retunnel installation)
start-remote-docker: ## Build and run the auth server in Docker with reTunnel
	docker build -t auth-server .
	docker stop auth-server-container || true
	docker rm auth-server-container || true
	docker run -d -p 4000:4000 --name auth-server-container auth-server
	@echo "Auth server running on port 4000. To expose publicly, run: retunnel http 4000"

# Start all services with docker-compose
start-compose: ## Start auth service with docker-compose
	docker-compose up -d auth

# Stop all services with docker-compose  
stop-compose: ## Stop all services with docker-compose
	docker-compose down

# Start auth service with reTunnel via docker-compose
start-compose-remote: ## Start auth service and provide remote access via reTunnel
	@echo "ERROR: Retunnel service not configured in this approach. Run 'retunnel http 4000' after starting auth service." && false

# Fix lint issues
lint-fix: ## Fix lint issues automatically
	ruff check . --fix

# Run format, lint, and type-check together
check: format lint type-check ## Run format, lint, and type-check
	@echo "All checks passed!"

# Run tests and checks
ci: check test ## Run all checks and tests (for CI)
	@echo "CI checks passed!"
