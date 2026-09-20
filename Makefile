.PHONY: help install format lint type-check test test-cov test-postgres probe-postgres version-check smoke build publish-test publish clean start-server list-keys start-remote start-remote-docker start-compose stop-compose start-compose-remote

# Pin dev tools to the project virtualenv so the make targets don't fall back
# to a system python that lacks the deps. Override any of these if needed,
# e.g. `make test PYTEST=pytest` when the venv is already activated.
VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
PYTEST ?= $(VENV)/bin/pytest
BLACK ?= $(VENV)/bin/black
ISORT ?= $(VENV)/bin/isort
RUFF ?= $(VENV)/bin/ruff
MYPY ?= $(VENV)/bin/mypy

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
	$(BLACK) .
	$(ISORT) .

# Lint code with ruff
lint: ## Lint code with ruff
	$(RUFF) check .

# Type check with mypy
type-check: ## Check types with mypy
	$(MYPY) .

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
	@# The image's init runs a transient server that pg_isready can catch;
	@# retry the migration until the real server accepts it (a failed connect
	@# applies nothing, so retrying is safe).
	@for i in $$(seq 1 30); do \
		MG_DATABASE_URL="postgresql://auth_test:auth_test@127.0.0.1:55432/auth_test" \
			$(VENV)/bin/mg apply && break; \
		[ $$i -eq 30 ] && { docker stop auth-test-pg >/dev/null; exit 1; }; \
		sleep 1; \
	done
	AUTH_DATABASE_TYPE=postgresql \
	AUTH_DATABASE_URL="postgresql://auth_test:auth_test@127.0.0.1:55432/auth_test" \
	AUTH_POSTGRESQL_URL= AUTH_SQLITE_PATH= \
	AUTH_DATABASE_SCHEMA=auth_rbac \
	AUTH_STRICT_USERS_DEFAULT=false \
	AUTH_ENABLE_ENCRYPTION=true \
	AUTH_ENCRYPTION_KEY=test-pg-encryption-key-1234 \
	AUTH_JWT_SECRET_KEY=test-secret \
	$(PYTEST) tests/postgres/ -m postgres; \
	status=$$?; docker stop auth-test-pg >/dev/null; exit $$status

# RLS probes against a disposable container.
#
# The app role must be a NON-superuser that OWNS the tables, because that is
# what production does and because both halves matter: a superuser bypasses RLS
# outright, and an owner bypasses it unless FORCE is set. Run as the container's
# own superuser, every probe below would pass without RLS existing at all.
#
# Sequences are not reassigned: one owned by a table follows that table's owner,
# and PostgreSQL refuses to separate them.
#
# AUDIT_DB_URL is deliberately NOT set: probe_audit_partition_runway asks
# whether a LIVE database's monthly partition cron has kept ahead, which a
# container built seconds ago cannot answer. It reports SKIPPED here, and
# saying so is the point -- run it against the deployment.
#
# AUDIT_ALLOW_SKIPS=1 acknowledges exactly that one gap. The runner otherwise
# exits non-zero on any skip, because a probe that could not run has checked
# nothing and must not be read as a pass. Everything else in the set DOES run
# here, which is what makes the acknowledgement narrow rather than a blanket.
probe-postgres: ## Run the RLS probes against a disposable PostgreSQL (Docker required)
	docker run -d --rm --name auth-probe-pg \
		-e POSTGRES_USER=pgadmin -e POSTGRES_PASSWORD=pgadmin \
		-e POSTGRES_DB=auth_probe -p 127.0.0.1:55433:5432 postgres:16-alpine
	@until docker exec auth-probe-pg pg_isready -U pgadmin -q; do sleep 1; done
	@for i in $$(seq 1 30); do \
		MG_DATABASE_URL="postgresql://pgadmin:pgadmin@127.0.0.1:55433/auth_probe" \
			$(VENV)/bin/mg apply && break; \
		[ $$i -eq 30 ] && { docker stop auth-probe-pg >/dev/null; exit 1; }; \
		sleep 1; \
	done
	@docker exec -e PGPASSWORD=pgadmin auth-probe-pg psql -U pgadmin -d auth_probe -v ON_ERROR_STOP=1 -q \
		-c "CREATE ROLE auth_app LOGIN PASSWORD 'auth_app' NOSUPERUSER NOBYPASSRLS" \
		-c "GRANT CREATE ON DATABASE auth_probe TO auth_app" \
		-c "ALTER SCHEMA auth_rbac OWNER TO auth_app" \
		-c "GRANT USAGE, CREATE ON SCHEMA auth_rbac TO auth_app" \
		-c "DO \$$\$$ DECLARE r record; BEGIN \
			FOR r IN SELECT c.oid::regclass AS t FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
			WHERE n.nspname='auth_rbac' AND c.relkind IN ('r','p') LOOP \
				EXECUTE format('ALTER TABLE %s OWNER TO auth_app', r.t); END LOOP; END \$$\$$;"
	@docker exec -e PGPASSWORD=pgadmin auth-probe-pg psql -U pgadmin -d auth_probe -tAc \
		"SELECT 'app role is superuser or bypasses rls: '||(rolsuper OR rolbypassrls) FROM pg_roles WHERE rolname='auth_app'" \
		| grep -q 'false' || { echo "FATAL: auth_app can bypass RLS; probes would be vacuous"; docker stop auth-probe-pg >/dev/null; exit 1; }
	AUTH_PG_URL="postgresql+psycopg://auth_app:auth_app@127.0.0.1:55433/auth_probe" \
	AUTH_PG_SUPERUSER_URL="postgresql+psycopg://pgadmin:pgadmin@127.0.0.1:55433/auth_probe" \
	AUTH_PG_SCHEMA=auth_rbac AUDIT_ALLOW_DESTRUCTIVE=1 AUDIT_ALLOW_SKIPS=1 \
		sh audit/evaluations/run_all.sh; \
	status=$$?; docker stop auth-probe-pg >/dev/null; exit $$status

version-check: ## Assert pyproject, docs/conf.py and changelog agree on the version
	@V=$$(grep -Po '(?<=^version = ")[^"]+' pyproject.toml); \
	grep -q "release = \"$$V\"" docs/conf.py || { echo "docs/conf.py release != $$V"; exit 1; }; \
	grep -q "Version $$V" docs/changelog.rst || { echo "changelog missing entry for $$V"; exit 1; }; \
	echo "version-check OK: $$V"

smoke: ## Build a wheel, install into a fresh venv, run the quick-start
	bash scripts/smoke_install.sh

build: version-check clean-dist ## Build sdist and wheel
	$(PYTHON) -m pip install --quiet --upgrade build twine
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*

clean-dist:
	rm -rf dist/ build/ *.egg-info

publish-test: build smoke ## Upload to TestPyPI
	$(PYTHON) -m twine upload --repository testpypi dist/*

publish: build smoke ## Upload to PyPI
	$(PYTHON) -m twine upload dist/*

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
	$(PYTHON) -m auth.server

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
	$(PYTHON) -c "from auth.main import app; app.run(host='0.0.0.0', port=11788, threaded=True, debug=False)" & \
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
	$(RUFF) check . --fix

# Run format, lint, and type-check together
check: format lint type-check ## Run format, lint, and type-check
	@echo "All checks passed!"

# Run tests and checks
ci: check test ## Run all checks and tests (for CI)
	@echo "CI checks passed!"
