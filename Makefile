.PHONY: help install format lint type-check test test-cov clean start-server list-keys

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
	pytest

# Run tests with coverage
test-cov: ## Run tests with coverage
	pytest --cov=auth --cov-report=html --cov-report=term

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
	docker run -p 4000:4000 --name auth-server-container auth-server

# Stop Docker container
stop-docker: ## Stop the auth server Docker container
	docker stop auth-server-container || true
	docker rm auth-server-container || true

# List keys - example operation to show available API keys/users/roles
list-keys: ## List available API keys or example data
	@echo "This would list available API keys, users, or roles if implemented"
	@echo "Available operations:"
	@echo "  - Add custom command implementations as needed"

# Fix lint issues
lint-fix: ## Fix lint issues automatically
	ruff check . --fix

# Run format, lint, and type-check together
check: format lint type-check ## Run format, lint, and type-check
	@echo "All checks passed!"

# Run tests and checks
ci: check test ## Run all checks and tests (for CI)
	@echo "CI checks passed!"