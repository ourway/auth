# Auth | Enterprise Authorization System

A comprehensive, production-ready authorization system with role-based access control (RBAC), audit logging, encryption, and high availability features.

[![Tests](https://img.shields.io/badge/tests-152%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## Features

### Core Features
- **Role-Based Access Control (RBAC)** - Hierarchical user, role, and permission management
- **Multiple Storage Backends** - SQLite (development) and PostgreSQL (production)
- **Dual Interface** - REST API and Python library
- **JWT Authentication** - Secure token-based authentication
- **Data Encryption** - Optional encryption for sensitive data fields
- **Audit Logging** - Comprehensive audit trail for compliance
- **Workflow Permissions** - APScheduler integration for workflow permission checking

### Security Features
- UUID4-based client authentication
- JWT token-based authorization
- **Deterministic field-level encryption** (AES-256-CTR) - Queryable encrypted data
- Comprehensive audit logging with timestamps
- Input validation and sanitization
- CORS configuration

### Production Features
- Connection pooling with retry logic
- Circuit breaker pattern for fault tolerance
- Configurable CORS settings
- Health check endpoint
- Consistent API response formats
- Extensive test coverage (152 tests)

## Requirements

- Python 3.9+
- PostgreSQL (for production) or SQLite (for development/testing)

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Start the Server

**Development (SQLite):**
```bash
python -m auth.main
```

**Production (PostgreSQL):**
```bash
export AUTH_DATABASE_TYPE=postgresql
export AUTH_POSTGRESQL_URL=postgresql://username:password@localhost:5432/auth_db
export AUTH_JWT_SECRET_KEY=your_secure_secret_key
export AUTH_ENABLE_ENCRYPTION=true
export AUTH_ENCRYPTION_KEY=your_encryption_key

python -m auth.main
```

The server will start on `http://127.0.0.1:5000`

### 2. Test the API

Run the showcase script to test all API endpoints:
```bash
bash showcase_api.sh
```

## Usage

### Python Library Usage

#### Basic Setup

```python
import uuid
from auth import Authorization

# Generate a client key (UUID4)
client_key = str(uuid.uuid4())

# Create authorization instance
auth = Authorization(client_key)

# Create roles
auth.add_role('admin', description='Administrator role')
auth.add_role('editor', description='Content editor role')
auth.add_role('viewer', description='Read-only role')

# Add permissions to roles
auth.add_permission('admin', 'manage_users')
auth.add_permission('admin', 'edit_content')
auth.add_permission('admin', 'view_content')
auth.add_permission('editor', 'edit_content')
auth.add_permission('editor', 'view_content')
auth.add_permission('viewer', 'view_content')

# Add users to roles
auth.add_membership('alice@example.com', 'admin')
auth.add_membership('bob@example.com', 'editor')
auth.add_membership('charlie@example.com', 'viewer')
```

#### Check Permissions

```python
# Check if user has specific permission
if auth.user_has_permission('alice@example.com', 'manage_users'):
    print("Alice can manage users")

# Check if user belongs to a role
if auth.has_membership('bob@example.com', 'editor'):
    print("Bob is an editor")

# Check if role has permission
if auth.has_permission('viewer', 'view_content'):
    print("Viewers can view content")
```

#### Query User Information

```python
# Get all permissions for a user
permissions = auth.get_user_permissions('alice@example.com')
print(f"Alice's permissions: {[p['name'] for p in permissions]}")

# Get all roles for a user
roles = auth.get_user_roles('bob@example.com')
print(f"Bob's roles: {[r['role'] for r in roles]}")

# Get all users with a specific permission
users = auth.which_users_can('edit_content')
print(f"Users who can edit: {[u['user'] for u in users]}")

# Get all roles with a specific permission
roles = auth.which_roles_can('manage_users')
print(f"Roles that can manage users: {[r['role'] for r in roles]}")
```

#### Query Role Information

```python
# Get all members of a role
members = auth.get_role_members('admin')
print(f"Admin users: {[m['user'] for m in members]}")

# Get all permissions for a role
permissions = auth.get_permissions('editor')
print(f"Editor permissions: {[p['name'] for p in permissions]}")

# Get all roles
all_roles = auth.roles
print(f"All roles: {[r['role'] for r in all_roles]}")
```

#### Modify Permissions and Memberships

```python
# Remove permission from role
auth.del_permission('editor', 'edit_content')

# Remove user from role
auth.del_membership('charlie@example.com', 'viewer')

# Delete role (also removes all memberships and permissions)
auth.del_role('viewer')
```

### REST API Usage

All API endpoints require a valid UUID4 Bearer token in the Authorization header.

#### Python Client

```python
import uuid
from auth.client import EnhancedAuthClient

# Generate a client key
client_key = str(uuid.uuid4())

# Create client instance
client = EnhancedAuthClient(
    api_key=client_key,
    service_url='http://127.0.0.1:5000'
)

# Create a role
response = client.create_role('admin')
print(response)

# Add permission to role
response = client.add_permission('admin', 'manage_users')
print(response)

# Add user to role
response = client.add_membership('alice@example.com', 'admin')
print(response)

# Check user permission
response = client.user_has_permission('alice@example.com', 'manage_users')
print(response)
```

#### cURL Examples

**Health Check:**
```bash
curl http://localhost:5000/ping
```

**Create a Role:**
```bash
CLIENT_KEY=$(uuidgen)
curl -X POST \
  http://localhost:5000/api/role/admin \
  -H "Authorization: Bearer $CLIENT_KEY" \
  -H "Content-Type: application/json"
```

**Add Permission to Role:**
```bash
curl -X POST \
  http://localhost:5000/api/permission/admin/manage_users \
  -H "Authorization: Bearer $CLIENT_KEY" \
  -H "Content-Type: application/json"
```

**Add User to Role:**
```bash
curl -X POST \
  http://localhost:5000/api/membership/alice@example.com/admin \
  -H "Authorization: Bearer $CLIENT_KEY" \
  -H "Content-Type: application/json"
```

**Check User Permission:**
```bash
curl -X GET \
  http://localhost:5000/api/has_permission/alice@example.com/manage_users \
  -H "Authorization: Bearer $CLIENT_KEY"
```

**Get User Permissions:**
```bash
curl -X GET \
  http://localhost:5000/api/user_permissions/alice@example.com \
  -H "Authorization: Bearer $CLIENT_KEY"
```

**Get User Roles:**
```bash
curl -X GET \
  http://localhost:5000/api/user_roles/alice@example.com \
  -H "Authorization: Bearer $CLIENT_KEY"
```

**Get Role Members:**
```bash
curl -X GET \
  http://localhost:5000/api/members/admin \
  -H "Authorization: Bearer $CLIENT_KEY"
```

**Find Users with Permission:**
```bash
curl -X GET \
  http://localhost:5000/api/which_users_can/manage_users \
  -H "Authorization: Bearer $CLIENT_KEY"
```

**Find Roles with Permission:**
```bash
curl -X GET \
  http://localhost:5000/api/which_roles_can/manage_users \
  -H "Authorization: Bearer $CLIENT_KEY"
```

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ping` | Health check endpoint |
| GET | `/api/roles` | List all roles |
| POST | `/api/role/{role}` | Create a new role |
| DELETE | `/api/role/{role}` | Delete a role |
| GET | `/api/permission/{group}/{name}` | Check if role has permission |
| POST | `/api/permission/{group}/{name}` | Add permission to role |
| DELETE | `/api/permission/{group}/{name}` | Remove permission from role |
| GET | `/api/membership/{user}/{group}` | Check if user is in role |
| POST | `/api/membership/{user}/{group}` | Add user to role |
| DELETE | `/api/membership/{user}/{group}` | Remove user from role |
| GET | `/api/has_permission/{user}/{name}` | Check if user has permission |
| GET | `/api/user_permissions/{user}` | Get all permissions for user |
| GET | `/api/user_roles/{user}` | Get all roles for user |
| GET | `/api/role_permissions/{role}` | Get all permissions for role |
| GET | `/api/members/{role}` | Get all members of role |
| GET | `/api/which_roles_can/{name}` | Get roles with specific permission |
| GET | `/api/which_users_can/{name}` | Get users with specific permission |

### Response Format

All API responses follow this format:

```json
{
  "success": true,
  "code": 200,
  "message": "Operation completed successfully",
  "data": { ... },
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

### Error Responses

```json
{
  "success": false,
  "code": 400,
  "message": "Invalid input",
  "error": "Detailed error message",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_DATABASE_TYPE` | Database type (sqlite or postgresql) | sqlite |
| `AUTH_DATABASE_URL` | Full database connection URL (overrides other settings) | - |
| `AUTH_POSTGRESQL_URL` | PostgreSQL connection string | - |
| `AUTH_SQLITE_PATH` | SQLite database path | ~/.auth.sqlite3 |
| `AUTH_JWT_SECRET_KEY` | Secret key for JWT tokens | (auto-generated) |
| `AUTH_JWT_ALGORITHM` | JWT algorithm | HS256 |
| `AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | 1440 |
| `AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiration time | 7 |
| `AUTH_ENABLE_ENCRYPTION` | Enable data encryption | false |
| `AUTH_ENCRYPTION_KEY` | Encryption key for sensitive data | - |
| `AUTH_SERVER_HOST` | Server host | 127.0.0.1 |
| `AUTH_SERVER_PORT` | Server port | 8000 |
| `AUTH_DEBUG_MODE` | Debug mode | false |
| `AUTH_ALLOW_CORS` | Enable CORS | true |
| `AUTH_CORS_ORIGINS` | Allowed CORS origins | * |
| `AUTH_ENABLE_AUDIT_LOGGING` | Enable audit logging | true |

### Configuration File

You can also use a `.env` file:

```env
AUTH_DATABASE_TYPE=postgresql
AUTH_POSTGRESQL_URL=postgresql://user:pass@localhost:5432/authdb
AUTH_JWT_SECRET_KEY=your-secret-key-here
AUTH_ENABLE_ENCRYPTION=true
AUTH_ENCRYPTION_KEY=your-encryption-key-here
AUTH_SERVER_PORT=8000
```

## Production Deployment

### Using Waitress (Recommended)

```bash
pip install waitress
waitress-serve --host=0.0.0.0 --port=5000 --threads=10 auth.main:app
```

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 auth.main:app
```

### Docker

```bash
docker-compose up -d
```

## Testing

Run the full test suite:

```bash
python -m pytest tests/ -v
```

Run specific test categories:

```bash
# Flask API tests
python -m pytest tests/test_flask.py -v

# Authorization tests
python -m pytest tests/test_authorization.py -v

# Database tests
python -m pytest tests/test_db_*.py -v
```

## Architecture

```
┌─────────────────────────────────────────────┐
│          API Layer (Flask)                  │
│  - REST endpoints                           │
│  - Request validation                       │
│  - Response formatting                      │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│       Service Layer (Business Logic)        │
│  - Authorization rules                      │
│  - Permission checking                      │
│  - Audit logging                            │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│      Data Access Layer (DAL)                │
│  - SQLAlchemy ORM                           │
│  - Database abstraction                     │
│  - Encryption/Decryption                    │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│         Database (SQLite/PostgreSQL)        │
│  - User data                                │
│  - Role & Permission mappings               │
│  - Audit logs                               │
└─────────────────────────────────────────────┘
```

## Data Encryption

The Auth system supports **deterministic field-level encryption** for sensitive data using AES-256-CTR with HMAC-derived initialization vectors.

### How It Works

**Deterministic Encryption:**
- Same plaintext always produces the same ciphertext
- Enables database queries on encrypted fields (user lookups, permission checks)
- Uses AES-256-CTR with PBKDF2-derived keys (100,000 iterations)
- HMAC-based IV generation ensures determinism

**What's Encrypted:**
- User names in `auth_membership` table
- Permission names in `auth_permission` table
- Optional: Role descriptions

**Example:**
```python
# Without encryption
Database stores: "john", "jane", "admin"

# With deterministic encryption enabled
Database stores: "xxqjTSaj0YGZD7v8khExdKkV+dA=", "sJ4Yaz56uRxmNF0mj3wOwUNE8Y8=", ...
```

### Enabling Encryption

1. Generate a secure encryption key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

2. Update `.env` file:
```bash
AUTH_ENABLE_ENCRYPTION=true
AUTH_ENCRYPTION_KEY=your_generated_key_here
```

3. Restart the service - encryption is applied automatically to all new data

### Security Considerations

**Deterministic vs Non-Deterministic:**
- **Deterministic** (current): Same value = same ciphertext (required for queries)
- **Trade-off**: Pattern analysis possible (acceptable for usernames/permissions)
- **Benefit**: Full database functionality with encrypted data

**Best Practices:**
- Use strong encryption keys (32+ characters)
- Rotate keys periodically
- Store keys securely (environment variables, secrets management)
- Never commit encryption keys to version control

## Security Best Practices

1. **Use PostgreSQL in Production** - SQLite is for development only
2. **Enable Encryption** - Set `AUTH_ENABLE_ENCRYPTION=true` for sensitive data
3. **Secure JWT Secret** - Use a strong, unique `AUTH_JWT_SECRET_KEY`
4. **Use HTTPS** - Always use TLS/SSL in production
5. **Rotate Keys** - Regularly rotate encryption and JWT keys
6. **Audit Logs** - Monitor audit logs for suspicious activity
7. **Client Keys** - Keep UUID4 client keys secure and confidential

## Examples

See the `showcase_api.sh` script for a complete example demonstrating all API features.

## Troubleshooting

### Database Connection Issues

If you encounter database connection errors:

```bash
# For PostgreSQL
export AUTH_POSTGRESQL_URL=postgresql://user:pass@localhost:5432/dbname

# Check PostgreSQL is running
psql -U user -d dbname -c "SELECT 1"
```

### Permission Denied Errors

Ensure your client key is a valid UUID4:

```python
import uuid
client_key = str(uuid.uuid4())  # Correct format
```

### Encryption Errors

If encryption is enabled, ensure the encryption key is set:

```bash
export AUTH_ENABLE_ENCRYPTION=true
export AUTH_ENCRYPTION_KEY=your-32-character-key-here
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=auth --cov-report=html

# Run specific test file
python -m pytest tests/test_flask.py -v
```

## License

MIT License - see LICENSE file for details

## Copyright

© Farshid Ashouri @RODMENA LIMITED

## Support

For issues and questions, please open an issue on GitHub.
