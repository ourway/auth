# Auth System Documentation

Complete documentation for the Auth Enterprise Authorization System.

## Documentation Overview

This directory contains comprehensive documentation for using and deploying the Auth system.

### Quick Links

- **[Main README](../README.md)** - Start here for installation, quick start, and overview
- **[API Reference](API.md)** - Complete REST API documentation
- **[Python Examples](PYTHON_EXAMPLES.md)** - Comprehensive Python usage examples

## Getting Started

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Start the Server

```bash
python -m auth.main
```

### 3. Try the API

```bash
bash showcase_api.sh
```

## Documentation Structure

### [API.md](API.md)
Complete REST API reference including:
- Authentication
- All endpoints with examples
- Request/response formats
- Error codes
- cURL, Python, and JavaScript examples

**Best for:** Understanding the HTTP API, integrating with non-Python applications

### [PYTHON_EXAMPLES.md](PYTHON_EXAMPLES.md)
Comprehensive Python library usage including:
- Basic setup and configuration
- Role and permission management
- User management and permission checking
- Advanced queries
- Real-world examples (blog, SaaS, e-commerce)
- Testing strategies

**Best for:** Python developers integrating Auth into their applications

### [Main README](../README.md)
General documentation including:
- Feature overview
- Installation and deployment
- Configuration options
- Quick start guide
- Both API and Python usage
- Troubleshooting

**Best for:** Initial setup, deployment, and general understanding

## Common Tasks

### Creating a Basic RBAC System

**Python:**
```python
import uuid
from auth import Authorization

client_key = str(uuid.uuid4())
auth = Authorization(client_key)

# Create roles
auth.add_role('admin', 'Full access')
auth.add_role('user', 'Regular user')

# Add permissions
auth.add_permission('admin', 'manage_users')
auth.add_permission('admin', 'view_content')
auth.add_permission('user', 'view_content')

# Add users
auth.add_membership('alice@example.com', 'admin')
auth.add_membership('bob@example.com', 'user')

# Check permissions
if auth.user_has_permission('alice@example.com', 'manage_users'):
    print("Alice can manage users")
```

**REST API:**
```bash
CLIENT_KEY=$(uuidgen)

# Create roles
curl -X POST -H "Authorization: Bearer $CLIENT_KEY" \
  http://localhost:5000/api/role/admin

# Add permissions
curl -X POST -H "Authorization: Bearer $CLIENT_KEY" \
  http://localhost:5000/api/permission/admin/manage_users

# Add users
curl -X POST -H "Authorization: Bearer $CLIENT_KEY" \
  http://localhost:5000/api/membership/alice@example.com/admin

# Check permission
curl -H "Authorization: Bearer $CLIENT_KEY" \
  http://localhost:5000/api/has_permission/alice@example.com/manage_users
```

### Checking Permissions

See [PYTHON_EXAMPLES.md#permission-checking](PYTHON_EXAMPLES.md#permission-checking) for detailed examples.

### Finding Users with Specific Permissions

See [API.md#find-users-with-permission](API.md#find-users-with-permission) for API details.

## Architecture

```
┌─────────────────────────────────────────────┐
│          REST API Layer (Flask)             │
│  - Endpoints                                │
│  - Request validation                       │
│  - Authentication                           │
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
│  - Database operations                      │
│  - Encryption/Decryption                    │
│  - SQLAlchemy ORM                           │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│         Database                            │
│  - SQLite (dev)                             │
│  - PostgreSQL (prod)                        │
└─────────────────────────────────────────────┘
```

## Key Concepts

### Roles
Groups that users can belong to. Examples: `admin`, `editor`, `viewer`

### Permissions
Actions that can be performed. Examples: `edit_content`, `delete_users`, `view_reports`

### Memberships
Associations between users and roles. A user can have multiple roles.

### Client Key
UUID4 identifier for API authentication. Each tenant/client has a unique key.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_DB_TYPE` | Database type (sqlite/postgresql) | sqlite |
| `POSTGRESQL_URL` | PostgreSQL connection string | - |
| `SQLITE_PATH` | SQLite database path | ~/.auth.sqlite3 |
| `JWT_SECRET_KEY` | Secret for JWT tokens | auto-generated |
| `ENABLE_ENCRYPTION` | Enable field encryption | false |
| `ENCRYPTION_KEY` | Encryption key | - |
| `SERVER_PORT` | Server port | 5000 |

See [Main README - Configuration](../README.md#configuration) for complete list.

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=auth

# Test the API
bash showcase_api.sh
```

## Deployment

### Development
```bash
python -m auth.main
```

### Production (Waitress)
```bash
pip install waitress
waitress-serve --host=0.0.0.0 --port=5000 --threads=10 auth.main:app
```

### Production (Gunicorn)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 auth.main:app
```

### Docker
```bash
docker-compose up -d
```

## Security Best Practices

1. **Use HTTPS in production** - Never use HTTP for production deployments
2. **Secure client keys** - Treat UUID4 client keys like passwords
3. **Enable encryption** - Use `ENABLE_ENCRYPTION=true` for sensitive data
4. **Use PostgreSQL** - SQLite is for development only
5. **Rotate keys** - Regularly rotate JWT and encryption keys
6. **Monitor audit logs** - Review logs for suspicious activity
7. **Set strong JWT secret** - Use a cryptographically secure `JWT_SECRET_KEY`

## Troubleshooting

### Common Issues

**Q: Permission check returns False when it should be True**

A: Check that:
1. User is added to the role: `auth.has_membership(user, role)`
2. Role has the permission: `auth.has_permission(role, permission)`
3. Client key is correct

**Q: Database connection error**

A: Verify:
1. Database credentials are correct
2. Database server is running
3. Database exists (for PostgreSQL)

**Q: Encryption errors**

A: Ensure:
1. `ENABLE_ENCRYPTION=true` is set
2. `ENCRYPTION_KEY` is provided (32+ characters)
3. Same encryption key is used consistently

See [Main README - Troubleshooting](../README.md#troubleshooting) for more details.

## Additional Resources

- **Tests:** See `tests/` directory for usage examples
- **Showcase Script:** `showcase_api.sh` demonstrates all API features
- **Configuration:** See `auth/config.py` for all settings

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review test files for usage examples

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass (`pytest tests/ -v`)
5. Submit a pull request

## License

MIT License - see [LICENSE](../LICENSE) file

## Copyright

© Farshid Ashouri @RODMENA LIMITED
