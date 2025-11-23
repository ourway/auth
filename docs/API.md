# Auth API Documentation

Complete REST API reference for the Auth authorization system.

## Base URL

```
http://localhost:5000
```

## Authentication

All API endpoints (except `/ping`) require a valid UUID4 client key in the Authorization header:

```
Authorization: Bearer <uuid4-client-key>
```

Example:
```
Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000
```

## Response Format

### Success Response

```json
{
  "success": true,
  "code": 200,
  "message": "Operation completed successfully",
  "data": { ... },
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

### Error Response

```json
{
  "success": false,
  "code": 400,
  "message": "Error description",
  "error": "Detailed error message",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

## Endpoints

### Health Check

#### Ping
Check if the service is running.

**Endpoint:** `GET /ping`

**Authentication:** Not required

**Response:**
```json
{
  "message": "PONG"
}
```

**Example:**
```bash
curl http://localhost:5000/ping
```

---

### Role Management

#### List All Roles
Get a list of all roles for the authenticated client.

**Endpoint:** `GET /api/roles`

**Authentication:** Required

**Response:**
```json
{
  "success": true,
  "code": 200,
  "data": [
    {
      "role": "admin",
      "description": "Administrator role"
    },
    {
      "role": "editor",
      "description": "Content editor"
    }
  ],
  "message": "Retrieved all roles",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/roles
```

#### Create Role
Create a new role.

**Endpoint:** `POST /api/role/{role}`

**Authentication:** Required

**Parameters:**
- `role` (path, required): Role name

**Request Body:** `{}` (empty JSON object)

**Response:**
```json
{
  "result": true
}
```

**Example:**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR-UUID4-KEY" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:5000/api/role/admin
```

#### Delete Role
Delete a role and all its associated permissions and memberships.

**Endpoint:** `DELETE /api/role/{role}`

**Authentication:** Required

**Parameters:**
- `role` (path, required): Role name

**Response:**
```json
{
  "success": true,
  "code": 200,
  "data": {
    "result": true
  },
  "message": "Role 'admin' deletion completed",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

**Example:**
```bash
curl -X DELETE \
  -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/role/admin
```

---

### Permission Management

#### Check Role Permission
Check if a role has a specific permission.

**Endpoint:** `GET /api/permission/{group}/{name}`

**Authentication:** Required

**Parameters:**
- `group` (path, required): Role name
- `name` (path, required): Permission name

**Response:**
```json
{
  "result": true
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/permission/admin/manage_users
```

#### Add Permission to Role
Grant a permission to a role.

**Endpoint:** `POST /api/permission/{group}/{name}`

**Authentication:** Required

**Parameters:**
- `group` (path, required): Role name
- `name` (path, required): Permission name

**Request Body:** `{}` (empty JSON object)

**Response:**
```json
{
  "result": true
}
```

**Example:**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR-UUID4-KEY" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:5000/api/permission/admin/manage_users
```

#### Remove Permission from Role
Revoke a permission from a role.

**Endpoint:** `DELETE /api/permission/{group}/{name}`

**Authentication:** Required

**Parameters:**
- `group` (path, required): Role name
- `name` (path, required): Permission name

**Response:**
```json
{
  "result": true
}
```

**Example:**
```bash
curl -X DELETE \
  -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/permission/admin/manage_users
```

#### Get Role Permissions
Get all permissions for a specific role.

**Endpoint:** `GET /api/role_permissions/{role}`

**Authentication:** Required

**Parameters:**
- `role` (path, required): Role name

**Response:**
```json
{
  "success": true,
  "code": 200,
  "data": [
    {"name": "manage_users"},
    {"name": "edit_content"},
    {"name": "view_content"}
  ],
  "message": "Retrieved permissions for role 'admin'",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/role_permissions/admin
```

---

### Membership Management

#### Check Membership
Check if a user belongs to a role.

**Endpoint:** `GET /api/membership/{user}/{group}`

**Authentication:** Required

**Parameters:**
- `user` (path, required): User identifier
- `group` (path, required): Role name

**Response:**
```json
{
  "success": true,
  "code": 200,
  "data": {
    "has_permission": true
  },
  "message": "Membership check for user 'alice' and group 'admin' completed",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/membership/alice@example.com/admin
```

#### Add User to Role
Add a user to a role.

**Endpoint:** `POST /api/membership/{user}/{group}`

**Authentication:** Required

**Parameters:**
- `user` (path, required): User identifier
- `group` (path, required): Role name

**Request Body:** `{}` (empty JSON object)

**Response:**
```json
{
  "result": true
}
```

**Example:**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR-UUID4-KEY" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:5000/api/membership/alice@example.com/admin
```

#### Remove User from Role
Remove a user from a role.

**Endpoint:** `DELETE /api/membership/{user}/{group}`

**Authentication:** Required

**Parameters:**
- `user` (path, required): User identifier
- `group` (path, required): Role name

**Response:**
```json
{
  "result": true
}
```

**Example:**
```bash
curl -X DELETE \
  -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/membership/alice@example.com/admin
```

#### Get Role Members
Get all users who belong to a specific role.

**Endpoint:** `GET /api/members/{role}`

**Authentication:** Required

**Parameters:**
- `role` (path, required): Role name

**Response:**
```json
{
  "result": [
    {"user": "alice@example.com", "role": "admin"},
    {"user": "bob@example.com", "role": "admin"}
  ]
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/members/admin
```

---

### User Permission Queries

#### Check User Permission
Check if a user has a specific permission.

**Endpoint:** `GET /api/has_permission/{user}/{name}`

**Authentication:** Required

**Parameters:**
- `user` (path, required): User identifier
- `name` (path, required): Permission name

**Response:**
```json
{
  "success": true,
  "code": 200,
  "data": {
    "has_permission": true
  },
  "message": "Permission check for user 'alice' and permission 'manage_users' completed",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/has_permission/alice@example.com/manage_users
```

#### Get User Permissions
Get all permissions for a specific user.

**Endpoint:** `GET /api/user_permissions/{user}`

**Authentication:** Required

**Parameters:**
- `user` (path, required): User identifier

**Response:**
```json
{
  "success": true,
  "code": 200,
  "data": {
    "permissions": [
      {"name": "manage_users"},
      {"name": "edit_content"},
      {"name": "view_content"}
    ],
    "count": 3
  },
  "message": "Retrieved permissions for user 'alice'",
  "timestamp": "2025-11-21T12:34:56.789012"
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/user_permissions/alice@example.com
```

#### Get User Roles
Get all roles for a specific user.

**Endpoint:** `GET /api/user_roles/{user}`

**Authentication:** Required

**Parameters:**
- `user` (path, required): User identifier

**Response:**
```json
{
  "result": [
    {"user": "alice@example.com", "role": "admin"},
    {"user": "alice@example.com", "role": "editor"}
  ]
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/user_roles/alice@example.com
```

---

### Permission Discovery

#### Find Roles with Permission
Get all roles that have a specific permission.

**Endpoint:** `GET /api/which_roles_can/{name}`

**Authentication:** Required

**Parameters:**
- `name` (path, required): Permission name

**Response:**
```json
{
  "result": [
    {"role": "admin"},
    {"role": "editor"}
  ]
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/which_roles_can/edit_content
```

#### Find Users with Permission
Get all users who have a specific permission.

**Endpoint:** `GET /api/which_users_can/{name}`

**Authentication:** Required

**Parameters:**
- `name` (path, required): Permission name

**Response:**
```json
{
  "result": [
    {"user": "alice@example.com", "role": "admin"},
    {"user": "bob@example.com", "role": "editor"}
  ]
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR-UUID4-KEY" \
  http://localhost:5000/api/which_users_can/edit_content
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid input parameters |
| 401 | Unauthorized - Missing or invalid authentication |
| 404 | Not Found - Resource does not exist |
| 500 | Internal Server Error |

## Rate Limiting

Currently, there is no rate limiting implemented. For production use, consider implementing rate limiting at the reverse proxy level (e.g., nginx, HAProxy).

## Audit Logging

All operations are logged in the audit table with the following information:
- Client ID
- User (if applicable)
- Action performed
- Resource affected
- Success/Failure status
- Timestamp
- IP address

## Security Considerations

1. **Always use HTTPS in production**
2. **Keep client keys secure** - They should be treated like passwords
3. **Validate all input** - The API performs input validation, but additional validation at the client is recommended
4. **Monitor audit logs** - Regularly review audit logs for suspicious activity
5. **Use environment variables** - Never hardcode credentials or keys in your code

## Client Libraries

### Python

```python
from auth.client import EnhancedAuthClient

client = EnhancedAuthClient(
    api_key='your-uuid4-key',
    service_url='http://localhost:5000'
)
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

const client = axios.create({
  baseURL: 'http://localhost:5000',
  headers: {
    'Authorization': 'Bearer your-uuid4-key',
    'Content-Type': 'application/json'
  }
});

// Example: Create role
await client.post('/api/role/admin', {});
```

### cURL

See the examples throughout this documentation for cURL usage.

## Postman Collection

A Postman collection is available in the `docs/` directory for easy API testing.

## OpenAPI/Swagger

An OpenAPI specification is planned for a future release.
